//! Ein segmentiertes Write-Ahead-Log: die Speicherform *einer* Prioritätsstufe.
//!
//! Aufbau: das Verzeichnis enthält fortlaufend nummerierte Segmentdateien
//! (`0000000000000001.log`) und eine Cursor-Datei mit der Leseposition. Neue
//! Records werden ans aktive Segment angehängt; ist es voll, beginnt ein neues.
//! Vollständig gelesene Segmente werden gelöscht — das ist der einzige Weg, auf
//! dem Platz frei wird, und macht das Aufräumen zu einer O(1)-Operation statt
//! einer Kompaktierung.
//!
//! Record-Format (Little Endian):
//!
//! ```text
//! ┌────────────┬────────────┬───────────────┐
//! │ len: u32   │ crc32: u32 │ payload: len B│
//! └────────────┴────────────┴───────────────┘
//! ```
//!
//! Ein abgeschnittener oder verfälschter Record beendet das Segment: beim Öffnen
//! wird auf den letzten gültigen Record gekürzt. Ein halb geschriebener Eintrag
//! nach einem Stromausfall kostet damit genau diesen einen Eintrag und nicht das
//! Segment — die Alternative (Segment verwerfen) würde Stunden an Telemetrie für
//! einen Teilschreibvorgang opfern.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{BufferError, Result};

/// Kopfgröße eines Records (len + crc).
const HEADER_LEN: u64 = 8;

/// Obergrenze für einen einzelnen Record. Ein größerer Wert im Header bedeutet
/// mit Sicherheit Datensalat und beendet das Segment.
pub const MAX_RECORD_BYTES: u32 = 1024 * 1024;

/// Kleinste sinnvolle Segmentgröße. Retention arbeitet segmentweise — sind die
/// Segmente zu klein, kostet jede Rotation mehr, als sie an Granularität bringt.
pub const MIN_SEGMENT_BYTES: u64 = 4 * 1024;

const CURSOR_FILE: &str = "cursor";
const SEGMENT_EXT: &str = "log";

/// Leseposition innerhalb des Logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct LogPosition {
    pub segment: u64,
    pub offset: u64,
}

/// Ein gelesener, noch nicht bestätigter Record.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub payload: Vec<u8>,
    /// Position *hinter* diesem Record — genau der Wert, der bei Bestätigung
    /// zum neuen Cursor wird.
    pub next: LogPosition,
}

pub struct SegmentedLog {
    dir: PathBuf,
    segment_bytes: u64,
    /// Bekannte Segmente, aufsteigend.
    segments: BTreeSet<u64>,
    /// Aktives (jüngstes) Segment, an das angehängt wird.
    active_id: u64,
    writer: BufWriter<File>,
    active_bytes: u64,
    /// Bestätigte Leseposition.
    cursor: LogPosition,
    /// Noch nicht bestätigte Records.
    pending: u64,
    /// Bytes aller Segmentdateien.
    disk_bytes: u64,
    /// Wie viele Records durch Retention verworfen wurden (kumulativ).
    dropped: u64,
}

impl SegmentedLog {
    /// Öffnet (oder erstellt) ein Log. Führt dabei die Crash-Recovery aus.
    pub fn open(dir: &Path, segment_bytes: u64) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|source| BufferError::Io {
            path: dir.to_path_buf(),
            source,
        })?;

        let mut segments = discover_segments(dir)?;
        let cursor = read_cursor(dir)?;

        if segments.is_empty() {
            segments.insert(1);
        }

        // Recovery: jedes Segment auf den letzten gültigen Record kürzen. Nur
        // das jüngste kann realistisch beschädigt sein, aber ein Torn Write beim
        // Segmentwechsel trifft potenziell auch ältere — also alle prüfen.
        let mut disk_bytes = 0u64;
        for id in &segments {
            let path = segment_path(dir, *id);
            if !path.exists() {
                continue;
            }
            let valid_end = truncate_to_last_valid_record(&path)?;
            disk_bytes += valid_end;
        }

        let active_id = *segments.iter().next_back().unwrap_or(&1);
        let active_path = segment_path(dir, active_id);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&active_path)
            .map_err(|source| BufferError::Io {
                path: active_path.clone(),
                source,
            })?;
        let active_bytes = file
            .metadata()
            .map_err(|source| BufferError::Io {
                path: active_path.clone(),
                source,
            })?
            .len();

        let mut log = Self {
            dir: dir.to_path_buf(),
            segment_bytes: segment_bytes.max(MIN_SEGMENT_BYTES),
            segments,
            active_id,
            writer: BufWriter::new(file),
            active_bytes,
            cursor,
            pending: 0,
            disk_bytes,
            dropped: 0,
        };

        // Ein Cursor, der auf ein längst gelöschtes Segment zeigt, würde das Log
        // dauerhaft blockieren. Auf das älteste vorhandene Segment nachziehen.
        log.clamp_cursor();
        log.pending = log.count_pending()?;
        Ok(log)
    }

    /// Hängt einen Record an und gibt seine Bruttogröße auf der Platte zurück.
    pub fn append(&mut self, payload: &[u8]) -> Result<u64> {
        let len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| BufferError::RecordTooLarge(payload.len()))?;
        if len > MAX_RECORD_BYTES {
            return Err(BufferError::RecordTooLarge(payload.len()));
        }

        if self.active_bytes >= self.segment_bytes {
            self.roll_segment()?;
        }

        let crc = crc32fast::hash(payload);
        let path = self.active_path();
        let mut header = [0u8; HEADER_LEN as usize];
        header[0..4].copy_from_slice(&len.to_le_bytes());
        header[4..8].copy_from_slice(&crc.to_le_bytes());

        self.writer
            .write_all(&header)
            .and_then(|()| self.writer.write_all(payload))
            .map_err(|source| BufferError::Io {
                path: path.clone(),
                source,
            })?;

        let written = HEADER_LEN + payload.len() as u64;
        self.active_bytes += written;
        self.disk_bytes += written;
        self.pending += 1;
        Ok(written)
    }

    /// Schreibt gepufferte Daten in die Datei und fsynct sie. Wird vor jedem
    /// Upload aufgerufen, damit ein Absturz zwischen Append und Upload nichts
    /// verschluckt.
    ///
    /// `BufWriter::flush()` allein reicht nicht: das übergibt die Daten nur an
    /// den Seiten-Cache des Kernels, nicht an die Platte. Ein Stromausfall
    /// direkt danach würde sie trotzdem verlieren — deshalb zusätzlich
    /// `sync_all()` auf der zugrunde liegenden Datei.
    pub fn flush(&mut self) -> Result<()> {
        let path = self.active_path();
        self.writer.flush().map_err(|source| BufferError::Io {
            path: path.clone(),
            source,
        })?;
        self.writer
            .get_ref()
            .sync_all()
            .map_err(|source| BufferError::Io { path, source })
    }

    /// Liest bis zu `max` Records ab der bestätigten Position, ohne sie zu
    /// bestätigen. Erst [`Self::commit`] gibt den Platz frei — geht der Upload
    /// schief, liefert der nächste Aufruf dieselben Records erneut.
    pub fn read_batch(&mut self, max: usize) -> Result<Vec<LogRecord>> {
        if max == 0 || self.pending == 0 {
            return Ok(Vec::new());
        }
        self.flush()?;

        let mut out = Vec::new();
        let mut pos = self.cursor;

        while out.len() < max {
            let Some(&segment) = self.segments.range(pos.segment..).next() else {
                break;
            };
            if segment != pos.segment {
                // Das Segment des Cursors existiert nicht mehr (Retention).
                pos = LogPosition { segment, offset: 0 };
            }
            let path = segment_path(&self.dir, segment);
            let Ok(mut file) = File::open(&path) else {
                // Verschwundenes Segment: zum nächsten weitergehen statt
                // steckenzubleiben.
                match self.segments.range(segment + 1..).next() {
                    Some(&next) => {
                        pos = LogPosition {
                            segment: next,
                            offset: 0,
                        };
                        continue;
                    }
                    None => break,
                }
            };
            file.seek(SeekFrom::Start(pos.offset))
                .map_err(|source| BufferError::Io {
                    path: path.clone(),
                    source,
                })?;

            let mut reached_segment_end = false;
            while out.len() < max {
                match read_record(&mut file)? {
                    Some((payload, consumed)) => {
                        pos.offset += consumed;
                        out.push(LogRecord { payload, next: pos });
                    }
                    None => {
                        reached_segment_end = true;
                        break;
                    }
                }
            }

            if reached_segment_end {
                match self.segments.range(segment + 1..).next() {
                    Some(&next) => {
                        pos = LogPosition {
                            segment: next,
                            offset: 0,
                        }
                    }
                    None => break,
                }
            }
        }

        Ok(out)
    }

    /// Bestätigt alles bis `pos` und räumt vollständig gelesene Segmente ab.
    pub fn commit(&mut self, pos: LogPosition) -> Result<()> {
        if pos <= self.cursor {
            return Ok(());
        }
        let consumed = self.count_records_between(self.cursor, pos)?;
        self.cursor = pos;
        self.pending = self.pending.saturating_sub(consumed);
        write_cursor(&self.dir, self.cursor)?;
        self.collect_consumed_segments()?;
        Ok(())
    }

    /// Verwirft das älteste Segment. Der grobe Schnitt ist Absicht: pro Segment
    /// eine Löschoperation, kein Umkopieren — Retention darf unter Druck nicht
    /// selbst zum teuren Vorgang werden.
    ///
    /// Gibt die Zahl der verworfenen Records zurück; `None`, wenn nur noch das
    /// aktive Segment übrig ist (das nie gelöscht wird).
    pub fn drop_oldest_segment(&mut self) -> Result<Option<u64>> {
        let Some(&oldest) = self.segments.iter().next() else {
            return Ok(None);
        };
        if oldest == self.active_id {
            return Ok(None);
        }

        let path = segment_path(&self.dir, oldest);
        let (records, bytes) = scan_segment(&path).unwrap_or((0, 0));

        // Nur was noch nicht bestätigt war, zählt als Verlust.
        let unread = if self.cursor.segment > oldest {
            0
        } else {
            let from = if self.cursor.segment == oldest {
                self.cursor.offset
            } else {
                0
            };
            count_records_from(&path, from).unwrap_or(records)
        };

        remove_segment(&path)?;
        self.segments.remove(&oldest);
        self.disk_bytes = self.disk_bytes.saturating_sub(bytes);
        self.pending = self.pending.saturating_sub(unread);
        self.dropped += unread;
        self.clamp_cursor();
        write_cursor(&self.dir, self.cursor)?;

        Ok(Some(unread))
    }

    pub fn pending(&self) -> u64 {
        self.pending
    }

    /// Tatsächlich verwendete Segmentgröße — kann über dem angeforderten Wert
    /// liegen (siehe [`MIN_SEGMENT_BYTES`]). Die Queue braucht den echten Wert,
    /// um ihre Platten-Untergrenze daraus abzuleiten.
    pub fn segment_bytes(&self) -> u64 {
        self.segment_bytes
    }

    pub fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn is_empty(&self) -> bool {
        self.pending == 0
    }

    // -- intern ------------------------------------------------------------

    fn active_path(&self) -> PathBuf {
        segment_path(&self.dir, self.active_id)
    }

    fn roll_segment(&mut self) -> Result<()> {
        self.flush()?;
        let next_id = self.active_id + 1;
        let path = segment_path(&self.dir, next_id);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|source| BufferError::Io {
                path: path.clone(),
                source,
            })?;
        self.segments.insert(next_id);
        self.active_id = next_id;
        self.writer = BufWriter::new(file);
        self.active_bytes = 0;
        Ok(())
    }

    /// Löscht alle Segmente vor dem Cursor-Segment.
    fn collect_consumed_segments(&mut self) -> Result<()> {
        let obsolete: Vec<u64> = self
            .segments
            .range(..self.cursor.segment)
            .copied()
            .collect();
        for id in obsolete {
            if id == self.active_id {
                continue;
            }
            let path = segment_path(&self.dir, id);
            let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            remove_segment(&path)?;
            self.segments.remove(&id);
            self.disk_bytes = self.disk_bytes.saturating_sub(bytes);
        }
        Ok(())
    }

    /// Zieht den Cursor auf das älteste vorhandene Segment nach, falls er auf
    /// ein gelöschtes zeigt.
    fn clamp_cursor(&mut self) {
        let Some(&oldest) = self.segments.iter().next() else {
            return;
        };
        if self.cursor.segment < oldest {
            self.cursor = LogPosition {
                segment: oldest,
                offset: 0,
            };
        }
    }

    fn count_pending(&self) -> Result<u64> {
        let mut total = 0u64;
        for &id in self.segments.range(self.cursor.segment..) {
            let path = segment_path(&self.dir, id);
            let from = if id == self.cursor.segment {
                self.cursor.offset
            } else {
                0
            };
            total += count_records_from(&path, from).unwrap_or(0);
        }
        Ok(total)
    }

    fn count_records_between(&self, from: LogPosition, to: LogPosition) -> Result<u64> {
        let mut total = 0u64;
        for &id in self.segments.range(from.segment..=to.segment) {
            let path = segment_path(&self.dir, id);
            let start = if id == from.segment { from.offset } else { 0 };
            let end = if id == to.segment {
                Some(to.offset)
            } else {
                None
            };
            total += count_records_in_range(&path, start, end).unwrap_or(0);
        }
        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Dateiebene
// ---------------------------------------------------------------------------

fn segment_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:016x}.{SEGMENT_EXT}"))
}

fn discover_segments(dir: &Path) -> Result<BTreeSet<u64>> {
    let mut out = BTreeSet::new();
    let entries = std::fs::read_dir(dir).map_err(|source| BufferError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(SEGMENT_EXT) {
            continue;
        }
        if let Some(id) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| u64::from_str_radix(s, 16).ok())
        {
            out.insert(id);
        }
    }
    Ok(out)
}

fn remove_segment(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(BufferError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Liest einen Record ab der aktuellen Dateiposition.
///
/// `Ok(None)` heißt "Segmentende" — dazu zählt auch ein beschädigter Rest, denn
/// beim Öffnen wurde bereits auf den letzten gültigen Record gekürzt.
fn read_record(file: &mut File) -> Result<Option<(Vec<u8>, u64)>> {
    let mut header = [0u8; HEADER_LEN as usize];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(source) => {
            return Err(BufferError::Io {
                path: PathBuf::from("<segment>"),
                source,
            })
        }
    }

    let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let crc = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if len == 0 || len > MAX_RECORD_BYTES {
        return Ok(None);
    }

    let mut payload = vec![0u8; len as usize];
    match file.read_exact(&mut payload) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(source) => {
            return Err(BufferError::Io {
                path: PathBuf::from("<segment>"),
                source,
            })
        }
    }
    if crc32fast::hash(&payload) != crc {
        return Ok(None);
    }
    Ok(Some((payload, HEADER_LEN + len as u64)))
}

/// Kürzt ein Segment auf den letzten gültigen Record und gibt dessen Endoffset
/// zurück.
fn truncate_to_last_valid_record(path: &Path) -> Result<u64> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|source| BufferError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| BufferError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();

    let mut valid_end = 0u64;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| BufferError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    while let Some((_, consumed)) = read_record(&mut file)? {
        valid_end += consumed;
    }

    if valid_end < len {
        tracing::warn!(
            path = %path.display(),
            valid_end,
            file_len = len,
            "truncating wal segment after incomplete record"
        );
        file.set_len(valid_end).map_err(|source| BufferError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(valid_end)
}

/// (Anzahl Records, Bytes) eines Segments.
fn scan_segment(path: &Path) -> Result<(u64, u64)> {
    let mut file = File::open(path).map_err(|source| BufferError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut count = 0u64;
    let mut bytes = 0u64;
    while let Some((_, consumed)) = read_record(&mut file)? {
        count += 1;
        bytes += consumed;
    }
    Ok((count, bytes))
}

fn count_records_from(path: &Path, from: u64) -> Result<u64> {
    count_records_in_range(path, from, None)
}

fn count_records_in_range(path: &Path, from: u64, to: Option<u64>) -> Result<u64> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(source) => {
            return Err(BufferError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    file.seek(SeekFrom::Start(from))
        .map_err(|source| BufferError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut count = 0u64;
    let mut offset = from;
    while let Some((_, consumed)) = read_record(&mut file)? {
        offset += consumed;
        count += 1;
        if let Some(limit) = to {
            if offset >= limit {
                break;
            }
        }
    }
    Ok(count)
}

fn cursor_path(dir: &Path) -> PathBuf {
    dir.join(CURSOR_FILE)
}

fn read_cursor(dir: &Path) -> Result<LogPosition> {
    let path = cursor_path(dir);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(LogPosition::default());
    };
    if bytes.len() != 16 {
        tracing::warn!(path = %path.display(), "ignoring malformed cursor file");
        return Ok(LogPosition::default());
    }
    let segment = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or_default());
    let offset = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or_default());
    Ok(LogPosition { segment, offset })
}

/// Schreibt den Cursor atomar. Ein halb geschriebener Cursor würde nach einem
/// Absturz an einer beliebigen Stelle im Log aufsetzen — deshalb erst in eine
/// temporäre Datei, dann umbenennen.
///
/// Die temporäre Datei wird vor dem Rename gefsynct (Inhalt muss vor der
/// Sichtbarwerdung auf der Platte liegen), danach die umbenannte Datei
/// zusätzlich noch einmal (schadet nicht, macht die Absicht explizit) und —
/// nur Linux/Unix, best effort — das Verzeichnis, damit auch der Rename
/// selbst einen Absturz übersteht. Ein Verzeichnis-fsync-Fehlschlag ist kein
/// harter Fehler: manche Dateisysteme/Container-Overlays unterstützen ihn
/// nicht, und der Cursor-Inhalt ist zu diesem Zeitpunkt bereits durabel.
fn write_cursor(dir: &Path, pos: LogPosition) -> Result<()> {
    let path = cursor_path(dir);
    let tmp = path.with_extension("tmp");
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&pos.segment.to_le_bytes());
    bytes[8..16].copy_from_slice(&pos.offset.to_le_bytes());
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(|source| BufferError::Io {
                path: tmp.clone(),
                source,
            })?;
        file.write_all(&bytes).map_err(|source| BufferError::Io {
            path: tmp.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| BufferError::Io {
            path: tmp.clone(),
            source,
        })?;
    }
    std::fs::rename(&tmp, &path).map_err(|source| BufferError::Io {
        path: path.clone(),
        source,
    })?;

    if let Ok(file) = File::open(&path) {
        let _ = file.sync_all();
    }
    sync_dir_best_effort(dir);
    Ok(())
}

/// Best-effort `fsync` des Verzeichnisses, damit ein Rename/Create darin einen
/// Absturz übersteht. Fehler werden nur geloggt: nicht jedes Dateisystem
/// unterstützt das öffnen/fsyncen eines Verzeichnisses, und ein Fehlschlag
/// hier darf den eigentlichen (bereits durabel geschriebenen) Cursor nicht
/// ungültig machen.
#[cfg(unix)]
fn sync_dir_best_effort(dir: &Path) {
    match File::open(dir) {
        Ok(dir_file) => {
            if let Err(source) = dir_file.sync_all() {
                tracing::warn!(path = %dir.display(), error = %source, "fsync of wal directory failed");
            }
        }
        Err(source) => {
            tracing::warn!(path = %dir.display(), error = %source, "could not open wal directory for fsync");
        }
    }
}

#[cfg(not(unix))]
fn sync_dir_best_effort(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(dir: &Path) -> SegmentedLog {
        SegmentedLog::open(dir, 64 * 1024).expect("open log")
    }

    #[test]
    fn append_and_read_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log = open(dir.path());
        log.append(b"one").expect("append");
        log.append(b"two").expect("append");

        let batch = log.read_batch(10).expect("read");
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].payload, b"one");
        assert_eq!(batch[1].payload, b"two");
        assert_eq!(log.pending(), 2);
    }

    #[test]
    fn uncommitted_reads_are_repeated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log = open(dir.path());
        log.append(b"alpha").expect("append");

        let first = log.read_batch(10).expect("read");
        let second = log.read_batch(10).expect("read again");
        assert_eq!(
            first[0].payload, second[0].payload,
            "no commit, no progress"
        );
    }

    #[test]
    fn commit_advances_and_empties() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log = open(dir.path());
        log.append(b"alpha").expect("append");
        log.append(b"beta").expect("append");

        let batch = log.read_batch(10).expect("read");
        let last = batch.last().expect("record").next;
        log.commit(last).expect("commit");

        assert_eq!(log.pending(), 0);
        assert!(log.read_batch(10).expect("read").is_empty());
    }

    #[test]
    fn partial_commit_keeps_the_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log = open(dir.path());
        for i in 0..5u8 {
            log.append(&[i]).expect("append");
        }

        let batch = log.read_batch(2).expect("read");
        log.commit(batch[1].next).expect("commit");
        assert_eq!(log.pending(), 3);

        let rest = log.read_batch(10).expect("read");
        assert_eq!(rest.len(), 3);
        assert_eq!(rest[0].payload, vec![2]);
    }

    #[test]
    fn state_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let mut log = open(dir.path());
            log.append(b"persisted-1").expect("append");
            log.append(b"persisted-2").expect("append");
            let batch = log.read_batch(1).expect("read");
            log.commit(batch[0].next).expect("commit");
        }

        let mut log = open(dir.path());
        assert_eq!(log.pending(), 1, "committed record stays consumed");
        let batch = log.read_batch(10).expect("read");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload, b"persisted-2");
    }

    #[test]
    fn torn_tail_record_is_truncated_not_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let mut log = open(dir.path());
            log.append(b"good").expect("append");
            log.flush().expect("flush");
        }

        // Halben Record anhängen, wie ihn ein Stromausfall hinterlässt.
        let seg = segment_path(dir.path(), 1);
        let mut f = OpenOptions::new().append(true).open(&seg).expect("open");
        f.write_all(&7u32.to_le_bytes()).expect("write len");
        f.write_all(&0u32.to_le_bytes()).expect("write crc");
        f.write_all(b"tru").expect("write partial payload");
        drop(f);

        let mut log = open(dir.path());
        assert_eq!(log.pending(), 1, "only the good record survives");
        let batch = log.read_batch(10).expect("read");
        assert_eq!(batch[0].payload, b"good");

        // Nach dem Kürzen muss weiteres Anhängen wieder sauber funktionieren.
        log.append(b"after-recovery").expect("append");
        log.flush().expect("flush");
        let batch = log.read_batch(10).expect("read");
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[1].payload, b"after-recovery");
    }

    #[test]
    fn corrupted_payload_ends_the_segment() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let mut log = open(dir.path());
            log.append(b"first").expect("append");
            log.append(b"second").expect("append");
            log.flush().expect("flush");
        }

        // Ein Byte im zweiten Payload kippen → CRC schlägt fehl.
        let seg = segment_path(dir.path(), 1);
        let mut bytes = std::fs::read(&seg).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&seg, &bytes).expect("write");

        let mut log = open(dir.path());
        let batch = log.read_batch(10).expect("read");
        assert_eq!(
            batch.len(),
            1,
            "corrupted record and everything after is cut"
        );
        assert_eq!(batch[0].payload, b"first");
    }

    #[test]
    fn segments_roll_and_consumed_ones_are_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log = SegmentedLog::open(dir.path(), 64 * 1024).expect("open");

        let payload = vec![b'x'; 4096];
        for _ in 0..40 {
            log.append(&payload).expect("append");
        }
        log.flush().expect("flush");
        assert!(
            discover_segments(dir.path()).expect("scan").len() > 1,
            "expected the log to roll into multiple segments"
        );

        let batch = log.read_batch(1000).expect("read");
        log.commit(batch.last().expect("record").next)
            .expect("commit");

        assert_eq!(log.pending(), 0);
        assert_eq!(
            discover_segments(dir.path()).expect("scan").len(),
            1,
            "consumed segments are removed, the active one stays"
        );
    }

    #[test]
    fn dropping_oldest_segment_frees_space_and_counts_loss() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log = SegmentedLog::open(dir.path(), 64 * 1024).expect("open");

        let payload = vec![b'y'; 4096];
        for _ in 0..40 {
            log.append(&payload).expect("append");
        }
        log.flush().expect("flush");

        let before_bytes = log.disk_bytes();
        let before_pending = log.pending();

        let dropped = log.drop_oldest_segment().expect("drop").expect("a segment");
        assert!(dropped > 0);
        assert_eq!(log.dropped(), dropped);
        assert!(log.disk_bytes() < before_bytes);
        assert_eq!(log.pending(), before_pending - dropped);

        // Nach dem Verwerfen muss weitergelesen werden können.
        let batch = log.read_batch(5).expect("read");
        assert!(!batch.is_empty());
    }

    #[test]
    fn active_segment_is_never_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log = open(dir.path());
        log.append(b"only").expect("append");
        assert!(log.drop_oldest_segment().expect("drop").is_none());
        assert_eq!(log.pending(), 1);
    }

    #[test]
    fn oversized_record_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log = open(dir.path());
        let huge = vec![0u8; MAX_RECORD_BYTES as usize + 1];
        assert!(matches!(
            log.append(&huge),
            Err(BufferError::RecordTooLarge(_))
        ));
    }

    #[test]
    fn stale_cursor_pointing_at_deleted_segment_recovers() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let mut log = open(dir.path());
            log.append(b"data").expect("append");
            log.flush().expect("flush");
        }
        // Cursor zeigt auf ein Segment, das es nie gab.
        write_cursor(
            dir.path(),
            LogPosition {
                segment: 0,
                offset: 999,
            },
        )
        .expect("cursor");

        let mut log = open(dir.path());
        let batch = log.read_batch(10).expect("read");
        assert_eq!(batch.len(), 1, "reader falls back to the oldest segment");
    }
}
