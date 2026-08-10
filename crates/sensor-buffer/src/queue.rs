//! Die Ereignis-Queue des Sensors: drei Logs, eine Platten-Obergrenze.
//!
//! Statt eines einzigen Logs mit Prioritätsfeld bekommt jede Stufe ihr eigenes
//! [`SegmentedLog`]. Das macht die beiden Operationen, auf die es ankommt,
//! trivial statt teuer:
//!
//! * **Lesen nach Wichtigkeit** — der Uploader leert erst `Critical`, dann
//!   `Standard`, dann `Bulk`. Kein Sortieren, kein Scannen.
//! * **Verwerfen nach Wichtigkeit** — läuft die Platte voll, fällt das älteste
//!   Segment des unwichtigsten nicht-leeren Logs. Ein Log mit gemischten
//!   Prioritäten müsste dafür umkopieren.
//!
//! Die Obergrenze ist eine Zusage an den Betreiber: ein Backend-Ausfall darf
//! einen Homelab-Host nicht die Platte volllaufen lassen. Sie gilt deshalb
//! ausnahmslos — notfalls fallen auch `Critical`-Events, denn ein Sensor, der
//! das Dateisystem füllt, richtet mehr Schaden an als einer mit Datenlücke.

use std::path::{Path, PathBuf};

use trapd_sensor_core::model::{Priority, SensorEvent};

use crate::error::Result;
use crate::log::{LogPosition, SegmentedLog};

/// Prioritäten in Lesereihenfolge (wichtigste zuerst).
const DRAIN_ORDER: [Priority; 3] = [Priority::Critical, Priority::Standard, Priority::Bulk];

/// Prioritäten in Verwerfreihenfolge (unwichtigste zuerst).
const EVICT_ORDER: [Priority; 3] = [Priority::Bulk, Priority::Standard, Priority::Critical];

fn subdir(priority: Priority) -> &'static str {
    match priority {
        Priority::Bulk => "bulk",
        Priority::Standard => "standard",
        Priority::Critical => "critical",
    }
}

fn slot(priority: Priority) -> usize {
    match priority {
        Priority::Bulk => 0,
        Priority::Standard => 1,
        Priority::Critical => 2,
    }
}

/// Ergebnis eines [`EventQueue::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushOutcome {
    /// Wurde das Event gespeichert?
    pub stored: bool,
    /// Wie viele bereits gepufferte Events mussten dafür weichen?
    pub evicted: u64,
}

/// Ein gelesener, noch nicht bestätigter Stapel.
#[derive(Debug, Clone, Default)]
pub struct ReadBatch {
    pub events: Vec<SensorEvent>,
    /// Neue Leseposition je Priorität — nur für die Logs gesetzt, aus denen
    /// tatsächlich gelesen wurde.
    positions: [Option<LogPosition>; 3],
    /// Records, die sich nicht mehr deserialisieren ließen (etwa nach einem
    /// Formatwechsel). Sie werden mitbestätigt, damit sie die Queue nicht
    /// dauerhaft blockieren.
    pub undecodable: u64,
}

impl ReadBatch {
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.undecodable == 0
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueStats {
    pub pending: u64,
    pub disk_bytes: u64,
    pub dropped: u64,
    pub pending_critical: u64,
    pub pending_standard: u64,
    pub pending_bulk: u64,
}

pub struct EventQueue {
    dir: PathBuf,
    logs: [SegmentedLog; 3],
    max_disk_bytes: u64,
    dropped_total: u64,
}

impl EventQueue {
    /// Öffnet die Queue unter `dir`. Vorhandene Segmente werden dabei
    /// wiederhergestellt (siehe [`SegmentedLog::open`]).
    pub fn open(dir: &Path, max_disk_bytes: u64, segment_bytes: u64) -> Result<Self> {
        let bulk = SegmentedLog::open(&dir.join(subdir(Priority::Bulk)), segment_bytes)?;
        let standard = SegmentedLog::open(&dir.join(subdir(Priority::Standard)), segment_bytes)?;
        let critical = SegmentedLog::open(&dir.join(subdir(Priority::Critical)), segment_bytes)?;

        // Verworfen wird immer ein ganzes Segment, und das *aktive* Segment
        // eines Logs bleibt unantastbar. Passen in das Budget nicht mindestens
        // zwei Segmente pro Log, gibt es im Ernstfall nichts zu verwerfen: die
        // Queue würde dann jedes neue Event ablehnen statt altes freizugeben —
        // aus einer Platten-Obergrenze würde ein Totalausfall der Telemetrie.
        // Deshalb wird die Grenze nach unten aufgezogen, und zwar anhand der
        // *effektiven* Segmentgröße (das Log erzwingt selbst ein Minimum).
        let effective_segment = bulk.segment_bytes();
        let floor = effective_segment * 2 * DRAIN_ORDER.len() as u64;
        if max_disk_bytes < floor {
            tracing::warn!(
                configured = max_disk_bytes,
                effective = floor,
                segment_bytes = effective_segment,
                "buffer.max_disk_bytes is too small for segment-wise retention — raising it"
            );
        }

        let queue = Self {
            dir: dir.to_path_buf(),
            logs: [bulk, standard, critical],
            max_disk_bytes: max_disk_bytes.max(floor),
            dropped_total: 0,
        };
        tracing::info!(
            dir = %dir.display(),
            pending = queue.stats().pending,
            disk_bytes = queue.stats().disk_bytes,
            max_disk_bytes = queue.max_disk_bytes,
            "event queue opened"
        );
        Ok(queue)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Nimmt ein Event auf. Reicht der Platz nicht, wird zuerst unwichtigeres
    /// Material verworfen; hilft auch das nicht, fällt das neue Event selbst.
    pub fn push(&mut self, event: &SensorEvent) -> Result<PushOutcome> {
        let payload = serde_json::to_vec(event)?;
        let needed = payload.len() as u64 + 8;
        let priority = event.priority();

        let mut evicted = 0u64;
        while self.disk_bytes() + needed > self.max_disk_bytes {
            match self.evict_one()? {
                Some(n) => evicted += n,
                // Nichts mehr wegzuwerfen: alle Logs bestehen nur noch aus
                // ihrem aktiven Segment. Dann wird das neue Event verworfen —
                // die Platten-Zusage schlägt den einzelnen Datenpunkt.
                None => {
                    self.dropped_total += 1;
                    tracing::warn!(
                        priority = ?priority,
                        disk_bytes = self.disk_bytes(),
                        max_disk_bytes = self.max_disk_bytes,
                        "queue at disk limit with nothing left to evict — dropping incoming event"
                    );
                    return Ok(PushOutcome {
                        stored: false,
                        evicted,
                    });
                }
            }
        }

        self.log_mut(priority).append(&payload)?;
        Ok(PushOutcome {
            stored: true,
            evicted,
        })
    }

    /// Liest bis zu `max` Events, wichtigste Priorität zuerst.
    pub fn read_batch(&mut self, max: usize) -> Result<ReadBatch> {
        let mut batch = ReadBatch::default();
        let mut remaining = max;

        for priority in DRAIN_ORDER {
            if remaining == 0 {
                break;
            }
            let records = self.log_mut(priority).read_batch(remaining)?;
            if records.is_empty() {
                continue;
            }
            let mut last_pos = None;
            for record in records {
                last_pos = Some(record.next);
                match serde_json::from_slice::<SensorEvent>(&record.payload) {
                    Ok(event) => batch.events.push(event),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            priority = ?priority,
                            "discarding undecodable queue record"
                        );
                        batch.undecodable += 1;
                    }
                }
                remaining = remaining.saturating_sub(1);
            }
            batch.positions[slot(priority)] = last_pos;
        }

        Ok(batch)
    }

    /// Bestätigt einen gelesenen Stapel. Erst danach gibt die Queue den Platz
    /// frei — ein fehlgeschlagener Upload lässt die Events also stehen.
    pub fn commit(&mut self, batch: &ReadBatch) -> Result<()> {
        for priority in DRAIN_ORDER {
            if let Some(pos) = batch.positions[slot(priority)] {
                self.log_mut(priority).commit(pos)?;
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        for log in &mut self.logs {
            log.flush()?;
        }
        Ok(())
    }

    pub fn stats(&self) -> QueueStats {
        let dropped_from_logs: u64 = self.logs.iter().map(|l| l.dropped()).sum();
        QueueStats {
            pending: self.logs.iter().map(|l| l.pending()).sum(),
            disk_bytes: self.disk_bytes(),
            dropped: self.dropped_total + dropped_from_logs,
            pending_critical: self.log(Priority::Critical).pending(),
            pending_standard: self.log(Priority::Standard).pending(),
            pending_bulk: self.log(Priority::Bulk).pending(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.logs.iter().all(|l| l.is_empty())
    }

    /// Die tatsächlich durchgesetzte Platten-Obergrenze — kann über dem
    /// konfigurierten Wert liegen, siehe [`EventQueue::open`].
    pub fn max_disk_bytes(&self) -> u64 {
        self.max_disk_bytes
    }

    // -- intern ------------------------------------------------------------

    fn disk_bytes(&self) -> u64 {
        self.logs.iter().map(|l| l.disk_bytes()).sum()
    }

    fn log(&self, priority: Priority) -> &SegmentedLog {
        &self.logs[slot(priority)]
    }

    fn log_mut(&mut self, priority: Priority) -> &mut SegmentedLog {
        &mut self.logs[slot(priority)]
    }

    /// Verwirft ein Segment beim unwichtigsten Log, das noch etwas herzugeben
    /// hat. `None` = nichts mehr verwerfbar.
    fn evict_one(&mut self) -> Result<Option<u64>> {
        for priority in EVICT_ORDER {
            if let Some(dropped) = self.log_mut(priority).drop_oldest_segment()? {
                tracing::warn!(
                    priority = ?priority,
                    dropped,
                    "queue over disk limit — evicted oldest segment"
                );
                return Ok(Some(dropped));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use trapd_sensor_core::model::{
        FlowDirection, FlowObservation, Observation, StatusLevel, StatusObservation,
        TransportProtocol,
    };

    fn status_event(seq: u64) -> SensorEvent {
        SensorEvent::new(
            seq,
            Observation::Status(StatusObservation {
                level: StatusLevel::Info,
                code: format!("code-{seq}"),
                message: "status".into(),
                details: BTreeMap::new(),
            }),
        )
    }

    fn flow_event(seq: u64) -> SensorEvent {
        SensorEvent::new(
            seq,
            Observation::Flow(FlowObservation {
                source_ip: "10.0.0.1".parse().expect("ip"),
                source_port: Some(1000 + seq as u16),
                dest_ip: "10.0.0.2".parse().expect("ip"),
                dest_port: Some(443),
                protocol: TransportProtocol::Tcp,
                service: Some("https".into()),
                direction: FlowDirection::Outbound,
                bytes: 4096,
                packets: 8,
                duration_ms: 250,
                first_seen: "2026-01-01T00:00:00Z".into(),
                last_seen: "2026-01-01T00:01:00Z".into(),
            }),
        )
    }

    /// Bulk-Event mit großem Payload, um die Platten-Grenze schnell zu erreichen.
    fn fat_flow_event(seq: u64) -> SensorEvent {
        let mut event = flow_event(seq);
        if let Observation::Flow(flow) = &mut event.observation {
            flow.service = Some("x".repeat(2048));
        }
        event
    }

    fn open(dir: &Path) -> EventQueue {
        EventQueue::open(dir, 1024 * 1024, 64 * 1024).expect("open queue")
    }

    #[test]
    fn push_and_read_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut q = open(dir.path());
        assert!(q.push(&status_event(1)).expect("push").stored);
        assert!(q.push(&flow_event(2)).expect("push").stored);

        let stats = q.stats();
        assert_eq!(stats.pending, 2);
        assert_eq!(stats.pending_critical, 1);
        assert_eq!(stats.pending_bulk, 1);

        let batch = q.read_batch(10).expect("read");
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn critical_events_are_drained_before_bulk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut q = open(dir.path());
        // Bulk zuerst einstellen — die Lesereihenfolge muss es trotzdem hinten anstellen.
        for i in 0..5 {
            q.push(&flow_event(i)).expect("push");
        }
        q.push(&status_event(99)).expect("push");

        let batch = q.read_batch(2).expect("read");
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.events[0].event_type(), "network.sensor.status");
        assert_eq!(batch.events[1].event_type(), "network.flow.metadata");
    }

    #[test]
    fn commit_is_required_for_progress() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut q = open(dir.path());
        q.push(&status_event(1)).expect("push");

        let first = q.read_batch(10).expect("read");
        assert_eq!(first.len(), 1);

        let repeat = q.read_batch(10).expect("read again");
        assert_eq!(repeat.len(), 1, "failed upload must leave the event queued");

        q.commit(&repeat).expect("commit");
        assert!(q.read_batch(10).expect("read").is_empty());
        assert_eq!(q.stats().pending, 0);
    }

    #[test]
    fn queue_survives_restart_with_uncommitted_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let mut q = open(dir.path());
            q.push(&status_event(1)).expect("push");
            q.push(&flow_event(2)).expect("push");
            q.flush().expect("flush");
        }

        let mut q = open(dir.path());
        assert_eq!(
            q.stats().pending,
            2,
            "nothing was committed, nothing is lost"
        );
        let batch = q.read_batch(10).expect("read");
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn disk_limit_is_respected_and_bulk_is_evicted_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut q = EventQueue::open(dir.path(), 512 * 1024, 16 * 1024).expect("open");
        let limit = q.max_disk_bytes();

        q.push(&status_event(1)).expect("push");
        for i in 0..2_000 {
            q.push(&fat_flow_event(i)).expect("push");
        }
        q.flush().expect("flush");

        let stats = q.stats();
        assert!(
            stats.disk_bytes <= limit,
            "disk usage {} exceeded the enforced limit {limit}",
            stats.disk_bytes
        );
        assert!(stats.dropped > 0, "expected bulk events to be evicted");
        assert_eq!(
            stats.pending_critical, 1,
            "the critical event must outlive the bulk flood"
        );
        assert!(
            stats.pending_bulk > 0,
            "eviction must free space, not empty the queue"
        );
    }

    #[test]
    fn eviction_reports_itself_through_push_outcome() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut q = EventQueue::open(dir.path(), 512 * 1024, 16 * 1024).expect("open");

        let mut total_evicted = 0u64;
        let mut rejected = 0u64;
        for i in 0..2_000 {
            let outcome = q.push(&fat_flow_event(i)).expect("push");
            total_evicted += outcome.evicted;
            if !outcome.stored {
                rejected += 1;
            }
        }
        assert!(total_evicted > 0, "expected segments to be evicted");
        assert_eq!(
            rejected, 0,
            "with room for several segments, no incoming event should be rejected"
        );
        assert_eq!(q.stats().dropped, total_evicted);
    }

    /// Eine zu knapp konfigurierte Grenze darf nicht dazu führen, dass die Queue
    /// nichts mehr aufnimmt — sie wird angehoben, bis segmentweises Verwerfen
    /// funktioniert.
    #[test]
    fn undersized_disk_limit_is_raised_to_a_workable_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut q = EventQueue::open(dir.path(), 1024, 16 * 1024).expect("open");
        assert!(
            q.max_disk_bytes() >= 16 * 1024 * 2,
            "limit must leave room for at least two segments per log"
        );

        for i in 0..500 {
            assert!(
                q.push(&fat_flow_event(i)).expect("push").stored,
                "queue must keep accepting events instead of rejecting everything"
            );
        }
        assert!(q.stats().pending > 0);
    }

    #[test]
    fn undecodable_records_do_not_block_the_queue() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            // Direkt ins Standard-Log schreiben, an der Serialisierung vorbei.
            let mut log =
                SegmentedLog::open(&dir.path().join("standard"), 64 * 1024).expect("open log");
            log.append(b"{\"not\":\"a sensor event\"}").expect("append");
            log.flush().expect("flush");
        }

        let mut q = open(dir.path());
        let batch = q.read_batch(10).expect("read");
        assert_eq!(batch.events.len(), 0);
        assert_eq!(batch.undecodable, 1);

        q.commit(&batch).expect("commit");
        assert_eq!(
            q.stats().pending,
            0,
            "garbage is acknowledged, not retried forever"
        );
    }

    #[test]
    fn empty_queue_reads_empty_batch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut q = open(dir.path());
        let batch = q.read_batch(100).expect("read");
        assert!(batch.is_empty());
        assert!(q.is_empty());
        q.commit(&batch).expect("commit of empty batch is a no-op");
    }

    #[test]
    fn partial_read_leaves_the_remainder_queued() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut q = open(dir.path());
        for i in 0..10 {
            q.push(&status_event(i)).expect("push");
        }

        let batch = q.read_batch(4).expect("read");
        assert_eq!(batch.len(), 4);
        q.commit(&batch).expect("commit");
        assert_eq!(q.stats().pending, 6);
    }
}
