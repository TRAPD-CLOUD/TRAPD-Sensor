//! Herstellererkennung über das MAC-Präfix (OUI).
//!
//! Die vollständige IEEE-Registrierung hat über 30 000 Einträge und ändert sich
//! laufend — sie gehört nicht ins Binary. Deshalb zwei Wege:
//!
//! 1. Eine kleine, eingebaute Liste der Hersteller, die in Homelabs praktisch
//!    immer vorkommen. Sie sorgt dafür, dass ein frisch installierter Sensor
//!    ohne jede Vorbereitung Brauchbares liefert.
//! 2. Eine optionale Datei (`oui.csv` im State-Verzeichnis), die die
//!    vollständige Registrierung nachlädt und Vorrang hat.
//!
//! Ein OUI sagt, *wer das Interface gebaut hat* — nicht, was das Gerät ist. Ein
//! Espressif-Chip steckt in Hunderten verschiedener Produkte. Das Ergebnis geht
//! deshalb als Hersteller-Signal in die Aggregation ein und nie als
//! Gerätetyp-Aussage.

use std::collections::HashMap;
use std::path::Path;

/// Eingebaute Kurzliste. Bewusst klein gehalten: jeder Eintrag hier ist eine
/// Behauptung über fremde Hardware, und eine falsche erzeugt ein falsch
/// beschriftetes Asset im Dashboard. Für Vollständigkeit ist die geladene
/// Registrierung zuständig.
const BUILTIN_OUI: &[(&str, &str)] = &[
    // Virtualisierung — im Homelab der häufigste Fall überhaupt.
    ("00:50:56", "VMware"),
    ("00:0c:29", "VMware"),
    ("00:05:69", "VMware"),
    ("00:1c:14", "VMware"),
    ("08:00:27", "Oracle VirtualBox"),
    ("52:54:00", "QEMU/KVM"),
    ("00:15:5d", "Microsoft Hyper-V"),
    ("00:16:3e", "Xen"),
    // Einplatinenrechner
    ("b8:27:eb", "Raspberry Pi Foundation"),
    ("dc:a6:32", "Raspberry Pi Trading"),
    ("e4:5f:01", "Raspberry Pi Trading"),
    ("d8:3a:dd", "Raspberry Pi Trading"),
    ("2c:cf:67", "Raspberry Pi Trading"),
    // IoT-Funkmodule
    ("24:0a:c4", "Espressif"),
    ("30:ae:a4", "Espressif"),
    ("a4:cf:12", "Espressif"),
    ("cc:50:e3", "Espressif"),
    ("84:f3:eb", "Espressif"),
    ("5c:cf:7f", "Espressif"),
    ("18:fe:34", "Espressif"),
    // Netzwerkausrüster
    ("00:00:0c", "Cisco"),
    ("00:1d:7e", "Cisco-Linksys"),
    ("74:ac:b9", "Ubiquiti"),
    ("fc:ec:da", "Ubiquiti"),
    ("24:5a:4c", "Ubiquiti"),
    ("00:27:22", "Ubiquiti"),
    ("00:09:5b", "Netgear"),
    ("00:14:6c", "Netgear"),
    ("00:1f:33", "Netgear"),
    ("00:1e:58", "D-Link"),
    ("00:24:01", "D-Link"),
    // Router im DACH-Raum
    ("00:04:0e", "AVM"),
    ("00:1f:3f", "AVM"),
    ("08:96:d7", "AVM"),
    ("3c:a6:2f", "AVM"),
    ("c8:0e:14", "AVM"),
    ("e0:28:6d", "AVM"),
    // NAS
    ("00:11:32", "Synology"),
    ("24:5e:be", "QNAP"),
    ("00:14:ee", "Western Digital"),
    // Drucker
    ("00:80:77", "Brother"),
    ("00:1b:a9", "Brother"),
    ("00:00:48", "Seiko Epson"),
    ("00:26:ab", "Seiko Epson"),
    ("00:1b:78", "Hewlett Packard"),
    ("3c:d9:2b", "Hewlett Packard"),
    // Server / Workstations
    ("00:25:90", "Super Micro"),
    ("ac:1f:6b", "Super Micro"),
    ("00:14:22", "Dell"),
    ("00:26:b9", "Dell"),
    ("b8:2a:72", "Dell"),
    ("00:1b:21", "Intel"),
    ("00:1e:67", "Intel"),
    // Smart Home
    ("00:17:88", "Philips Lighting"),
    ("ec:b5:fa", "Philips Lighting"),
];

pub struct OuiDatabase {
    entries: HashMap<[u8; 3], String>,
    /// Wurde eine externe Registrierung geladen?
    loaded_from_file: bool,
}

impl Default for OuiDatabase {
    fn default() -> Self {
        Self::builtin()
    }
}

impl OuiDatabase {
    /// Nur die eingebaute Kurzliste.
    pub fn builtin() -> Self {
        let entries = BUILTIN_OUI
            .iter()
            .filter_map(|(prefix, vendor)| parse_prefix(prefix).map(|p| (p, (*vendor).to_string())))
            .collect();
        Self {
            entries,
            loaded_from_file: false,
        }
    }

    /// Lädt zusätzlich eine CSV-Datei `prefix,vendor` (Zeilen mit `#` sind
    /// Kommentare). Fehlt die Datei, bleibt es bei der Kurzliste — ein Sensor
    /// soll deswegen nicht den Start verweigern.
    pub fn with_file(path: &Path) -> Self {
        let mut db = Self::builtin();
        let Ok(content) = std::fs::read_to_string(path) else {
            tracing::debug!(
                path = %path.display(),
                "no OUI database found, using the built-in short list"
            );
            return db;
        };

        let mut added = 0usize;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((prefix, vendor)) = line.split_once(',') else {
                continue;
            };
            let vendor = vendor.trim().trim_matches('"');
            if vendor.is_empty() {
                continue;
            }
            if let Some(key) = parse_prefix(prefix.trim()) {
                // Die geladene Registrierung hat Vorrang: sie ist aktueller als
                // alles, was im Binary steht.
                db.entries.insert(key, vendor.to_string());
                added += 1;
            }
        }

        if added > 0 {
            db.loaded_from_file = true;
            tracing::info!(path = %path.display(), entries = added, "OUI database loaded");
        }
        db
    }

    /// Hersteller zu einer normalisierten MAC (`aa:bb:cc:dd:ee:ff`).
    ///
    /// Ein bekanntes Präfix gewinnt immer — auch wenn es lokal verwaltet ist.
    /// Das ist kein Sonderfall, sondern der Regelfall bei Virtualisierung:
    /// QEMU/KVM vergibt standardmäßig `52:54:00…`, und das Bit für "lokal
    /// verwaltet" ist dort gesetzt. Würde die Prüfung zuerst greifen, bliebe
    /// ausgerechnet die häufigste VM-Kennung im Homelab unerkannt.
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let prefix = parse_prefix(mac)?;
        if let Some(vendor) = self.entries.get(&prefix) {
            return Some(vendor.as_str());
        }
        // Unbekannt *und* lokal verwaltet: erfundene Adresse (Container, VPN,
        // Adressrandomisierung auf Smartphones). Dafür gibt es keinen
        // Hersteller, und einen zu raten wäre falsch.
        None
    }

    /// Ist die MAC lokal verwaltet (also nicht vom Hersteller vergeben)?
    pub fn is_locally_administered(mac: &str) -> bool {
        parse_prefix(mac).map(|p| p[0] & 0x02 != 0).unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn loaded_from_file(&self) -> bool {
        self.loaded_from_file
    }
}

/// Liest die ersten drei Oktette aus `aa:bb:cc…`, `aa-bb-cc…` oder `aabbcc…`.
fn parse_prefix(mac: &str) -> Option<[u8; 3]> {
    let hex: Vec<u8> = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c as u8)
        .collect();
    if hex.len() < 6 {
        return None;
    }
    let mut out = [0u8; 3];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (hex[i * 2] as char).to_digit(16)? as u8;
        let lo = (hex[i * 2 + 1] as char).to_digit(16)? as u8;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_database_resolves_common_vendors() {
        let db = OuiDatabase::builtin();
        assert_eq!(
            db.lookup("b8:27:eb:11:22:33"),
            Some("Raspberry Pi Foundation")
        );
        assert_eq!(db.lookup("00:50:56:aa:bb:cc"), Some("VMware"));
        assert_eq!(db.lookup("52:54:00:12:34:56"), Some("QEMU/KVM"));
        assert!(!db.is_empty());
    }

    #[test]
    fn lookup_is_case_and_separator_insensitive() {
        let db = OuiDatabase::builtin();
        assert_eq!(
            db.lookup("B8:27:EB:11:22:33"),
            Some("Raspberry Pi Foundation")
        );
        assert_eq!(
            db.lookup("b8-27-eb-11-22-33"),
            Some("Raspberry Pi Foundation")
        );
        assert_eq!(db.lookup("b827eb112233"), Some("Raspberry Pi Foundation"));
    }

    #[test]
    fn unknown_prefixes_return_nothing() {
        let db = OuiDatabase::builtin();
        assert_eq!(db.lookup("00:00:00:00:00:01"), None);
    }

    /// Randomisierte MACs (Smartphones, Container) tragen keinen Hersteller.
    /// Trotzdem einen zu nennen, wäre schlicht erfunden.
    #[test]
    fn unknown_locally_administered_macs_have_no_vendor() {
        let db = OuiDatabase::builtin();
        assert!(OuiDatabase::is_locally_administered("02:11:22:33:44:55"));
        assert_eq!(db.lookup("02:11:22:33:44:55"), None);
        assert!(!OuiDatabase::is_locally_administered("b8:27:eb:11:22:33"));
    }

    /// QEMU/KVM vergibt `52:54:00…` — lokal verwaltet und trotzdem eindeutig.
    /// Ein bekanntes Präfix darf an der Bit-Prüfung nicht scheitern.
    #[test]
    fn known_prefix_wins_over_the_locally_administered_bit() {
        let db = OuiDatabase::builtin();
        assert!(OuiDatabase::is_locally_administered("52:54:00:12:34:56"));
        assert_eq!(db.lookup("52:54:00:12:34:56"), Some("QEMU/KVM"));
    }

    #[test]
    fn malformed_macs_are_rejected() {
        let db = OuiDatabase::builtin();
        assert_eq!(db.lookup(""), None);
        assert_eq!(db.lookup("zz:zz:zz"), None);
        assert_eq!(db.lookup("b8:27"), None);
    }

    #[test]
    fn file_database_extends_and_overrides_the_builtin_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("oui.csv");
        std::fs::write(
            &path,
            "# comment line\n\
             AA:BB:CC,Example Corp\n\
             B8:27:EB,\"Raspberry Pi (updated)\"\n\
             malformed line without comma\n\
             ZZ:ZZ:ZZ,Bogus\n",
        )
        .expect("write");

        let db = OuiDatabase::with_file(&path);
        assert!(db.loaded_from_file());
        assert_eq!(db.lookup("aa:bb:cc:00:00:01"), Some("Example Corp"));
        assert_eq!(
            db.lookup("b8:27:eb:11:22:33"),
            Some("Raspberry Pi (updated)"),
            "the loaded registry is newer than the compiled-in list"
        );
        assert_eq!(
            db.lookup("00:50:56:aa:bb:cc"),
            Some("VMware"),
            "builtin kept"
        );
    }

    #[test]
    fn missing_file_falls_back_to_builtin_without_failing() {
        let db = OuiDatabase::with_file(Path::new("/definitely/not/here/oui.csv"));
        assert!(!db.loaded_from_file());
        assert_eq!(db.lookup("00:50:56:aa:bb:cc"), Some("VMware"));
    }

    #[test]
    fn builtin_entries_are_all_parseable_and_unique() {
        let db = OuiDatabase::builtin();
        assert_eq!(
            db.len(),
            BUILTIN_OUI.len(),
            "every builtin prefix must parse and be unique"
        );
    }
}
