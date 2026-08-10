//! Mehrstufiges Geräte-Fingerprinting.
//!
//! Drei Stufen, aufsteigend nach Aufwand und absteigend nach Verlässlichkeit:
//!
//! 1. **Passiv, sehr zuverlässig** — MAC-OUI und DHCP-Option-55. Beides kommt
//!    ungefragt über die Leitung und ist je Stack charakteristisch.
//! 2. **Passiv, mittel** — mDNS- und SSDP-Ankündigungen. Geräte beschreiben
//!    sich hier selbst; die Angabe ist gut, aber nicht überprüft.
//! 3. **Aktiv** — Banner offener Dienste und SNMP `sysDescr`. Nur im
//!    entsprechenden Betriebsmodus und nur auf freigegebenen Zielen.
//!
//! Ausdrücklich **nicht** enthalten ist aktives OS-Fingerprinting über
//! ungewöhnliche Flag-Kombinationen oder Fragmentierung (die klassische
//! `nmap -O`-Technik). Es ist unzuverlässig hinter NAT und Virtualisierung,
//! löst in vielen Netzen IDS-Alarme aus und passt nicht zu einem Werkzeug, das
//! Sichtbarkeit schafft statt zu sondieren.

pub mod engine;
pub mod oui;
pub mod signature;

pub use engine::{DeviceSignals, FingerprintEngine, MIN_REPORTABLE_CONFIDENCE};
pub use oui::OuiDatabase;
pub use signature::device_type;

/// Dateiname der optionalen, vollständigen OUI-Registrierung im
/// State-Verzeichnis des Sensors.
pub const OUI_FILE: &str = "oui.csv";
