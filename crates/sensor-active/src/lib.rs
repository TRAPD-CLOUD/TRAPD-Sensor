//! Aktive, defensive Erkennung.
//!
//! Dieses Crate ist das einzige im Sensor, das Pakete erzeugt. Es steht unter
//! drei Bedingungen, die alle erfüllt sein müssen:
//!
//! 1. Der Betriebsmodus erlaubt aktive Erkennung (`balanced` oder `active`).
//! 2. Der Betreiber hat auf dem Host quittiert (`active.acknowledged`).
//! 3. Das Ziel liegt in einem konfigurierten CIDR und in keinem Ausschluss.
//!
//! Fehlt eine davon, liefert [`Scanner::new`] gar keinen Scanner. Es gibt keinen
//! Pfad, der an dieser Prüfung vorbeiführt — die Proben in [`probe`] kennen die
//! Policy nicht einmal.
//!
//! ## Was hier bewusst fehlt
//!
//! Kein SYN-Stealth mit Raw Sockets, keine Fragmentierungs-Tricks, kein
//! aktives OS-Fingerprinting über ungewöhnliche Flag-Kombinationen, kein
//! Erraten von Zugangsdaten (auch nicht von SNMP-Communities), kein
//! Schwachstellen-Test. Der Sensor stellt fest, was da ist — er sondiert nicht,
//! wie man hineinkommt.

pub mod probe;
pub mod rate_limit;
pub mod scanner;
pub mod snmp;

pub use probe::{PortProbeResult, PortState};
pub use rate_limit::RateLimiter;
pub use scanner::{Scanner, SweepStats};
