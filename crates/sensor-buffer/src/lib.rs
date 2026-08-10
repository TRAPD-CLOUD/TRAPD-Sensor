//! Persistente Ereignis-Queue des TRAPD Network Sensor.
//!
//! Der Sensor läuft an Stellen, an denen das Backend regelmäßig unerreichbar
//! ist — Heimanschluss, wartungsfenster, Netzumbau. Diese Queue ist die
//! Antwort darauf: Events landen zuerst auf der Platte und werden erst nach
//! bestätigtem Upload freigegeben (at-least-once). Zwei Zusagen macht sie
//! dabei:
//!
//! * Ein Absturz kostet höchstens den gerade halb geschriebenen Record.
//! * Die Queue wächst nie über ihre konfigurierte Grenze hinaus — auch nicht
//!   nach Tagen ohne Backend.
//!
//! Einstiegspunkt ist [`EventQueue`].

pub mod error;
pub mod log;
pub mod queue;

pub use error::{BufferError, Result};
pub use log::{LogPosition, SegmentedLog, MAX_RECORD_BYTES};
pub use queue::{EventQueue, PushOutcome, QueueStats, ReadBatch};
