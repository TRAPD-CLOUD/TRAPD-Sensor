//! Fehlertypen des Sensors.
//!
//! Bibliotheks-Crates geben [`SensorError`] zurück (`thiserror`), die Binaries
//! an ihren Rändern `anyhow::Result` — analog zur Konvention im TRAPD-Backend.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("configuration file {path} is not readable: {source}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("configuration file {path} is malformed: {source}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    /// Der Sensor ist noch nicht enrolled — es gibt keine lokale Identity.
    #[error("sensor is not enrolled (no identity at {path})")]
    NotEnrolled { path: PathBuf },

    /// Die Identity-Datei hat zu weite Dateirechte. Wird bewusst als harter
    /// Fehler behandelt: ein weltlesbares Sensor-Secret ist ein Sicherheits-
    /// vorfall, kein Schönheitsfehler.
    #[error("identity file {path} has insecure permissions {mode:o}, expected 0600")]
    InsecurePermissions { path: PathBuf, mode: u32 },

    #[error("identity store error at {path}: {source}")]
    Identity {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SensorError>;
