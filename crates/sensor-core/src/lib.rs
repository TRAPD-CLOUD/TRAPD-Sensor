//! Gemeinsamer Kern des TRAPD Network Sensor.
//!
//! Hier liegt alles, was mehrere Sensor-Crates teilen: die Konfiguration samt
//! der daraus abgeleiteten Betriebs-Policy, das Beobachtungsmodell, das
//! Drahtformat zum Backend und die lokale Identität.
//!
//! Der Kern hat bewusst keine Laufzeit-Abhängigkeiten (kein Tokio, kein HTTP) —
//! er ist reine Datenmodellierung und dadurch vollständig ohne Netzwerk oder
//! root-Rechte testbar.

pub mod config;
pub mod deployment;
pub mod envelope;
pub mod error;
pub mod identity;
pub mod model;
pub mod visibility;

pub use config::{
    Cidr, EffectiveActivePolicy, EffectivePolicy, SensorConfig, SensorMode, DEFAULT_CONFIG_PATH,
};
pub use deployment::{DeploymentConfig, Edition, NetworkProfile, Vantage};
pub use envelope::{IngestBatch, IngestResponse, WireEvent, SOURCE_TYPE, WIRE_VERSION};
pub use error::{Result, SensorError};
pub use identity::{derive_device_id, Secret, SensorIdentity};
pub use model::{
    normalize_mac, sanitize_banner, AssetObservation, Confidence, DhcpObservation, DiscoveryMethod,
    DnsObservation, FingerprintEvidence, FingerprintObservation, FlowDirection, FlowObservation,
    HeartbeatObservation, InterfaceHealth, Observation, Priority, RelationshipObservation,
    RelationshipType, SensorEvent, ServiceObservation, StatusLevel, StatusObservation,
    TransportProtocol,
};
pub use visibility::{Capability, VisibilityLevel, VisibilityReport, VISIBILITY_SCHEMA_VERSION};

/// Version des Sensors, aus dem Cargo-Manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-Agent für alle Backend-Aufrufe.
pub fn user_agent() -> String {
    format!("trapd-sensor/{VERSION}")
}
