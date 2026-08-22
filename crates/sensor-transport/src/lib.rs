//! Anbindung des Sensors an das TRAPD-Backend.
//!
//! Enthält den HTTP-Client (Enrollment, Upload, Remote-Config), die
//! Fehlerklassifikation, das Backoff und die Uploader-Task, die die persistente
//! Queue leert.
//!
//! Authentifiziert wird primär mit einem Bearer-Secret aus dem Enrollment —
//! dasselbe Verfahren wie beim Endpoint-Agent, damit Backend und Betrieb nur
//! ein Modell kennen müssen. Optional kann zusätzlich ein mTLS-Client-
//! Zertifikat konfiguriert werden ([`client::ClientIdentity`],
//! `backend.mtls_client_cert_path`/`_key_path`) — additiv und ohne den
//! Bearer-Pfad zu ersetzen, standardmäßig aus. Die Trennung von `api_url`
//! und `ingest_url` sowie die zentrale [`client::BackendClient`]-Fassade
//! sind so geschnitten, dass das den Rest des Sensors nicht berührt.

pub mod backoff;
pub mod client;
pub mod error;
pub mod remote_config;
pub mod uploader;

pub use backoff::{Backoff, BackoffConfig};
pub use client::{BackendClient, ClientIdentity, EnrollRequest, EnrollResponse};
pub use error::{Result, TransportError};
pub use remote_config::{ApplyOutcome, RemoteConfig};
pub use uploader::{
    BackendSink, BatchSink, Uploader, UploaderConfig, UploaderOutcome, UploaderStats,
    UploaderStatsSnapshot,
};
