//! Das Drahtformat zwischen Sensor und `ingest-gateway`.
//!
//! Der Sensor schickt Batches von [`WireEvent`]; das Gateway ergänzt die
//! `project_id` aus der Authentifizierung (der Sensor bestimmt sie nie selbst)
//! und produziert daraus `EnvelopeV1` nach Kafka.
//!
//! `source_type` ist der Schlüssel zum quellenübergreifenden Modell: derselbe
//! Envelope trägt später Endpoint-Agent, Netzwerksensor und Cloud-Connector.
//! Das Backend entscheidet anhand dieses Feldes, welcher Normalizer greift, und
//! kann Assets über Korrelationsschlüssel (MAC, Hostname) quellenübergreifend
//! zusammenführen.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{Priority, SensorEvent};

/// Version des Drahtformats. Wird bei inkompatiblen Änderungen erhöht; das
/// Gateway kann so alte Sensoren weiter bedienen.
pub const WIRE_VERSION: u8 = 1;

/// Quellenkennung dieses Sensortyps.
pub const SOURCE_TYPE: &str = "network_sensor";

/// Ein Event auf der Leitung.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEvent {
    pub event_id: Uuid,
    /// Monoton je Sensor — das Gateway erkennt damit Replays.
    pub sequence: u64,
    /// RFC3339-Zeitpunkt der Beobachtung.
    pub observed_at: String,
    pub event_type: String,
    pub priority: Priority,
    /// Die serialisierte [`Observation`](crate::model::Observation), inklusive
    /// ihres `kind`-Diskriminators.
    pub payload: serde_json::Value,
}

impl WireEvent {
    pub fn from_event(event: &SensorEvent) -> Result<Self, serde_json::Error> {
        Ok(Self {
            event_id: event.event_id,
            sequence: event.sequence,
            observed_at: event.observed_at.clone(),
            event_type: event.event_type().to_string(),
            priority: event.priority(),
            payload: serde_json::to_value(&event.observation)?,
        })
    }
}

/// Ein Upload-Batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestBatch {
    pub v: u8,
    pub source_type: String,
    /// Muss zur authentifizierten Identität passen; das Gateway weist
    /// Abweichungen ab, statt sie zu übernehmen.
    pub sensor_id: String,
    pub sensor_version: String,
    /// Zeitpunkt des Absendens — erlaubt dem Backend, Uhrendrift und
    /// Nachlieferungen aus dem Offline-Puffer zu erkennen.
    pub sent_at: String,
    pub events: Vec<WireEvent>,
}

impl IngestBatch {
    pub fn new(
        sensor_id: impl Into<String>,
        sensor_version: impl Into<String>,
        events: Vec<WireEvent>,
    ) -> Self {
        Self {
            v: WIRE_VERSION,
            source_type: SOURCE_TYPE.to_string(),
            sensor_id: sensor_id.into(),
            sensor_version: sensor_version.into(),
            sent_at: chrono::Utc::now().to_rfc3339(),
            events,
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Antwort des Gateways auf einen Batch.
#[derive(Debug, Clone, Deserialize)]
pub struct IngestResponse {
    pub received: usize,
    #[serde(default)]
    pub errors: usize,
    #[serde(default)]
    pub request_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Observation, StatusLevel, StatusObservation};
    use std::collections::BTreeMap;

    fn sample_event() -> SensorEvent {
        SensorEvent::new(
            7,
            Observation::Status(StatusObservation {
                level: StatusLevel::Info,
                code: "started".into(),
                message: "sensor started".into(),
                details: BTreeMap::new(),
            }),
        )
    }

    #[test]
    fn wire_event_carries_type_priority_and_payload() {
        let event = sample_event();
        let wire = WireEvent::from_event(&event).expect("convert");
        assert_eq!(wire.event_type, "network.sensor.status");
        assert_eq!(wire.priority, Priority::Critical);
        assert_eq!(wire.sequence, 7);
        assert_eq!(wire.payload["kind"], "status");
        assert_eq!(wire.payload["code"], "started");
    }

    #[test]
    fn batch_declares_source_type_and_version() {
        let wire = WireEvent::from_event(&sample_event()).expect("convert");
        let batch = IngestBatch::new("sensor_abc", "0.1.0", vec![wire]);
        let json = serde_json::to_value(&batch).expect("serialize");
        assert_eq!(json["v"], 1);
        assert_eq!(json["source_type"], "network_sensor");
        assert_eq!(json["sensor_id"], "sensor_abc");
        assert_eq!(json["events"].as_array().expect("array").len(), 1);
    }

    #[test]
    fn ingest_response_tolerates_missing_optional_fields() {
        let parsed: IngestResponse = serde_json::from_str(r#"{"received":3}"#).expect("parse");
        assert_eq!(parsed.received, 3);
        assert_eq!(parsed.errors, 0);
        assert!(parsed.request_id.is_none());
    }
}
