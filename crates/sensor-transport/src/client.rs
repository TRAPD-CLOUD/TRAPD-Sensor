//! HTTP-Client zum TRAPD-Backend.
//!
//! Drei Aufrufe, mehr braucht der Sensor nicht:
//!
//! | Zweck        | Route                                      | Auth          |
//! |--------------|--------------------------------------------|---------------|
//! | Enrollment   | `POST {api}/api/v1/sensors/enroll`         | Einmal-Token  |
//! | Event-Upload | `POST {ingest}/api/v1/ingest/network`      | Sensor-Bearer |
//! | Remote-Config| `GET  {api}/api/v1/sensors/{id}/config`     | Sensor-Bearer |
//!
//! Der Bearer wandert ausschließlich in den `Authorization`-Header und
//! erscheint in keiner Logzeile — die Fehlerpfade geben Statuscodes und
//! Servermeldungen weiter, niemals die Anfrage selbst.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use trapd_sensor_core::envelope::{IngestBatch, IngestResponse};
use trapd_sensor_core::identity::{Secret, SensorIdentity};

use crate::error::{Result, TransportError};
use crate::remote_config::RemoteConfig;

/// Anfrage an den Enrollment-Endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollRequest {
    pub enrollment_token: String,
    pub device_id: String,
    pub hostname: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    pub os_version: String,
    pub arch: String,
    pub sensor_version: String,
    /// Betriebsmodus zum Zeitpunkt des Enrollments — das Dashboard zeigt damit
    /// an, was dieser Sensor überhaupt darf.
    pub mode: String,
    pub interfaces: Vec<String>,
}

impl std::fmt::Display for EnrollRequest {
    /// Bewusst ohne Token: `EnrollRequest` taucht in Fehlermeldungen auf.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EnrollRequest(device_id={}, hostname={}, mode={})",
            self.device_id, self.hostname, self.mode
        )
    }
}

/// Antwort des Enrollment-Endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub sensor_id: String,
    pub sensor_secret: String,
    pub project_id: String,
    #[serde(default)]
    pub api_url: Option<String>,
    #[serde(default)]
    pub ingest_url: Option<String>,
}

impl EnrollResponse {
    /// Baut die dauerhaft zu speichernde Identität.
    pub fn into_identity(self, device_id: String) -> SensorIdentity {
        SensorIdentity {
            sensor_id: self.sensor_id,
            project_id: self.project_id,
            secret: Secret::new(self.sensor_secret),
            device_id,
            enrolled_at: chrono::Utc::now().to_rfc3339(),
            api_url: self.api_url,
            ingest_url: self.ingest_url,
        }
    }
}

/// Fehlerantwort des Backends, soweit sie sich parsen lässt.
#[derive(Debug, Default, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

pub struct BackendClient {
    http: reqwest::Client,
    api_url: String,
    ingest_url: String,
}

impl BackendClient {
    pub fn new(api_url: &str, ingest_url: &str, timeout: Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(trapd_sensor_core::user_agent())
            // Der Sensor spricht mit genau einem Backend; ein Redirect würde
            // Bearer-Token an einen fremden Host tragen.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| TransportError::Network(e.to_string()))?;

        Ok(Self {
            http,
            api_url: api_url.trim_end_matches('/').to_string(),
            ingest_url: ingest_url.trim_end_matches('/').to_string(),
        })
    }

    /// Meldet den Sensor mit einem Einmal-Token an.
    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse> {
        let url = format!("{}/api/v1/sensors/enroll", self.api_url);
        let response = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        if !(200..300).contains(&status) {
            let detail = extract_message(&body);
            tracing::error!(status, detail = %detail, "enrollment rejected");
            return Err(TransportError::Enrollment(format!(
                "backend returned {status}: {detail}"
            )));
        }

        serde_json::from_str(&body).map_err(|e| {
            TransportError::Enrollment(format!("could not parse enrollment response: {e}"))
        })
    }

    /// Lädt einen Batch hoch.
    pub async fn upload(&self, secret: &Secret, batch: &IngestBatch) -> Result<IngestResponse> {
        let url = format!("{}/api/v1/ingest/network", self.ingest_url);
        let response = self
            .http
            .post(&url)
            .bearer_auth(secret.expose())
            .json(batch)
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        let status = response.status().as_u16();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.unwrap_or_default();

        if let Some(err) = classify(status, &body, retry_after) {
            return Err(err);
        }

        // Eine leere 2xx-Antwort ist zulässig; dann gelten alle Events als
        // angenommen.
        if body.trim().is_empty() {
            return Ok(IngestResponse {
                received: batch.len(),
                errors: 0,
                request_id: None,
            });
        }
        serde_json::from_str(&body).map_err(|e| TransportError::Server {
            status,
            message: format!("unparsable ingest response: {e}"),
        })
    }

    /// Holt die vom Dashboard gepflegte Konfiguration.
    pub async fn fetch_config(&self, identity: &SensorIdentity) -> Result<RemoteConfig> {
        let url = format!(
            "{}/api/v1/sensors/{}/config",
            self.api_url, identity.sensor_id
        );
        let response = self
            .http
            .get(&url)
            .bearer_auth(identity.secret.expose())
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        let status = response.status().as_u16();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.unwrap_or_default();

        if let Some(err) = classify(status, &body, retry_after) {
            return Err(err);
        }
        if body.trim().is_empty() {
            return Ok(RemoteConfig::default());
        }
        serde_json::from_str(&body).map_err(|e| TransportError::Server {
            status,
            message: format!("unparsable config response: {e}"),
        })
    }

    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    pub fn ingest_url(&self) -> &str {
        &self.ingest_url
    }
}

/// Übersetzt einen HTTP-Status in die Handlungsempfehlung des Sensors.
/// `None` = alles in Ordnung.
pub(crate) fn classify(
    status: u16,
    body: &str,
    retry_after: Option<Duration>,
) -> Option<TransportError> {
    let detail = extract_message(body);
    match status {
        200..=299 => None,
        401 | 403 => Some(TransportError::Unauthorized(detail)),
        // 410 Gone ist das Widerrufs-Signal: der Sensor existiert für das
        // Backend nicht mehr und stellt den Betrieb ein.
        410 => Some(TransportError::Revoked(detail)),
        429 => Some(TransportError::RateLimited { retry_after }),
        400..=499 => Some(TransportError::BadRequest {
            status,
            message: detail,
        }),
        _ => Some(TransportError::Server {
            status,
            message: detail,
        }),
    }
}

/// Zieht eine lesbare Meldung aus dem Fehlerkörper. Kein JSON? Dann der
/// gekürzte Rohtext — Hauptsache, im Log steht etwas Brauchbares.
fn extract_message(body: &str) -> String {
    if body.trim().is_empty() {
        return "(empty response)".to_string();
    }
    if let Ok(parsed) = serde_json::from_str::<ErrorBody>(body) {
        if let Some(msg) = parsed.message.or(parsed.error) {
            return msg;
        }
    }
    body.chars().take(200).collect()
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_not_an_error() {
        assert!(classify(200, "{}", None).is_none());
        assert!(classify(202, "", None).is_none());
    }

    #[test]
    fn auth_failures_map_to_unauthorized() {
        let err = classify(401, r#"{"error":"unauthorized"}"#, None).expect("error");
        assert!(matches!(err, TransportError::Unauthorized(_)));
        assert!(err.is_terminal());

        assert!(matches!(
            classify(403, "", None),
            Some(TransportError::Unauthorized(_))
        ));
    }

    #[test]
    fn gone_means_revoked() {
        let err = classify(410, r#"{"message":"sensor quarantined"}"#, None).expect("error");
        match &err {
            TransportError::Revoked(msg) => assert_eq!(msg, "sensor quarantined"),
            other => panic!("expected Revoked, got {other:?}"),
        }
        assert!(err.is_terminal());
        assert!(!err.is_retryable());
    }

    #[test]
    fn rate_limit_carries_retry_after() {
        let err = classify(429, "", Some(Duration::from_secs(45))).expect("error");
        assert_eq!(err.retry_after(), Some(Duration::from_secs(45)));
        assert!(err.is_retryable());
    }

    #[test]
    fn client_errors_are_not_retried() {
        let err = classify(400, r#"{"error":"invalid_body"}"#, None).expect("error");
        assert!(matches!(
            err,
            TransportError::BadRequest { status: 400, .. }
        ));
        assert!(!err.is_retryable());
    }

    #[test]
    fn server_errors_are_retried() {
        for status in [500, 502, 503, 504] {
            let err = classify(status, "", None).expect("error");
            assert!(err.is_retryable(), "status {status} should be retryable");
        }
    }

    #[test]
    fn error_message_extraction_prefers_message_then_error() {
        assert_eq!(
            extract_message(r#"{"message":"nice message","error":"code"}"#),
            "nice message"
        );
        assert_eq!(extract_message(r#"{"error":"just a code"}"#), "just a code");
        assert_eq!(extract_message(""), "(empty response)");
        assert_eq!(extract_message("plain text failure"), "plain text failure");
    }

    #[test]
    fn overlong_plain_bodies_are_truncated() {
        let body = "x".repeat(5_000);
        assert_eq!(extract_message(&body).len(), 200);
    }

    #[test]
    fn enroll_request_display_hides_the_token() {
        let req = EnrollRequest {
            enrollment_token: "enroll_supersecret".into(),
            device_id: "dev_1".into(),
            hostname: "sensor-host".into(),
            name: "sensor".into(),
            site: None,
            os_version: "Debian 12".into(),
            arch: "x86_64".into(),
            sensor_version: "0.1.0".into(),
            mode: "balanced".into(),
            interfaces: vec!["eth0".into()],
        };
        let rendered = req.to_string();
        assert!(
            !rendered.contains("enroll_supersecret"),
            "token leaked: {rendered}"
        );
        assert!(rendered.contains("sensor-host"));
    }

    #[test]
    fn enroll_response_becomes_a_redacted_identity() {
        let response = EnrollResponse {
            sensor_id: "sensor_1".into(),
            sensor_secret: "secret_abc".into(),
            project_id: "p-1".into(),
            api_url: Some("https://api.example.com".into()),
            ingest_url: None,
        };
        let identity = response.into_identity("dev_1".into());

        assert_eq!(identity.sensor_id, "sensor_1");
        assert_eq!(identity.secret.expose(), "secret_abc");
        assert!(!format!("{identity:?}").contains("secret_abc"));
    }

    #[test]
    fn client_normalises_trailing_slashes() {
        let client = BackendClient::new(
            "https://api.example.com/",
            "https://ingest.example.com//",
            Duration::from_secs(5),
        )
        .expect("client");
        assert_eq!(client.api_url(), "https://api.example.com");
        assert_eq!(client.ingest_url(), "https://ingest.example.com");
    }
}
