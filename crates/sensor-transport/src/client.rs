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

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use trapd_sensor_core::envelope::{IngestBatch, IngestResponse};
use trapd_sensor_core::identity::{Secret, SensorIdentity};

use crate::error::{Result, TransportError};
use crate::remote_config::RemoteConfig;

/// Optionale mTLS-Client-Identität für die Verbindung zum Backend.
///
/// Additiv: der Sensor authentifiziert sich weiterhin primär über das
/// Bearer-Secret (siehe Modul-Doku in `lib.rs`). Ist ein Client-Zertifikat
/// konfiguriert, wird es zusätzlich beim TLS-Handshake vorgezeigt — der
/// Gateway kann es prüfen, ist aber (Stand v0.1) nicht darauf angewiesen.
pub struct ClientIdentity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Baut eine [`reqwest::Identity`] aus PEM-kodiertem Zertifikat + privatem
/// Schlüssel. Von den Dateien getrennt, damit sich das Parsen ohne
/// Dateisystem testen lässt.
fn build_client_identity(cert_pem: &[u8], key_pem: &[u8]) -> Result<reqwest::Identity> {
    // `Identity::from_pem` erwartet Zertifikatskette und privaten Schlüssel
    // in einem gemeinsamen PEM-Puffer.
    let mut combined = Vec::with_capacity(cert_pem.len() + key_pem.len() + 1);
    combined.extend_from_slice(cert_pem);
    combined.push(b'\n');
    combined.extend_from_slice(key_pem);

    reqwest::Identity::from_pem(&combined)
        .map_err(|e| TransportError::Tls(format!("could not build client identity: {e}")))
}

/// Liest Zertifikat + Schlüssel von der Platte und baut daraus die Identität.
fn load_client_identity(identity: &ClientIdentity) -> Result<reqwest::Identity> {
    let cert_pem = std::fs::read(&identity.cert_path).map_err(|e| {
        TransportError::Tls(format!(
            "could not read mTLS client certificate {}: {e}",
            identity.cert_path.display()
        ))
    })?;
    let key_pem = std::fs::read(&identity.key_path).map_err(|e| {
        TransportError::Tls(format!(
            "could not read mTLS client key {}: {e}",
            identity.key_path.display()
        ))
    })?;
    build_client_identity(&cert_pem, &key_pem)
}

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
        Self::with_client_identity(api_url, ingest_url, timeout, None)
    }

    /// Wie [`Self::new`], aber mit optionalem mTLS-Client-Zertifikat.
    ///
    /// `client_identity: None` ist das Default-Verhalten und identisch zu
    /// [`Self::new`] — die Erweiterung ist additiv und ändert nichts, solange
    /// niemand `backend.mtls_client_cert_path`/`_key_path` konfiguriert.
    pub fn with_client_identity(
        api_url: &str,
        ingest_url: &str,
        timeout: Duration,
        client_identity: Option<&ClientIdentity>,
    ) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(trapd_sensor_core::user_agent())
            // Der Sensor spricht mit genau einem Backend; ein Redirect würde
            // Bearer-Token an einen fremden Host tragen.
            .redirect(reqwest::redirect::Policy::none());

        if let Some(identity) = client_identity {
            let identity = load_client_identity(identity)?;
            tracing::info!("mTLS: client identity loaded — mutual TLS enabled");
            builder = builder.identity(identity);
        }

        let http = builder
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
        // These statuses commonly describe a rolling-deploy/proxy/routing
        // condition rather than malformed event bytes. Never acknowledge the
        // WAL for them.
        404 | 405 | 408 | 409 | 425 => Some(TransportError::Routing {
            status,
            message: detail,
        }),
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

    // Self-signed test-only EC keypair (P-256, CN=trapd-sensor-test, 10y
    // validity, generated once with `openssl req -x509 -newkey ec
    // -pkeyopt ec_paramgen_curve:prime256v1 -nodes`). Never used against a
    // real backend — only exercises the local PEM-parsing/identity-building
    // path.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBjDCCATOgAwIBAgIUMGKTlDub+LbdaPD3REG9zSAXmd8wCgYIKoZIzj0EAwIw\n\
HDEaMBgGA1UEAwwRdHJhcGQtc2Vuc29yLXRlc3QwHhcNMjYwODIyMjEyOTA1WhcN\n\
MzYwODE5MjEyOTA1WjAcMRowGAYDVQQDDBF0cmFwZC1zZW5zb3ItdGVzdDBZMBMG\n\
ByqGSM49AgEGCCqGSM49AwEHA0IABODLazsHAQuDHOkPwl0GsWJ+atv3GGayXf3t\n\
coRN/CTGNP18EF1zOq/9xxwXSsLNZNFly0OYIaO89W4FxDPoNlajUzBRMB0GA1Ud\n\
DgQWBBS70S5AQQTIJipReDtR+aai79N8LzAfBgNVHSMEGDAWgBS70S5AQQTIJipR\n\
eDtR+aai79N8LzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIHX9\n\
aQu66OhVsSAuy6++RxWcVuNwn8Jcd0h6WkUt4qiSAiBUj7p+wVGziKbD8dQrqibi\n\
fbrDjzcNU793Rrs+NCr23g==\n\
-----END CERTIFICATE-----\n";

    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg55HvAIW3aEQtPyZ3\n\
YHK6cYHMmpLzKsZ1Sw2ADTrxe+ahRANCAATgy2s7BwELgxzpD8JdBrFifmrb9xhm\n\
sl397XKETfwkxjT9fBBdczqv/cccF0rCzWTRZctDmCGjvPVuBcQz6DZW\n\
-----END PRIVATE KEY-----\n";

    #[test]
    fn valid_cert_and_key_build_a_client_identity() {
        let identity = build_client_identity(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes());
        assert!(identity.is_ok(), "expected a valid identity: {identity:?}");
    }

    #[test]
    fn garbage_pem_is_a_tls_error_not_a_panic() {
        let err = build_client_identity(b"not a cert", b"not a key").unwrap_err();
        assert!(matches!(err, TransportError::Tls(_)));
    }

    #[test]
    fn missing_identity_files_are_reported_as_a_tls_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = ClientIdentity {
            cert_path: dir.path().join("missing.crt"),
            key_path: dir.path().join("missing.key"),
        };
        let err = load_client_identity(&identity).unwrap_err();
        assert!(matches!(err, TransportError::Tls(_)));
    }

    #[test]
    fn client_without_identity_behaves_like_new() {
        // Default path (no mTLS configured) must keep working exactly as
        // before — the extension is additive.
        let client = BackendClient::with_client_identity(
            "https://api.example.com",
            "https://ingest.example.com",
            Duration::from_secs(5),
            None,
        )
        .expect("client");
        assert_eq!(client.api_url(), "https://api.example.com");
    }

    #[test]
    fn client_with_a_valid_configured_identity_builds_successfully() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        std::fs::write(&cert_path, TEST_CERT_PEM).expect("write cert");
        std::fs::write(&key_path, TEST_KEY_PEM).expect("write key");

        let identity = ClientIdentity {
            cert_path,
            key_path,
        };
        let client = BackendClient::with_client_identity(
            "https://api.example.com",
            "https://ingest.example.com",
            Duration::from_secs(5),
            Some(&identity),
        );
        assert!(client.is_ok(), "expected mTLS client to build");
    }

    #[test]
    fn client_with_an_unreadable_configured_identity_fails_loudly() {
        // A configured-but-broken client cert must not silently degrade to
        // "no mTLS" — that would be an unnoticed weakening of transport
        // security. It must fail closed.
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = ClientIdentity {
            cert_path: dir.path().join("absent.crt"),
            key_path: dir.path().join("absent.key"),
        };
        let result = BackendClient::with_client_identity(
            "https://api.example.com",
            "https://ingest.example.com",
            Duration::from_secs(5),
            Some(&identity),
        );
        match result {
            Err(TransportError::Tls(_)) => {}
            _ => panic!("expected a TransportError::Tls for an unreadable client identity"),
        }
    }

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
    fn missing_or_not_yet_routed_endpoint_is_retried() {
        for status in [404, 405, 408, 409, 425] {
            let err = classify(status, "", None).expect("error");
            assert!(matches!(err, TransportError::Routing { .. }));
            assert!(err.is_retryable());
            assert!(!err.is_terminal());
        }
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
