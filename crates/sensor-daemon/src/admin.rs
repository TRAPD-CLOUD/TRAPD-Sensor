//! Der lokale Admin-Endpunkt: Health, Readiness, Prometheus-Metriken.
//!
//! Bewusst ein handgeschriebener Mini-HTTP-Server statt eines Web-Frameworks.
//! Drei Routen, nur GET, ausschließlich auf Loopback — dafür ein
//! Framework samt Abhängigkeitsbaum in einen Prozess zu ziehen, der mit
//! `CAP_NET_RAW` läuft, wäre schlecht eingekauft.
//!
//! Der Listener hört per Voreinstellung auf `127.0.0.1:9531`: Port über 1024
//! (kein `CAP_NET_BIND_SERVICE` nötig) und nicht nach außen erreichbar.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::state::SensorState;

/// Wie viele Bytes einer Anfrage überhaupt gelesen werden. Mehr braucht eine
/// GET-Zeile nicht, und mehr zu lesen wäre ein kostenloser Speicherfresser.
const MAX_REQUEST_BYTES: usize = 2048;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve(
    listen: &str,
    state: Arc<SensorState>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "admin endpoint listening");

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("admin endpoint shutting down");
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            match tokio::time::timeout(REQUEST_TIMEOUT, handle(stream, state)).await {
                                Ok(Err(e)) => tracing::debug!(error = %e, "admin request failed"),
                                Err(_) => tracing::debug!("admin request timed out"),
                                Ok(Ok(())) => {}
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "admin accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

async fn handle(mut stream: TcpStream, state: Arc<SensorState>) -> anyhow::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST_BYTES];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request_path(&request);

    let (status, content_type, body) = route(path, &state);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Zieht den Pfad aus der Request-Zeile. Alles, was nicht wie `GET <pfad>`
/// aussieht, wird zu `/` und landet damit auf der 404.
pub(crate) fn request_path(request: &str) -> &str {
    let mut parts = request.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(path)) => path.split('?').next().unwrap_or("/"),
        _ => "/",
    }
}

pub(crate) fn route(path: &str, state: &SensorState) -> (&'static str, &'static str, String) {
    match path {
        "/admin/health" => {
            let (health, reason) = state.health();
            let status = if health == crate::state::HealthState::Unhealthy {
                "503 Service Unavailable"
            } else {
                "200 OK"
            };
            (
                status,
                "text/plain",
                format!("{}: {reason}\n", health.as_str()),
            )
        }

        // Readiness: enrolled und mindestens ein Interface im Capture.
        "/admin/ready" => {
            let (ready, reason) = state.readiness();
            if ready {
                ("200 OK", "text/plain", "ok\n".to_string())
            } else {
                (
                    "503 Service Unavailable",
                    "text/plain",
                    format!("{reason}\n"),
                )
            }
        }

        "/admin/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4",
            state.render_prometheus(),
        ),

        // Menschenlesbarer Zustand — was `trapd-sensorctl status` abfragt.
        "/admin/status" => ("200 OK", "application/json", state.render_status_json()),

        _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
    }
}

/// Laufzeit seit Prozessstart.
pub struct Uptime(Instant);

impl Uptime {
    pub fn start() -> Self {
        Self(Instant::now())
    }

    pub fn secs(&self) -> u64 {
        self.0.elapsed().as_secs()
    }
}

impl Default for Uptime {
    fn default() -> Self {
        Self::start()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SensorState {
        SensorState::new("sensor_test".into(), "balanced".into())
    }

    #[test]
    fn request_line_is_parsed() {
        assert_eq!(
            request_path("GET /admin/health HTTP/1.1\r\n"),
            "/admin/health"
        );
        assert_eq!(
            request_path("GET /admin/metrics?format=x HTTP/1.1\r\n"),
            "/admin/metrics"
        );
    }

    #[test]
    fn non_get_requests_fall_through_to_not_found() {
        assert_eq!(request_path("POST /admin/health HTTP/1.1\r\n"), "/");
        assert_eq!(request_path(""), "/");
        assert_eq!(request_path("garbage"), "/");
    }

    #[test]
    fn health_reports_missing_capture_as_unhealthy() {
        let state = state();
        let (status, _, body) = route("/admin/health", &state);
        assert_eq!(status, "503 Service Unavailable");
        assert!(body.contains("unhealthy"));
    }

    #[test]
    fn readiness_reflects_actual_capture() {
        let state = state();
        let (status, _, body) = route("/admin/ready", &state);
        assert_eq!(status, "503 Service Unavailable");
        assert!(
            body.contains("interface"),
            "the reason must be actionable: {body}"
        );

        state.set_interfaces_up(1);
        let (status, _, _) = route("/admin/ready", &state);
        assert_eq!(status, "200 OK");
    }

    #[test]
    fn metrics_are_prometheus_formatted() {
        let state = state();
        state.set_interfaces_up(2);
        let (status, content_type, body) = route("/admin/metrics", &state);

        assert_eq!(status, "200 OK");
        assert!(content_type.starts_with("text/plain"));
        assert!(body.contains("# HELP trapd_sensor_interfaces_up"));
        assert!(body.contains("# TYPE trapd_sensor_interfaces_up gauge"));
        assert!(body.contains("trapd_sensor_interfaces_up 2"));
    }

    #[test]
    fn status_endpoint_returns_valid_json() {
        let state = state();
        let (status, content_type, body) = route("/admin/status", &state);

        assert_eq!(status, "200 OK");
        assert_eq!(content_type, "application/json");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(parsed["sensor_id"], "sensor_test");
        assert_eq!(parsed["mode"], "balanced");
    }

    #[test]
    fn unknown_paths_are_not_found() {
        let (status, _, _) = route("/", &state());
        assert_eq!(status, "404 Not Found");
        let (status, _, _) = route("/../../etc/passwd", &state());
        assert_eq!(status, "404 Not Found");
    }
}
