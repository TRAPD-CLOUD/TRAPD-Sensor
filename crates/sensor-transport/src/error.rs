//! Fehlerklassifikation des Transports.
//!
//! Die Einteilung ist bewusst nach *Handlungsfolge* geschnitten, nicht nach
//! HTTP-Status: der Aufrufer muss aus dem Fehlertyp allein ablesen können, ob
//! er es erneut versuchen, warten oder sich abschalten soll.

use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Netz weg, DNS kaputt, TLS-Handshake gescheitert. Erneut versuchen.
    #[error("network error: {0}")]
    Network(String),

    /// 5xx. Erneut versuchen — das Backend hat ein Problem, nicht wir.
    #[error("backend error {status}: {message}")]
    Server { status: u16, message: String },

    /// 429. Erneut versuchen, aber frühestens nach `retry_after`.
    #[error("rate limited, retry after {retry_after:?}")]
    RateLimited { retry_after: Option<Duration> },

    /// Routing/proxy mismatch (404/405/408/409/425). The same payload can
    /// succeed after a rollout or failover, so the WAL must retain it.
    #[error("backend route temporarily unavailable ({status}): {message}")]
    Routing { status: u16, message: String },

    /// 401/403. Das Secret gilt nicht mehr. Weiter zu versuchen ist zwecklos
    /// und würde nur Last erzeugen — der Sensor meldet das und hält an.
    #[error("authentication rejected: {0}")]
    Unauthorized(String),

    /// 410 oder ein explizites Quarantäne-Signal. Der Sensor wurde widerrufen
    /// und muss aufhören zu senden — fail-closed, nicht fail-open.
    #[error("sensor has been revoked or quarantined: {0}")]
    Revoked(String),

    /// 4xx auf einen Batch: die Nutzlast ist fehlerhaft. Ein Retry würde sie
    /// nicht besser machen, also wird der Batch verworfen statt endlos
    /// wiederholt.
    #[error("backend rejected the payload ({status}): {message}")]
    BadRequest { status: u16, message: String },

    #[error("failed to encode request: {0}")]
    Encode(#[from] serde_json::Error),

    #[error("enrollment failed: {0}")]
    Enrollment(String),
}

impl TransportError {
    /// Lohnt ein erneuter Versuch mit denselben Daten?
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Network(_)
                | Self::Server { .. }
                | Self::RateLimited { .. }
                | Self::Routing { .. }
        )
    }

    /// Ist der Sensor dauerhaft abgemeldet? Dann hilft kein Warten.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Unauthorized(_) | Self::Revoked(_))
    }

    /// Vom Server vorgegebene Wartezeit, falls vorhanden.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => *retry_after,
            _ => None,
        }
    }

    /// Kurzer, stabiler Bezeichner für Metriken und Statusmeldungen.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Network(_) => "network",
            Self::Server { .. } => "server",
            Self::RateLimited { .. } => "rate_limited",
            Self::Routing { .. } => "routing",
            Self::Unauthorized(_) => "unauthorized",
            Self::Revoked(_) => "revoked",
            Self::BadRequest { .. } => "bad_request",
            Self::Encode(_) => "encode",
            Self::Enrollment(_) => "enrollment",
        }
    }
}

impl From<reqwest::Error> for TransportError {
    fn from(e: reqwest::Error) -> Self {
        Self::Network(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_failures_are_retryable() {
        assert!(TransportError::Network("timeout".into()).is_retryable());
        assert!(TransportError::Server {
            status: 503,
            message: "unavailable".into()
        }
        .is_retryable());
        assert!(TransportError::RateLimited { retry_after: None }.is_retryable());
    }

    #[test]
    fn credential_failures_stop_the_sensor_instead_of_looping() {
        let unauthorized = TransportError::Unauthorized("bad token".into());
        assert!(!unauthorized.is_retryable());
        assert!(unauthorized.is_terminal());

        let revoked = TransportError::Revoked("quarantined".into());
        assert!(!revoked.is_retryable());
        assert!(revoked.is_terminal());
    }

    #[test]
    fn malformed_payloads_are_neither_retried_nor_terminal() {
        let bad = TransportError::BadRequest {
            status: 400,
            message: "invalid envelope".into(),
        };
        assert!(!bad.is_retryable(), "retrying will not fix the payload");
        assert!(!bad.is_terminal(), "the sensor itself is still healthy");
    }

    #[test]
    fn rate_limit_carries_the_server_hint() {
        let err = TransportError::RateLimited {
            retry_after: Some(Duration::from_secs(30)),
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
        assert_eq!(err.code(), "rate_limited");
    }
}
