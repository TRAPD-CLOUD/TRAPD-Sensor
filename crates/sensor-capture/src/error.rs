use std::io;

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("network interface '{interface}' does not exist")]
    UnknownInterface { interface: String },

    /// Der mit Abstand häufigste Startfehler. Die Meldung nennt die konkrete
    /// Capability, damit niemand nach Dateirechten sucht.
    #[error(
        "missing {needed} to capture on '{interface}' — grant it in the systemd unit \
         (AmbientCapabilities=) or with `setcap` on the binary"
    )]
    MissingCapability {
        interface: String,
        needed: &'static str,
    },

    #[error("failed to open capture socket on '{interface}': {source}")]
    Open {
        interface: String,
        #[source]
        source: io::Error,
    },

    #[error("failed to read from '{interface}': {source}")]
    Read {
        interface: String,
        #[source]
        source: io::Error,
    },
}

pub type Result<T> = std::result::Result<T, CaptureError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_error_tells_the_operator_what_to_do() {
        let err = CaptureError::MissingCapability {
            interface: "eth0".into(),
            needed: "CAP_NET_RAW",
        };
        let msg = err.to_string();
        assert!(msg.contains("CAP_NET_RAW"));
        assert!(msg.contains("eth0"));
        assert!(msg.contains("setcap"), "the message should be actionable");
    }

    #[test]
    fn unknown_interface_names_the_interface() {
        let err = CaptureError::UnknownInterface {
            interface: "eth9".into(),
        };
        assert!(err.to_string().contains("eth9"));
    }
}
