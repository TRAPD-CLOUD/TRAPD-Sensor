//! Vendor-isolated FRITZ!OS live-capture client.
//!
//! FRITZ!OS' capture CGI is not a stable public API.  Nothing in this module is
//! shared with backend transport: redirects and content compression are
//! disabled, response sizes are bounded, and credentials are represented by a
//! redacted, zeroizing type.

mod auth;
mod client;
mod pcap;
mod secrets;

pub use auth::{challenge_response, AuthError, ChallengeKind};
pub use client::{FritzBoxClient, FritzBoxError, FritzBoxSession};
pub use pcap::{Endianness, PcapError, PcapPacket, PcapStreamDecoder};
pub use secrets::{Credentials, SecretError, SecretStore};

/// A capture source returned by FRITZ!OS discovery. IDs are opaque and must be
/// sent back unchanged; model-specific IDs are never guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureInterface {
    pub id: String,
    pub display_name: String,
    pub category: String,
    pub available: bool,
}

/// Observable lifecycle states used by daemon status and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderState {
    Disabled,
    Authenticating,
    DiscoveringInterfaces,
    Connecting,
    Capturing,
    Degraded,
    Reconnecting,
}

/// Bounded exponential retry schedule. Authentication failures use the slower
/// half to avoid hammering a router after a password change.
pub fn retry_delay(attempt: u32, authentication_failure: bool) -> std::time::Duration {
    const SECONDS: [u64; 6] = [1, 2, 5, 10, 30, 60];
    let floor = if authentication_failure { 3 } else { 0 };
    std::time::Duration::from_secs(SECONDS[(attempt as usize + floor).min(5)])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_is_bounded_and_auth_is_slower() {
        assert_eq!(retry_delay(0, false).as_secs(), 1);
        assert_eq!(retry_delay(99, false).as_secs(), 60);
        assert_eq!(retry_delay(0, true).as_secs(), 10);
    }
}
