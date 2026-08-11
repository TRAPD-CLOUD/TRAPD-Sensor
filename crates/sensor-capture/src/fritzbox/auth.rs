use md5::{Digest as _, Md5};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    Legacy,
    Pbkdf2,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("unsupported or malformed FRITZ!OS authentication challenge")]
    InvalidChallenge,
    #[error("FRITZ!Box rejected the credentials")]
    Rejected,
    #[error("FRITZ!Box returned a malformed session response")]
    MalformedResponse,
    #[error("FRITZ!Box session expired")]
    Expired,
}

/// Computes AVM's legacy or FRITZ!OS 7 PBKDF2 response. Errors never contain
/// the password or challenge response.
pub fn challenge_response(
    challenge: &str,
    password: &str,
) -> Result<(ChallengeKind, String), AuthError> {
    if challenge.starts_with("2$") {
        let fields: Vec<_> = challenge.split('$').collect();
        if fields.len() != 5 {
            return Err(AuthError::InvalidChallenge);
        }
        let iter1 = fields[1]
            .parse::<u32>()
            .ok()
            .filter(|n| (1..=10_000_000).contains(n))
            .ok_or(AuthError::InvalidChallenge)?;
        let salt1 = decode_hex(fields[2])?;
        let iter2 = fields[3]
            .parse::<u32>()
            .ok()
            .filter(|n| (1..=10_000_000).contains(n))
            .ok_or(AuthError::InvalidChallenge)?;
        let salt2 = decode_hex(fields[4])?;
        if salt1.is_empty() || salt2.is_empty() {
            return Err(AuthError::InvalidChallenge);
        }
        let mut first = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt1, iter1, &mut first);
        let mut second = [0u8; 32];
        pbkdf2_hmac::<Sha256>(&first, &salt2, iter2, &mut second);
        Ok((
            ChallengeKind::Pbkdf2,
            format!("2${}${}", fields[4], hex(&second)),
        ))
    } else {
        if challenge.is_empty() || challenge.len() > 1024 || challenge.chars().any(char::is_control)
        {
            return Err(AuthError::InvalidChallenge);
        }
        let input = format!("{challenge}-{password}");
        let utf16: Vec<u8> = input.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let digest = Md5::digest(utf16);
        Ok((
            ChallengeKind::Legacy,
            format!("{challenge}-{}", hex(&digest)),
        ))
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AuthError> {
    if value.len() % 2 != 0 || value.len() > 512 {
        return Err(AuthError::InvalidChallenge);
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| AuthError::InvalidChallenge))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_vector() {
        assert_eq!(
            challenge_response("12345678", "secret").unwrap().1,
            "12345678-e7bed1e656ae2567d7ee3c6682a6fe30"
        );
    }
    #[test]
    fn modern_is_stable() {
        let (_, value) =
            challenge_response("2$1000$0011223344556677$1000$8899aabbccddeeff", "secret").unwrap();
        assert_eq!(
            value,
            "2$8899aabbccddeeff$b588104a34879e8ebe742de4a1b811c1c405d1acd0e0bf2e2bdacd9579426021"
        );
    }
    #[test]
    fn malformed_modern_is_rejected() {
        assert_eq!(
            challenge_response("2$0$xx$1$00", "x"),
            Err(AuthError::InvalidChallenge)
        );
    }
}
