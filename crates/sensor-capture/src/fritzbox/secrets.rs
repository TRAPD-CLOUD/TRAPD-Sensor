use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &"[redacted]")
            .field("password", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("credential store has unsafe permissions (expected 0600)")]
    UnsafePermissions,
    #[error("could not access credential store: {0}")]
    Io(#[from] std::io::Error),
    #[error("credential store is malformed")]
    Malformed,
}
pub struct SecretStore {
    path: PathBuf,
}
impl SecretStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
    pub fn save(&self, value: &Credentials) -> Result<(), SecretError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        let temporary = self.path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        // A tiny private format avoids adding secrets to SensorConfig/RemoteConfig.
        writeln!(file, "{}", escape(&value.username))?;
        writeln!(file, "{}", escape(&value.password))?;
        file.sync_all()?;
        std::fs::rename(temporary, &self.path)?;
        Ok(())
    }
    pub fn load(&self) -> Result<Credentials, SecretError> {
        let meta = std::fs::metadata(&self.path)?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(SecretError::UnsafePermissions);
        }
        let text = std::fs::read_to_string(&self.path)?;
        let mut lines = text.lines();
        let username = lines
            .next()
            .and_then(unescape)
            .ok_or(SecretError::Malformed)?;
        let password = lines
            .next()
            .and_then(unescape)
            .ok_or(SecretError::Malformed)?;
        if lines.next().is_some() || username.is_empty() {
            return Err(SecretError::Malformed);
        }
        Ok(Credentials { username, password })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}
fn escape(s: &str) -> String {
    s.bytes()
        .flat_map(|b| {
            if b == b'%' || b == b'\n' || b == b'\r' {
                format!("%{b:02X}").into_bytes()
            } else {
                vec![b]
            }
        })
        .map(char::from)
        .collect()
}
fn unescape(s: &str) -> Option<String> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).ok()?, 16).ok()?);
            i += 3
        } else {
            out.push(b[i]);
            i += 1
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_redaction() {
        let d = tempfile::tempdir().unwrap();
        let s = SecretStore::new(d.path().join("x"));
        let c = Credentials {
            username: "u".into(),
            password: "super-secret".into(),
        };
        s.save(&c).unwrap();
        assert_eq!(s.load().unwrap().password, "super-secret");
        assert!(!format!("{c:?}").contains("secret"));
        assert_eq!(
            std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
