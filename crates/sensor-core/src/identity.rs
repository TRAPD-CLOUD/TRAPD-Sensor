//! Lokale Sensor-Identität: `sensor_id` + Bearer-Secret aus dem Enrollment.
//!
//! Zwei Dinge sind hier bewusst streng:
//!
//! 1. Das Secret liegt in [`Secret`], dessen `Debug`/`Display` nur `***`
//!    ausgeben. Damit kann ein `tracing::debug!(?identity)` das Token nicht
//!    versehentlich in ein Log schreiben — die Redaction hängt am Typ, nicht an
//!    der Disziplin des Aufrufers.
//! 2. Die Identity-Datei wird mit `0600` geschrieben und beim Laden geprüft.
//!    Zu weite Rechte sind ein Ladefehler, keine Warnung.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, SensorError};

/// Dateiname der Identity innerhalb des State-Verzeichnisses.
pub const IDENTITY_FILE: &str = "identity.json";

/// Erwartete Dateirechte (nur Besitzer lesen/schreiben).
const REQUIRED_MODE: u32 = 0o600;

/// Ein Geheimnis, das sich nicht versehentlich ausgeben lässt.
///
/// `Zeroize`/`ZeroizeOnDrop` sorgen dafür, dass der Klartext beim Fallenlassen
/// (Scope-Ende, `std::mem::drop`, Prozessende ohne Absturz) im Speicher
/// überschrieben wird, statt bis zur nächsten Wiederverwendung der Seite
/// liegen zu bleiben.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Einziger Weg an den Klartext. Der sperrige Name ist Absicht: er macht
    /// jede Verwendung im Code-Review sichtbar.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// Was das Enrollment dauerhaft hinterlässt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorIdentity {
    pub sensor_id: String,
    pub project_id: String,
    pub secret: Secret,
    /// Stabile, lokal erzeugte Geräte-ID. Überlebt ein Re-Enrollment und
    /// erlaubt dem Backend, denselben Host wiederzuerkennen.
    pub device_id: String,
    pub enrolled_at: String,
    /// Vom Backend beim Enrollment zurückgegebene URLs. Sie haben Vorrang vor
    /// der lokalen Config, damit ein Umzug der Ingest-Endpunkte zentral
    /// steuerbar bleibt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_url: Option<String>,
}

impl SensorIdentity {
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(IDENTITY_FILE)
    }

    /// Lädt die Identität und weist zu weite Dateirechte zurück.
    pub fn load(state_dir: &Path) -> Result<Self> {
        let path = Self::path(state_dir);
        if !path.exists() {
            return Err(SensorError::NotEnrolled { path });
        }

        let meta = std::fs::metadata(&path).map_err(|source| SensorError::Identity {
            path: path.clone(),
            source,
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SensorError::InsecurePermissions { path, mode });
        }

        let raw = std::fs::read_to_string(&path).map_err(|source| SensorError::Identity {
            path: path.clone(),
            source,
        })?;
        let identity: Self = serde_json::from_str(&raw)?;
        if identity.sensor_id.is_empty() || identity.secret.is_empty() {
            return Err(SensorError::Config(format!(
                "identity file {} is incomplete",
                path.display()
            )));
        }
        Ok(identity)
    }

    /// Schreibt die Identität atomar mit `0600`.
    ///
    /// Die Rechte werden auf der temporären Datei gesetzt, *bevor* sie an ihren
    /// Platz wandert — sonst gäbe es ein Fenster, in dem das Secret mit den
    /// Standardrechten der umask lesbar wäre.
    pub fn save(&self, state_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(state_dir).map_err(|source| SensorError::Identity {
            path: state_dir.to_path_buf(),
            source,
        })?;
        // Das State-Verzeichnis selbst darf ebenfalls nicht offen stehen.
        let dir_perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(state_dir, dir_perms);

        let path = Self::path(state_dir);
        let tmp = path.with_extension("json.tmp");

        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, json).map_err(|source| SensorError::Identity {
            path: tmp.clone(),
            source,
        })?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(REQUIRED_MODE)).map_err(
            |source| SensorError::Identity {
                path: tmp.clone(),
                source,
            },
        )?;
        std::fs::rename(&tmp, &path).map_err(|source| SensorError::Identity {
            path: path.clone(),
            source,
        })?;
        Ok(())
    }

    /// Löscht die Identität — für `sensorctl reset` und für den Fall, dass das
    /// Backend den Sensor widerrufen hat.
    pub fn remove(state_dir: &Path) -> Result<()> {
        let path = Self::path(state_dir);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(SensorError::Identity { path, source }),
        }
    }

    pub fn exists(state_dir: &Path) -> bool {
        Self::path(state_dir).exists()
    }
}

/// Erzeugt eine stabile Geräte-ID aus Maschinenmerkmalen.
///
/// Bevorzugt `/etc/machine-id`; existiert die nicht (minimale Container,
/// read-only Images), fällt die Funktion auf den Hostnamen plus Zufall zurück.
/// Der Rückgabewert ist gehasht, damit die Roh-`machine-id` — die anderswo als
/// Geheimnis gilt — den Host nicht verlässt.
pub fn derive_device_id() -> String {
    let seed = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let host = std::fs::read_to_string("/etc/hostname")
                .unwrap_or_default()
                .trim()
                .to_string();
            format!("{host}-{}", uuid::Uuid::new_v4())
        });

    format!("dev_{}", short_hash(&format!("trapd-sensor:{seed}")))
}

/// FNV-1a, gekürzt auf 16 Hex-Zeichen. Kein Krypto-Hash und keiner nötig: die
/// Funktion soll die `machine-id` verschleiern und stabil bleiben, nicht
/// Angriffe abwehren.
fn short_hash(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(dir: &Path) -> SensorIdentity {
        let _ = dir;
        SensorIdentity {
            sensor_id: "sensor_test".into(),
            project_id: "p-1".into(),
            secret: Secret::new("super-secret-token"),
            device_id: "dev_0123456789abcdef".into(),
            enrolled_at: "2026-01-01T00:00:00Z".into(),
            api_url: Some("https://api.example.com".into()),
            ingest_url: None,
        }
    }

    #[test]
    fn secret_zeroizes_its_contents() {
        use zeroize::Zeroize;
        let mut s = Secret::new("hunter2");
        s.zeroize();
        assert_eq!(s.expose(), "", "zeroize must scrub the secret in place");
    }

    #[test]
    fn secret_never_leaks_through_debug_or_display() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(format!("{s}"), "***");
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn identity_debug_output_hides_the_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = sample(dir.path());
        let rendered = format!("{identity:?}");
        assert!(
            !rendered.contains("super-secret-token"),
            "secret leaked: {rendered}"
        );
        assert!(rendered.contains("sensor_test"));
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = sample(dir.path());
        identity.save(dir.path()).expect("save");

        let loaded = SensorIdentity::load(dir.path()).expect("load");
        assert_eq!(loaded.sensor_id, "sensor_test");
        assert_eq!(loaded.secret.expose(), "super-secret-token");
        assert_eq!(loaded.api_url.as_deref(), Some("https://api.example.com"));
    }

    #[test]
    fn saved_identity_is_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        sample(dir.path()).save(dir.path()).expect("save");

        let meta = std::fs::metadata(SensorIdentity::path(dir.path())).expect("metadata");
        assert_eq!(meta.permissions().mode() & 0o777, REQUIRED_MODE);
    }

    #[test]
    fn loading_world_readable_identity_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        sample(dir.path()).save(dir.path()).expect("save");

        let path = SensorIdentity::path(dir.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        match SensorIdentity::load(dir.path()) {
            Err(SensorError::InsecurePermissions { mode, .. }) => assert_eq!(mode, 0o644),
            other => panic!("expected InsecurePermissions, got {other:?}"),
        }
    }

    #[test]
    fn missing_identity_reports_not_enrolled() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            SensorIdentity::load(dir.path()),
            Err(SensorError::NotEnrolled { .. })
        ));
        assert!(!SensorIdentity::exists(dir.path()));
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        SensorIdentity::remove(dir.path()).expect("remove on empty dir");
        sample(dir.path()).save(dir.path()).expect("save");
        SensorIdentity::remove(dir.path()).expect("remove");
        assert!(!SensorIdentity::exists(dir.path()));
    }

    #[test]
    fn device_id_is_stable_and_prefixed() {
        let a = derive_device_id();
        let b = derive_device_id();
        assert_eq!(a, b, "device id must be stable across calls");
        assert!(a.starts_with("dev_"));
    }

    #[test]
    fn device_id_does_not_expose_raw_machine_id() {
        if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
            let machine_id = machine_id.trim();
            if !machine_id.is_empty() {
                assert!(!derive_device_id().contains(machine_id));
            }
        }
    }
}
