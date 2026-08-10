//! Interface-Erkennung über `/sys/class/net`.
//!
//! Bewusst über sysfs statt über `getifaddrs`: es ist ein reiner Lesevorgang auf
//! Textdateien, braucht keine zusätzliche Abhängigkeit und lässt sich gegen ein
//! nachgebautes Verzeichnis testen — was für die Auswahllogik der interessante
//! Teil ist.

use std::path::{Path, PathBuf};

/// Ein gefundenes Netzwerk-Interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    /// Inhalt von `operstate` (`up`, `down`, `unknown`, …).
    pub operstate: String,
    /// `true` für Loopback (Flag `IFF_LOOPBACK`).
    pub is_loopback: bool,
    /// MAC-Adresse, falls vorhanden.
    pub mac: Option<String>,
}

impl Interface {
    /// Taugt das Interface zum Mithören?
    ///
    /// `unknown` gilt als brauchbar: TAP-Devices und manche virtuellen
    /// Interfaces melden nie etwas anderes, tragen aber Verkehr — genau die
    /// Sorte Interface, an der ein Sensor in einer VM hängt.
    pub fn is_capturable(&self) -> bool {
        !self.is_loopback && matches!(self.operstate.as_str(), "up" | "unknown")
    }
}

const SYS_CLASS_NET: &str = "/sys/class/net";

/// `IFF_LOOPBACK` aus `linux/if.h`.
const IFF_LOOPBACK: u64 = 0x8;

/// Listet alle Interfaces des Systems.
pub fn list_interfaces() -> Vec<Interface> {
    list_interfaces_in(Path::new(SYS_CLASS_NET))
}

/// Wählt die Interfaces aus, auf denen der Sensor lauschen soll.
///
/// Ist `configured` nicht leer, gilt genau diese Liste (auch wenn ein Interface
/// gerade `down` ist — der Betreiber weiß, was er will, und ein Link kann
/// später kommen). Sonst werden alle brauchbaren Interfaces genommen.
pub fn select_interfaces(configured: &[String]) -> Vec<String> {
    select_interfaces_in(Path::new(SYS_CLASS_NET), configured)
}

pub(crate) fn select_interfaces_in(root: &Path, configured: &[String]) -> Vec<String> {
    if !configured.is_empty() {
        return configured.to_vec();
    }
    let mut names: Vec<String> = list_interfaces_in(root)
        .into_iter()
        .filter(Interface::is_capturable)
        .map(|i| i.name)
        .collect();
    names.sort();
    names
}

pub(crate) fn list_interfaces_in(root: &Path) -> Vec<Interface> {
    let Ok(entries) = std::fs::read_dir(root) else {
        tracing::warn!(path = %root.display(), "cannot enumerate network interfaces");
        return Vec::new();
    };

    let mut out: Vec<Interface> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.is_empty() {
                return None;
            }
            let dir = entry.path();
            Some(Interface {
                operstate: read_trimmed(&dir.join("operstate")).unwrap_or_else(|| "unknown".into()),
                is_loopback: read_flags(&dir.join("flags"))
                    .map(|f| f & IFF_LOOPBACK != 0)
                    .unwrap_or(name == "lo"),
                mac: read_trimmed(&dir.join("address")).filter(|m| m != "00:00:00:00:00:00"),
                name,
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn read_trimmed(path: &PathBuf) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `flags` steht als Hex-Zahl mit `0x`-Präfix in sysfs.
fn read_flags(path: &PathBuf) -> Option<u64> {
    let raw = read_trimmed(path)?;
    let digits = raw.strip_prefix("0x").unwrap_or(&raw);
    u64::from_str_radix(digits, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baut ein sysfs-artiges Verzeichnis nach.
    fn fake_sysfs(interfaces: &[(&str, &str, u64, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, operstate, flags, mac) in interfaces {
            let iface = dir.path().join(name);
            std::fs::create_dir_all(&iface).expect("mkdir");
            std::fs::write(iface.join("operstate"), operstate).expect("write");
            std::fs::write(iface.join("flags"), format!("0x{flags:x}")).expect("write");
            std::fs::write(iface.join("address"), mac).expect("write");
        }
        dir
    }

    #[test]
    fn interfaces_are_listed_with_their_state() {
        let dir = fake_sysfs(&[
            ("eth0", "up", 0x1003, "aa:bb:cc:dd:ee:ff"),
            ("lo", "unknown", 0x9, "00:00:00:00:00:00"),
        ]);
        let found = list_interfaces_in(dir.path());

        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "eth0");
        assert_eq!(found[0].operstate, "up");
        assert!(!found[0].is_loopback);
        assert_eq!(found[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));

        assert_eq!(found[1].name, "lo");
        assert!(found[1].is_loopback);
        assert_eq!(found[1].mac, None, "the all-zero MAC is not a MAC");
    }

    #[test]
    fn loopback_and_down_interfaces_are_not_captured() {
        let lo = Interface {
            name: "lo".into(),
            operstate: "up".into(),
            is_loopback: true,
            mac: None,
        };
        assert!(!lo.is_capturable(), "loopback carries no network traffic");

        let down = Interface {
            name: "eth1".into(),
            operstate: "down".into(),
            is_loopback: false,
            mac: None,
        };
        assert!(!down.is_capturable());
    }

    #[test]
    fn unknown_operstate_still_counts_as_capturable() {
        let tap = Interface {
            name: "tap0".into(),
            operstate: "unknown".into(),
            is_loopback: false,
            mac: None,
        };
        assert!(
            tap.is_capturable(),
            "tap/veth devices report unknown but do carry traffic"
        );
    }

    #[test]
    fn auto_detection_picks_usable_interfaces_only() {
        let dir = fake_sysfs(&[
            ("eth0", "up", 0x1003, "aa:bb:cc:dd:ee:01"),
            ("eth1", "down", 0x1002, "aa:bb:cc:dd:ee:02"),
            ("lo", "unknown", 0x9, "00:00:00:00:00:00"),
            ("tap0", "unknown", 0x1003, "aa:bb:cc:dd:ee:03"),
        ]);
        let selected = select_interfaces_in(dir.path(), &[]);
        assert_eq!(selected, vec!["eth0".to_string(), "tap0".to_string()]);
    }

    #[test]
    fn explicit_configuration_wins_over_auto_detection() {
        let dir = fake_sysfs(&[("eth0", "up", 0x1003, "aa:bb:cc:dd:ee:01")]);
        let configured = vec!["eth9".to_string()];
        assert_eq!(
            select_interfaces_in(dir.path(), &configured),
            configured,
            "a configured interface is used even if it is not up yet"
        );
    }

    #[test]
    fn missing_sysfs_yields_no_interfaces_instead_of_panicking() {
        let missing = Path::new("/definitely/not/here");
        assert!(list_interfaces_in(missing).is_empty());
        assert!(select_interfaces_in(missing, &[]).is_empty());
    }

    #[test]
    fn interface_without_flags_falls_back_to_the_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let iface = dir.path().join("lo");
        std::fs::create_dir_all(&iface).expect("mkdir");
        std::fs::write(iface.join("operstate"), "unknown").expect("write");

        let found = list_interfaces_in(dir.path());
        assert!(
            found[0].is_loopback,
            "name-based fallback for missing flags"
        );
    }
}
