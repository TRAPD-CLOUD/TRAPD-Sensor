//! Vom Dashboard gesteuerte Konfiguration.
//!
//! Das Backend darf den Sensor im laufenden Betrieb umstellen — Discovery-Module
//! an- und abschalten, Ziele und Ports setzen, SNMP-Communities hinterlegen,
//! Auto-Update umlegen. Zwei Dinge darf es ausdrücklich **nicht**:
//!
//! * **den Betriebsmodus anheben** ([`SensorMode`](trapd_sensor_core::SensorMode)),
//! * **die aktive Erkennung quittieren** (`active.acknowledged`).
//!
//! Beides bleibt in der Datei auf dem Sensor-Host. Damit ist der Modus eine
//! lokale Obergrenze, innerhalb derer das Dashboard frei schalten kann: ein
//! übernommenes Backend kann einen als `passive_only` aufgesetzten Sensor nicht
//! in einen Scanner verwandeln. Der Preis ist eine bewusste Einmal-Handlung auf
//! dem Host, bevor aktive Erkennung überhaupt möglich wird — die Zustimmung zum
//! Senden von Paketen gehört dorthin, wo die Pakete entstehen.
//!
//! Alle Felder sind optional: das Backend schickt nur, was es ändern will, und
//! ein unbekanntes Feld einer neueren Backend-Version wird ignoriert statt den
//! Abruf scheitern zu lassen.

use serde::{Deserialize, Serialize};
use trapd_sensor_core::config::SensorConfig;

/// Antwort von `GET /api/v1/sensors/{id}/config`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoteConfig {
    /// Monoton steigend. Der Sensor wendet nur neuere Versionen an — so kostet
    /// ein unveränderter Poll nichts und eine veraltete Antwort aus einem Cache
    /// kann keine Einstellung zurückdrehen.
    pub config_version: u64,
    /// Vom Dashboard abgeschaltet oder unter Quarantäne. `false` = der Sensor
    /// stellt Erfassung und Versand ein.
    pub enabled: Option<bool>,
    pub passive: Option<PassiveOverride>,
    pub active: Option<ActiveOverride>,
    pub privacy: Option<PrivacyOverride>,
    pub update: Option<UpdateOverride>,
    pub capture: Option<CaptureOverride>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PassiveOverride {
    pub arp: Option<bool>,
    pub dhcp: Option<bool>,
    pub mdns: Option<bool>,
    pub ssdp: Option<bool>,
    pub dns: Option<bool>,
    pub flows: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActiveOverride {
    pub enabled: Option<bool>,
    pub targets: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    pub rate_limit_per_sec: Option<u32>,
    pub icmp: Option<bool>,
    pub tcp_connect: Option<bool>,
    pub ports: Option<Vec<u16>>,
    pub banner_grab: Option<bool>,
    pub sweep_interval_secs: Option<u64>,
    pub snmp_enabled: Option<bool>,
    /// SNMP-Community-Strings. Werden nie geloggt und nie geraten — was hier
    /// nicht steht, wird nicht ausprobiert.
    pub snmp_communities: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyOverride {
    pub dns_observation: Option<bool>,
    pub dns_exclude_domains: Option<Vec<String>>,
    pub exclude_clients: Option<Vec<String>>,
    pub store_dns_answers: Option<bool>,
    pub hash_dns_names: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateOverride {
    pub auto_update: Option<bool>,
    pub channel: Option<String>,
    pub check_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureOverride {
    pub interfaces: Option<Vec<String>>,
    pub flow_window_secs: Option<u64>,
    pub max_tracked_flows: Option<usize>,
}

/// Was das Anwenden einer Remote-Config bewirkt hat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// Wurde überhaupt etwas übernommen? (`false` bei veralteter Version.)
    pub applied: bool,
    /// Soll der Sensor laufen?
    pub enabled: bool,
}

impl RemoteConfig {
    /// Übernimmt die Remote-Einstellungen in die laufende Konfiguration.
    ///
    /// `current_version` ist die zuletzt angewandte Version; ältere oder gleiche
    /// Antworten werden verworfen.
    pub fn apply(&self, cfg: &mut SensorConfig, current_version: u64) -> ApplyOutcome {
        let enabled = self.enabled.unwrap_or(true);

        // Eine Abschaltung gilt sofort, unabhängig von der Versionszählung: sie
        // ist eine Notbremse und darf nicht daran scheitern, dass jemand die
        // Version nicht hochgezählt hat.
        if self.config_version <= current_version {
            return ApplyOutcome {
                applied: false,
                enabled,
            };
        }

        if let Some(p) = &self.passive {
            apply_opt(&mut cfg.passive.arp, p.arp);
            apply_opt(&mut cfg.passive.dhcp, p.dhcp);
            apply_opt(&mut cfg.passive.mdns, p.mdns);
            apply_opt(&mut cfg.passive.ssdp, p.ssdp);
            apply_opt(&mut cfg.passive.dns, p.dns);
            apply_opt(&mut cfg.passive.flows, p.flows);
        }

        if let Some(a) = &self.active {
            apply_opt(&mut cfg.active.enabled, a.enabled);
            apply_opt(&mut cfg.active.targets, a.targets.clone());
            apply_opt(&mut cfg.active.exclude, a.exclude.clone());
            apply_opt(&mut cfg.active.rate_limit_per_sec, a.rate_limit_per_sec);
            apply_opt(&mut cfg.active.icmp, a.icmp);
            apply_opt(&mut cfg.active.tcp_connect, a.tcp_connect);
            apply_opt(&mut cfg.active.ports, a.ports.clone());
            apply_opt(&mut cfg.active.banner_grab, a.banner_grab);
            apply_opt(&mut cfg.active.sweep_interval_secs, a.sweep_interval_secs);
            apply_opt(&mut cfg.active.snmp.enabled, a.snmp_enabled);
            apply_opt(&mut cfg.active.snmp.communities, a.snmp_communities.clone());
            // `acknowledged` fehlt hier absichtlich — siehe Modul-Doku.
        }

        if let Some(p) = &self.privacy {
            apply_opt(&mut cfg.privacy.dns_observation, p.dns_observation);
            apply_opt(
                &mut cfg.privacy.dns_exclude_domains,
                p.dns_exclude_domains.clone(),
            );
            apply_opt(&mut cfg.privacy.exclude_clients, p.exclude_clients.clone());
            apply_opt(&mut cfg.privacy.store_dns_answers, p.store_dns_answers);
            apply_opt(&mut cfg.privacy.hash_dns_names, p.hash_dns_names);
        }

        if let Some(u) = &self.update {
            apply_opt(&mut cfg.update.auto_update, u.auto_update);
            apply_opt(&mut cfg.update.channel, u.channel.clone());
            apply_opt(&mut cfg.update.check_interval_secs, u.check_interval_secs);
        }

        if let Some(c) = &self.capture {
            apply_opt(&mut cfg.capture.interfaces, c.interfaces.clone());
            apply_opt(&mut cfg.capture.flow_window_secs, c.flow_window_secs);
            apply_opt(&mut cfg.capture.max_tracked_flows, c.max_tracked_flows);
        }

        ApplyOutcome {
            applied: true,
            enabled,
        }
    }
}

fn apply_opt<T>(target: &mut T, value: Option<T>) {
    if let Some(v) = value {
        *target = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trapd_sensor_core::config::SensorMode;

    #[test]
    fn overrides_are_applied_and_unset_fields_left_alone() {
        let mut cfg = SensorConfig::default();
        cfg.passive.mdns = true;
        cfg.passive.ssdp = true;

        let remote = RemoteConfig {
            config_version: 1,
            passive: Some(PassiveOverride {
                mdns: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let outcome = remote.apply(&mut cfg, 0);
        assert!(outcome.applied);
        assert!(!cfg.passive.mdns, "explicit override applies");
        assert!(cfg.passive.ssdp, "untouched field keeps its value");
    }

    #[test]
    fn auto_update_is_remotely_switchable() {
        let mut cfg = SensorConfig::default();
        assert!(!cfg.update.auto_update, "auto update is off by default");

        let remote = RemoteConfig {
            config_version: 1,
            update: Some(UpdateOverride {
                auto_update: Some(true),
                channel: Some("beta".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        remote.apply(&mut cfg, 0);

        assert!(cfg.update.auto_update);
        assert_eq!(cfg.update.channel, "beta");
    }

    #[test]
    fn snmp_settings_are_remotely_configurable() {
        let mut cfg = SensorConfig::default();
        let remote = RemoteConfig {
            config_version: 1,
            active: Some(ActiveOverride {
                snmp_enabled: Some(true),
                snmp_communities: Some(vec!["ro-community".into()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        remote.apply(&mut cfg, 0);

        assert!(cfg.active.snmp.enabled);
        assert_eq!(
            cfg.active.snmp.communities,
            vec!["ro-community".to_string()]
        );
    }

    /// Der Kern der Sicherheitszusage: ein übernommenes Backend darf einen
    /// passiven Sensor nicht zum Scanner machen.
    #[test]
    fn remote_config_cannot_raise_the_operating_mode() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::PassiveOnly;

        // Ein Backend, das alles anschalten will, was es kann.
        let remote = RemoteConfig {
            config_version: 1,
            active: Some(ActiveOverride {
                enabled: Some(true),
                targets: Some(vec!["0.0.0.0/0".into()]),
                ports: Some(vec![22, 3389]),
                banner_grab: Some(true),
                snmp_enabled: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        remote.apply(&mut cfg, 0);

        assert_eq!(cfg.sensor.mode, SensorMode::PassiveOnly);
        let policy = cfg.effective_policy();
        assert!(
            policy.active.is_none(),
            "passive_only must stay passive no matter what the backend asks for"
        );
    }

    #[test]
    fn remote_config_cannot_acknowledge_active_discovery() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Balanced;
        assert!(!cfg.active.acknowledged);

        let remote = RemoteConfig {
            config_version: 1,
            active: Some(ActiveOverride {
                enabled: Some(true),
                targets: Some(vec!["192.168.1.0/24".into()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        remote.apply(&mut cfg, 0);

        assert!(
            !cfg.active.acknowledged,
            "acknowledgement stays a local, on-host decision"
        );
        assert!(cfg.effective_policy().active.is_none());
    }

    /// Sobald der Host quittiert hat, steuert das Dashboard innerhalb des Modus.
    #[test]
    fn with_local_acknowledgement_the_dashboard_drives_active_discovery() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Balanced;
        cfg.active.acknowledged = true;

        let remote = RemoteConfig {
            config_version: 1,
            active: Some(ActiveOverride {
                enabled: Some(true),
                targets: Some(vec!["192.168.1.0/24".into()]),
                ports: Some(vec![22, 443]),
                ..Default::default()
            }),
            ..Default::default()
        };
        remote.apply(&mut cfg, 0);

        let active = cfg
            .effective_policy()
            .active
            .expect("dashboard-enabled discovery");
        assert_eq!(active.ports, vec![22, 443]);
    }

    #[test]
    fn stale_config_versions_are_ignored() {
        let mut cfg = SensorConfig::default();
        cfg.passive.mdns = true;

        let remote = RemoteConfig {
            config_version: 5,
            passive: Some(PassiveOverride {
                mdns: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let outcome = remote.apply(&mut cfg, 7);
        assert!(!outcome.applied);
        assert!(
            cfg.passive.mdns,
            "an older config must not roll settings back"
        );
    }

    #[test]
    fn disable_is_reported_even_for_a_stale_version() {
        let mut cfg = SensorConfig::default();
        let remote = RemoteConfig {
            config_version: 1,
            enabled: Some(false),
            ..Default::default()
        };
        let outcome = remote.apply(&mut cfg, 99);
        assert!(!outcome.applied);
        assert!(
            !outcome.enabled,
            "the kill switch must not depend on versioning"
        );
    }

    #[test]
    fn unknown_fields_from_a_newer_backend_are_ignored() {
        let json = r#"{
            "config_version": 3,
            "enabled": true,
            "some_future_feature": {"a": 1},
            "passive": {"dns": false, "future_toggle": true}
        }"#;
        let remote: RemoteConfig = serde_json::from_str(json).expect("tolerant parsing");
        assert_eq!(remote.config_version, 3);

        let mut cfg = SensorConfig::default();
        remote.apply(&mut cfg, 0);
        assert!(!cfg.passive.dns);
    }

    #[test]
    fn empty_response_changes_nothing_but_stays_enabled() {
        let mut cfg = SensorConfig::default();
        let before = cfg.clone();
        let remote: RemoteConfig = serde_json::from_str("{}").expect("parse");

        let outcome = remote.apply(&mut cfg, 0);
        assert!(!outcome.applied, "version 0 is never newer than 0");
        assert!(outcome.enabled);
        assert_eq!(cfg.passive.arp, before.passive.arp);
    }
}
