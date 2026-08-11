//! Welche Netzwerk-Sichtbarkeit dieser Sensor tatsächlich hat.
//!
//! Der [`VisibilityReport`] beantwortet die Frage, die sonst erst nach Wochen
//! Betrieb auffällt: *"Warum sehe ich keine DNS-Abfragen?"* — und zwar
//! **hergeleitet**, nicht behauptet. Jede Zeile entsteht aus drei Fakten, die
//! ohnehin schon in der Konfiguration stehen:
//!
//! 1. dem Beobachtungspunkt ([`Vantage`]) — ein geswitchtes LAN liefert an
//!    einen normalen Port nun einmal nur Broadcast, Multicast und den eigenen
//!    Verkehr,
//! 2. der bereits durch den Betriebsmodus gefilterten
//!    [`EffectivePolicy`](crate::config::EffectivePolicy) — ein abgeschaltetes
//!    Modul sieht nichts, egal wie gut der Anschluss ist,
//! 3. `capture.promiscuous` — ohne den Modus verwirft die NIC an einem
//!    Mirror-Port alles, was nicht an sie adressiert ist.
//!
//! Damit ist der Bericht eine reine Funktion über die Konfiguration: gut
//! testbar, und ohne die Möglichkeit, versehentlich mehr zu versprechen, als
//! der Sensor an dieser Stelle im Netz einlösen kann.
//!
//! Was der Bericht **nicht** tut: er misst nicht. Ob auf dem gewählten
//! Interface tatsächlich Pakete ankommen, beantwortet
//! `trapd-sensorctl status`/`diagnose`; hier steht, was an diesem Anschluss
//! überhaupt möglich ist.

use serde::{Deserialize, Serialize};

use crate::config::SensorConfig;
use crate::deployment::{Edition, NetworkProfile, Vantage};

/// Schema-Version der JSON-Ausgabe. Wie beim Diagnose-Bericht: Automation
/// muss erkennen können, wann sich die Struktur ändert.
pub const VISIBILITY_SCHEMA_VERSION: u32 = 1;

/// Wie gut ist eine Fähigkeit an diesem Anschluss verfügbar?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VisibilityLevel {
    /// Nicht verfügbar.
    None,
    /// Teilweise — es gibt Daten, aber mit einer benannten Lücke.
    Partial,
    /// Vollständig, soweit der Sensor diese Aussage überhaupt treffen kann.
    Full,
}

impl VisibilityLevel {
    /// Zeichen für die Textausgabe: `✓` / `△` / `✗`.
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Full => "✓",
            Self::Partial => "△",
            Self::None => "✗",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::None => "none",
        }
    }
}

/// Eine Zeile des Berichts.
///
/// Nur `Serialize`: der Bericht wird ausgegeben, nie eingelesen — `id` und
/// `label` bleiben dadurch `&'static str` statt allozierter Kopien.
#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    /// Stabiler Bezeichner für Automation (`asset_discovery`, `dns`, …).
    pub id: &'static str,
    /// Beschriftung für die Textausgabe.
    pub label: &'static str,
    pub level: VisibilityLevel,
    /// Warum dieser Wert — der wichtigste Teil der Zeile. Ein `✗` ohne Grund
    /// ist eine Beschwerde, kein Befund.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VisibilityReport {
    pub schema_version: u32,
    pub edition: Edition,
    pub profile: NetworkProfile,
    pub vantage: Vantage,
    /// `false`, solange das Setup nie gelaufen ist — dann sind die Werte
    /// unten die konservativen Vorgaben, keine Feststellungen.
    pub configured: bool,
    pub capabilities: Vec<Capability>,
    /// Hinweise, die keiner einzelnen Zeile gehören (Bauartgrenzen des
    /// Sensors, Eigenheiten der Plattform, nächste Schritte).
    pub notes: Vec<String>,
}

impl VisibilityReport {
    pub fn derive(config: &SensorConfig) -> Self {
        let deployment = &config.deployment;
        let policy = config.effective_policy();
        let vantage = deployment.vantage;
        let profile = deployment.profile;
        let promiscuous = config.capture.promiscuous;

        // Ohne Promiscuous liefert ein Spiegel-Anschluss nichts, was ein
        // normaler LAN-Port nicht auch liefern würde. Der Bericht rechnet
        // deshalb mit dem *wirksamen* Beobachtungspunkt, nicht mit dem
        // gewünschten — sonst stünde hier "volle Sicht" für eine Konfiguration,
        // die faktisch blind ist.
        let effective_vantage = if vantage.requires_promiscuous() && !promiscuous {
            Vantage::LanHost
        } else {
            vantage
        };
        let all_traffic = effective_vantage.sees_all_segment_traffic();
        let routed_traffic = effective_vantage.sees_routed_traffic();

        let passive = &policy.passive;
        // ARP, DHCP, mDNS und SSDP sind Broadcast bzw. Multicast: sie erreichen
        // jeden Port des Segments, unabhängig vom Beobachtungspunkt. Genau
        // darauf beruht die Zusage, dass ein Homelab ohne Managed Switch
        // funktioniert.
        let broadcast_sources = [passive.arp, passive.dhcp, passive.mdns, passive.ssdp]
            .iter()
            .filter(|on| **on)
            .count();
        let fingerprint_sources = [passive.dhcp, passive.mdns, passive.ssdp]
            .iter()
            .filter(|on| **on)
            .count();
        let active = policy.active.is_some();

        let mut capabilities = Vec::new();

        // --- Asset Discovery ------------------------------------------------
        capabilities.push(match (broadcast_sources, all_traffic, active) {
            (0, false, false) => Capability {
                id: "asset_discovery",
                label: "Asset Discovery",
                level: VisibilityLevel::None,
                reason: "every passive discovery module is disabled and active discovery is off"
                    .into(),
            },
            (0, _, _) => Capability {
                id: "asset_discovery",
                label: "Asset Discovery",
                level: VisibilityLevel::Partial,
                reason: "the discovery modules are disabled; devices are only inferred from \
                         observed traffic and active probes"
                    .into(),
            },
            _ => Capability {
                id: "asset_discovery",
                label: "Asset Discovery",
                level: VisibilityLevel::Full,
                reason: format!(
                    "{broadcast_sources} of 4 broadcast/multicast sources (ARP/NDP, DHCP, mDNS, \
                     SSDP) are active — these reach every port of the segment"
                ),
            },
        });

        // --- New Device Detection -------------------------------------------
        capabilities.push(if broadcast_sources > 0 {
            Capability {
                id: "new_device_detection",
                label: "New Device Detection",
                level: VisibilityLevel::Full,
                reason: "a device announces itself on the segment (ARP/NDP, DHCP) as soon as it \
                         joins the network"
                    .into(),
            }
        } else {
            Capability {
                id: "new_device_detection",
                label: "New Device Detection",
                level: VisibilityLevel::None,
                reason: "needs at least one of the ARP, DHCP, mDNS or SSDP modules".into(),
            }
        });

        // --- Device Fingerprinting ------------------------------------------
        capabilities.push(match (fingerprint_sources, passive.arp) {
            (0, false) => Capability {
                id: "device_fingerprinting",
                label: "Device Fingerprinting",
                level: VisibilityLevel::None,
                reason: "no fingerprint source is active (DHCP options, mDNS/SSDP records, MAC \
                         vendor)"
                    .into(),
            },
            (0, true) => Capability {
                id: "device_fingerprinting",
                label: "Device Fingerprinting",
                level: VisibilityLevel::Partial,
                reason: "only the MAC vendor (OUI) is available — enable DHCP, mDNS or SSDP for \
                         device type and model"
                    .into(),
            },
            (1, _) => Capability {
                id: "device_fingerprinting",
                label: "Device Fingerprinting",
                level: VisibilityLevel::Partial,
                reason: "one of DHCP/mDNS/SSDP is active; confidence stays lower than with \
                         several corroborating signals"
                    .into(),
            },
            _ => Capability {
                id: "device_fingerprinting",
                label: "Device Fingerprinting",
                level: VisibilityLevel::Full,
                reason: "DHCP options, mDNS/SSDP records and MAC vendor corroborate each other"
                    .into(),
            },
        });

        // --- Local Discovery (ARP/NDP) ---------------------------------------
        // NDP läuft unabhängig vom ARP-Schalter mit; ein abgeschaltetes ARP
        // kostet also IPv4, nicht alles.
        capabilities.push(if passive.arp {
            Capability {
                id: "local_discovery",
                label: "Local Discovery (ARP/NDP)",
                level: VisibilityLevel::Full,
                reason: "IPv4 ARP and IPv6 Neighbor Discovery are evaluated".into(),
            }
        } else {
            Capability {
                id: "local_discovery",
                label: "Local Discovery (ARP/NDP)",
                level: VisibilityLevel::Partial,
                reason: "passive.arp is disabled — only IPv6 Neighbor Discovery remains".into(),
            }
        });

        // --- Gateway Visibility ----------------------------------------------
        capabilities.push(if effective_vantage == Vantage::Gateway {
            Capability {
                id: "gateway_visibility",
                label: "Gateway Visibility",
                level: VisibilityLevel::Full,
                reason: "the sensor observes the gateway's own traffic".into(),
            }
        } else if all_traffic {
            Capability {
                id: "gateway_visibility",
                label: "Gateway Visibility",
                level: VisibilityLevel::Full,
                reason: "the mirrored segment carries the gateway's traffic".into(),
            }
        } else if broadcast_sources > 0 {
            Capability {
                id: "gateway_visibility",
                label: "Gateway Visibility",
                level: VisibilityLevel::Partial,
                reason: match &deployment.gateway_ip {
                    Some(ip) => format!(
                        "the gateway ({ip}) is discovered and fingerprinted like any other \
                         device, but its forwarded traffic is not visible from here"
                    ),
                    None => "the gateway is discovered like any other device, but its forwarded \
                             traffic is not visible from here"
                        .into(),
                },
            }
        } else {
            Capability {
                id: "gateway_visibility",
                label: "Gateway Visibility",
                level: VisibilityLevel::None,
                reason: "no discovery module can see the gateway from this vantage point".into(),
            }
        });

        // --- DNS Visibility ---------------------------------------------------
        // `passive.dns` ist der Unicast-Port 53; mDNS läuft über sein eigenes
        // Modul und ist Multicast, also überall sichtbar.
        capabilities.push(if !policy.privacy.dns_observation || !passive.dns {
            Capability {
                id: "dns_visibility",
                label: "DNS Visibility",
                level: VisibilityLevel::None,
                reason: "DNS observation is switched off in the configuration".into(),
            }
        } else if all_traffic {
            Capability {
                id: "dns_visibility",
                label: "DNS Visibility",
                level: VisibilityLevel::Full,
                reason: "every DNS query on the mirrored segment is observed".into(),
            }
        } else if routed_traffic {
            Capability {
                id: "dns_visibility",
                label: "DNS Visibility",
                level: VisibilityLevel::Partial,
                reason: "queries that pass the gateway are observed; queries answered inside the \
                         LAN or sent encrypted (DoH/DoT) are not"
                    .into(),
            }
        } else {
            Capability {
                id: "dns_visibility",
                label: "DNS Visibility",
                level: VisibilityLevel::None,
                reason: "DNS is unicast between client and resolver — a switched LAN does not \
                         deliver it to this port"
                    .into(),
            }
        });

        // --- Internet Traffic --------------------------------------------------
        capabilities.push(traffic_capability(
            "internet_traffic_visibility",
            "Internet Traffic Visibility",
            passive.flows,
            if all_traffic {
                (
                    VisibilityLevel::Full,
                    "north/south traffic of the mirrored segment is aggregated into flows".into(),
                )
            } else if routed_traffic {
                (
                    VisibilityLevel::Full,
                    "all traffic towards the internet passes this vantage point".to_string(),
                )
            } else {
                (
                    VisibilityLevel::None,
                    "other hosts' uplink traffic never reaches a normal switch port".to_string(),
                )
            },
        ));

        // --- Internal Traffic ---------------------------------------------------
        capabilities.push(traffic_capability(
            "internal_traffic_visibility",
            "Internal Traffic Visibility",
            passive.flows,
            if all_traffic {
                (
                    VisibilityLevel::Full,
                    "east/west traffic of the mirrored segment is aggregated into flows".into(),
                )
            } else if routed_traffic {
                (
                    VisibilityLevel::Partial,
                    "only traffic routed between subnets/VLANs is visible; devices talking inside \
                     one subnet never reach the gateway"
                        .into(),
                )
            } else {
                (
                    VisibilityLevel::None,
                    "a switch forwards a conversation only to the two ports involved".into(),
                )
            },
        ));

        // --- Full Packet Visibility ----------------------------------------------
        capabilities.push(if all_traffic {
            Capability {
                id: "full_packet_visibility",
                label: "Full Packet Visibility",
                level: VisibilityLevel::Full,
                reason: "every frame of the mirrored segment reaches the capture socket".into(),
            }
        } else if vantage.requires_promiscuous() && !promiscuous {
            Capability {
                id: "full_packet_visibility",
                label: "Full Packet Visibility",
                level: VisibilityLevel::None,
                reason: format!(
                    "{} is configured, but capture.promiscuous = false makes the NIC drop every \
                     frame not addressed to this host",
                    vantage.label()
                ),
            }
        } else if effective_vantage == Vantage::Gateway {
            Capability {
                id: "full_packet_visibility",
                label: "Full Packet Visibility",
                level: VisibilityLevel::Partial,
                reason: "frames that are routed pass the sensor; frames switched inside a segment \
                         do not"
                    .into(),
            }
        } else {
            Capability {
                id: "full_packet_visibility",
                label: "Full Packet Visibility",
                level: VisibilityLevel::None,
                reason: "needs a SPAN/mirror port or a network TAP".into(),
            }
        });

        capabilities.push(if config.capture.fritzbox.enabled {
            Capability { id: "fritzbox_remote_capture", label: "FRITZ!Box Remote Capture", level: VisibilityLevel::Partial,
                reason: "remote capture is configured; live provider health and selected router sources determine the traffic actually visible (source labels are not treated as capabilities)".into() }
        } else {
            Capability { id: "fritzbox_remote_capture", label: "FRITZ!Box Remote Capture", level: VisibilityLevel::None,
                reason: "the optional FRITZ!Box remote capture provider is disabled".into() }
        });

        // --- Notes ----------------------------------------------------------------
        let mut notes = Vec::new();
        if !deployment.is_configured() {
            notes.push(
                "This sensor's network environment was never recorded — the values above are the \
                 conservative defaults. Run `trapd-sensorctl setup` to record how it is attached."
                    .to_string(),
            );
        }
        if vantage.requires_promiscuous() && !promiscuous {
            notes.push(format!(
                "capture.promiscuous is false while the vantage point is {} — the sensor is \
                 effectively reduced to a plain LAN host until it is switched on (needs \
                 CAP_NET_ADMIN).",
                vantage.label()
            ));
        }
        if all_traffic {
            notes.push(
                "Traffic visibility is exactly what the switch mirrors: mirroring the uplink port \
                 shows internet traffic, mirroring a single access port shows only that device."
                    .to_string(),
            );
        }
        if !all_traffic && profile.supports_port_mirroring() == Some(false) {
            notes.push(format!(
                "{} cannot mirror ports. Full traffic visibility needs a managed switch with SPAN \
                 or a network TAP between the router and the rest of the LAN.",
                profile.label()
            ));
        }
        // Die Bauartgrenze gehört an jeden Bericht: auch bei vollem Frame-Zugang
        // liest der Sensor Header und benannte Klartextfelder — es gibt keinen
        // Payload-Pfad, den man einschalten könnte.
        notes.push(
            "TRAPD never stores packet payloads. Even with full frame access it reads headers and \
             selected clear-text fields (DHCP options, mDNS/SSDP records, DNS query names) only."
                .to_string(),
        );

        Self {
            schema_version: VISIBILITY_SCHEMA_VERSION,
            edition: deployment.edition,
            profile,
            vantage,
            configured: deployment.is_configured(),
            capabilities,
            notes,
        }
    }

    pub fn get(&self, id: &str) -> Option<&Capability> {
        self.capabilities.iter().find(|c| c.id == id)
    }

    pub fn level(&self, id: &str) -> Option<VisibilityLevel> {
        self.get(id).map(|c| c.level)
    }

    /// Kompakte Darstellung ohne Begründungen — die Zusammenfassung, die das
    /// Setup am Ende zeigt.
    pub fn render_summary(&self) -> String {
        let mut out = format!(
            "Network:\n  {} ({})\n\nTRAPD Visibility:\n\n",
            self.profile.label(),
            self.vantage.label()
        );
        for capability in &self.capabilities {
            out.push_str(&format!(
                "  {} {}\n",
                capability.level.symbol(),
                capability.label
            ));
        }
        out
    }

    /// Vollständige Darstellung mit Begründung je Zeile.
    pub fn render_text(&self) -> String {
        let mut out = format!(
            "TRAPD Network Sensor — visibility\n\n  edition:  {}\n  network:  {}\n  vantage:  {}\n",
            self.edition.label(),
            self.profile.label(),
            self.vantage.label()
        );
        out.push('\n');
        for capability in &self.capabilities {
            out.push_str(&format!(
                "  {} {:<32} {}\n",
                capability.level.symbol(),
                capability.label,
                capability.reason
            ));
        }
        if !self.notes.is_empty() {
            out.push('\n');
            for note in &self.notes {
                out.push_str(&format!("  note: {note}\n"));
            }
        }
        out
    }
}

/// Flow-abhängige Zeilen. Ohne `passive.flows` gibt es keine Verkehrsdaten,
/// egal wie gut der Anschluss ist — das ist die eine Regel, die für beide
/// Verkehrszeilen gilt, deshalb steht sie an einer Stelle.
fn traffic_capability(
    id: &'static str,
    label: &'static str,
    flows_enabled: bool,
    positional: (VisibilityLevel, String),
) -> Capability {
    let (level, reason) = positional;
    if !flows_enabled {
        return Capability {
            id,
            label,
            level: VisibilityLevel::None,
            reason: "passive.flows is disabled — the sensor does not aggregate traffic metadata"
                .into(),
        };
    }
    Capability {
        id,
        label,
        level,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SensorMode;
    use crate::deployment::NetworkProfile;

    fn config_with(profile: NetworkProfile, vantage: Vantage) -> SensorConfig {
        let mut config = SensorConfig::default();
        config.deployment.profile = profile;
        config.deployment.vantage = vantage;
        config
    }

    #[test]
    fn a_plain_home_network_still_gets_a_useful_sensor() {
        let config = config_with(NetworkProfile::Fritzbox, Vantage::LanHost);
        let report = VisibilityReport::derive(&config);

        // Das ist die Kernzusage der Homelab-Variante: ohne Managed Switch,
        // ohne Mirror-Port, trotzdem Inventar.
        assert_eq!(
            report.level("asset_discovery"),
            Some(VisibilityLevel::Full),
            "broadcast/multicast reaches every port"
        );
        assert_eq!(
            report.level("new_device_detection"),
            Some(VisibilityLevel::Full)
        );
        assert_eq!(
            report.level("device_fingerprinting"),
            Some(VisibilityLevel::Full)
        );
        assert_eq!(report.level("local_discovery"), Some(VisibilityLevel::Full));

        // Und ebenso ehrlich: was hier nicht geht.
        assert_eq!(report.level("dns_visibility"), Some(VisibilityLevel::None));
        assert_eq!(
            report.level("internet_traffic_visibility"),
            Some(VisibilityLevel::None)
        );
        assert_eq!(
            report.level("full_packet_visibility"),
            Some(VisibilityLevel::None)
        );
        assert_eq!(
            report.level("gateway_visibility"),
            Some(VisibilityLevel::Partial)
        );
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("cannot mirror ports")),
            "a FRITZ!Box user must learn why full visibility is missing: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_mirror_port_unlocks_traffic_and_dns() {
        let config = config_with(NetworkProfile::Span, Vantage::MirrorPort);
        let report = VisibilityReport::derive(&config);

        assert_eq!(report.level("dns_visibility"), Some(VisibilityLevel::Full));
        assert_eq!(
            report.level("internet_traffic_visibility"),
            Some(VisibilityLevel::Full)
        );
        assert_eq!(
            report.level("internal_traffic_visibility"),
            Some(VisibilityLevel::Full)
        );
        assert_eq!(
            report.level("full_packet_visibility"),
            Some(VisibilityLevel::Full)
        );
        assert!(
            report.notes.iter().any(|n| n.contains("never stores")),
            "the no-payload guarantee belongs on every report"
        );
    }

    /// Ein Mirror-Port ohne Promiscuous liefert faktisch nichts Zusätzliches.
    /// Der Bericht darf das nicht als volle Sicht ausweisen.
    #[test]
    fn a_mirror_port_without_promiscuous_is_reported_as_blind() {
        let mut config = config_with(NetworkProfile::Span, Vantage::MirrorPort);
        config.capture.promiscuous = false;
        let report = VisibilityReport::derive(&config);

        assert_eq!(
            report.level("full_packet_visibility"),
            Some(VisibilityLevel::None)
        );
        assert_eq!(
            report.level("internal_traffic_visibility"),
            Some(VisibilityLevel::None)
        );
        assert_eq!(report.level("dns_visibility"), Some(VisibilityLevel::None));
        assert!(report
            .notes
            .iter()
            .any(|n| n.contains("capture.promiscuous")));
        assert_eq!(
            report.vantage,
            Vantage::MirrorPort,
            "the configured vantage is still reported as configured"
        );
    }

    #[test]
    fn a_gateway_vantage_sees_routed_but_not_switched_traffic() {
        let config = config_with(NetworkProfile::Opnsense, Vantage::Gateway);
        let report = VisibilityReport::derive(&config);

        assert_eq!(
            report.level("internet_traffic_visibility"),
            Some(VisibilityLevel::Full)
        );
        assert_eq!(
            report.level("internal_traffic_visibility"),
            Some(VisibilityLevel::Partial)
        );
        assert_eq!(
            report.level("dns_visibility"),
            Some(VisibilityLevel::Partial)
        );
        assert_eq!(
            report.level("gateway_visibility"),
            Some(VisibilityLevel::Full)
        );
    }

    #[test]
    fn disabled_modules_lower_the_report_even_on_a_perfect_vantage_point() {
        let mut config = config_with(NetworkProfile::Span, Vantage::NetworkTap);
        config.passive.flows = false;
        config.privacy.dns_observation = false;
        let report = VisibilityReport::derive(&config);

        assert_eq!(report.level("dns_visibility"), Some(VisibilityLevel::None));
        assert_eq!(
            report.level("internet_traffic_visibility"),
            Some(VisibilityLevel::None)
        );
        assert_eq!(
            report
                .get("internet_traffic_visibility")
                .expect("row")
                .reason,
            "passive.flows is disabled — the sensor does not aggregate traffic metadata"
        );
        assert_eq!(
            report.level("full_packet_visibility"),
            Some(VisibilityLevel::Full),
            "the vantage point is unchanged; only the modules are off"
        );
    }

    #[test]
    fn an_unconfigured_sensor_says_so_instead_of_guessing() {
        let report = VisibilityReport::derive(&SensorConfig::default());
        assert!(!report.configured);
        assert_eq!(report.vantage, Vantage::LanHost);
        assert!(report
            .notes
            .iter()
            .any(|n| n.contains("trapd-sensorctl setup")));
    }

    #[test]
    fn passive_only_mode_does_not_change_what_the_sensor_can_see() {
        let mut config = config_with(NetworkProfile::Span, Vantage::MirrorPort);
        config.sensor.mode = SensorMode::PassiveOnly;
        let report = VisibilityReport::derive(&config);

        assert_eq!(
            report.level("asset_discovery"),
            Some(VisibilityLevel::Full),
            "passive discovery is exactly what a SPAN deployment runs on"
        );
    }

    #[test]
    fn every_capability_carries_a_reason() {
        for vantage in Vantage::ALL {
            for profile in NetworkProfile::ALL {
                let report = VisibilityReport::derive(&config_with(*profile, *vantage));
                for capability in &report.capabilities {
                    assert!(
                        !capability.reason.trim().is_empty(),
                        "{}/{} has no reason for {}",
                        profile,
                        vantage,
                        capability.id
                    );
                }
            }
        }
    }

    #[test]
    fn the_report_is_serialisable_and_versioned() {
        let report = VisibilityReport::derive(&SensorConfig::default());
        let value = serde_json::to_value(&report).expect("serialize");
        assert_eq!(value["schema_version"], VISIBILITY_SCHEMA_VERSION);
        assert_eq!(value["vantage"], "lan_host");
        assert_eq!(value["capabilities"][0]["id"], "asset_discovery");
        assert_eq!(value["capabilities"][0]["level"], "full");
    }

    #[test]
    fn the_summary_uses_the_documented_symbols() {
        let report =
            VisibilityReport::derive(&config_with(NetworkProfile::Fritzbox, Vantage::LanHost));
        let summary = report.render_summary();
        assert!(summary.contains("FRITZ!Box"));
        assert!(summary.contains("✓ Asset Discovery"));
        assert!(summary.contains("✗ Full Packet Visibility"));
    }
}
