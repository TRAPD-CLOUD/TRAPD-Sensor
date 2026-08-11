//! Wie und wo dieser Sensor im Netz hängt.
//!
//! Drei unabhängige Angaben, die zusammen den `[deployment]`-Abschnitt der
//! Konfiguration bilden:
//!
//! * [`Edition`] — welche Installationsvariante eingerichtet wurde. Rein
//!   organisatorisch: sie steuert die Einrichtung (geführt vs. automatisiert)
//!   und die Darstellung, **nicht** was der Daemon darf. Die Obergrenze bleibt
//!   [`SensorMode`](crate::config::SensorMode).
//! * [`NetworkProfile`] — welche Plattform das Netz verwaltet. Daraus ergeben
//!   sich die plattformspezifischen Hinweise (kann diese Plattform überhaupt
//!   spiegeln?) und die Vorschläge des Setups.
//! * [`Vantage`] — der Beobachtungspunkt: wie der Sensor an das Netz
//!   angeschlossen ist. Das ist die einzige der drei Angaben, die tatsächlich
//!   bestimmt, was der Sensor sehen *kann*, und damit die Grundlage der
//!   [`VisibilityReport`](crate::visibility::VisibilityReport).
//!
//! Absichtlich getrennt: eine FRITZ!Box bleibt eine FRITZ!Box, auch wenn
//! jemand später einen Managed Switch mit SPAN dazwischenhängt — dann ändert
//! sich der Vantage, nicht das Profil.

use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::config::Cidr;

/// Installationsvariante.
///
/// Sie ist eine Aussage über die Einrichtung, keine Berechtigung: eine
/// Enterprise-Installation darf nicht mehr als eine Homelab-Installation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Edition {
    /// Geführte Einrichtung für Heimnetze. Setzt keinen Managed Switch und
    /// keinen Mirror-Port voraus und nutzt, was in der jeweiligen Umgebung
    /// technisch möglich ist.
    Homelab,
    /// Klassisches Sensor-Deployment: SPAN/TAP, benannte Capture-Interfaces,
    /// vollständig automatisierbar. Vorgabe — eine Konfiguration ohne
    /// `[deployment]`-Abschnitt ist genau das, was es vor den Editionen gab:
    /// ein von Hand eingerichteter Sensor ohne geführtes Setup.
    #[default]
    Enterprise,
}

impl Edition {
    pub const ALL: &'static [Self] = &[Self::Homelab, Self::Enterprise];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Homelab => "homelab",
            Self::Enterprise => "enterprise",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Homelab => "Homelab",
            Self::Enterprise => "Enterprise",
        }
    }
}

impl std::fmt::Display for Edition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Edition {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        parse_token(s, Self::ALL, Edition::as_str, "edition")
    }
}

/// Die Plattform, die das Netz verwaltet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProfile {
    /// AVM FRITZ!Box (und baugleiche Consumer-Router).
    Fritzbox,
    /// Ubiquiti UniFi (Controller/Dream Machine plus UniFi-Switches).
    Unifi,
    Opnsense,
    Pfsense,
    Openwrt,
    /// Managed Switch mit SPAN-/Mirror-Port oder ein Netzwerk-TAP.
    Span,
    /// Anderer oder unbekannter Router.
    Generic,
    /// Von Hand eingerichtet. Vorgabe, und zugleich die ehrliche Antwort für
    /// jede Konfiguration, die das Setup nie durchlaufen hat: der Sensor weiß
    /// dann nicht, wie er angeschlossen ist, und behauptet es auch nicht.
    #[default]
    Manual,
}

impl NetworkProfile {
    /// Reihenfolge wie im geführten Setup — die Nummern in der Auswahl sind
    /// genau die Indizes dieser Liste.
    pub const ALL: &'static [Self] = &[
        Self::Fritzbox,
        Self::Unifi,
        Self::Opnsense,
        Self::Pfsense,
        Self::Openwrt,
        Self::Span,
        Self::Generic,
        Self::Manual,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fritzbox => "fritzbox",
            Self::Unifi => "unifi",
            Self::Opnsense => "opnsense",
            Self::Pfsense => "pfsense",
            Self::Openwrt => "openwrt",
            Self::Span => "span",
            Self::Generic => "generic",
            Self::Manual => "manual",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Fritzbox => "FRITZ!Box",
            Self::Unifi => "UniFi",
            Self::Opnsense => "OPNsense",
            Self::Pfsense => "pfSense",
            Self::Openwrt => "OpenWrt",
            Self::Span => "Managed Switch / SPAN",
            Self::Generic => "Other / Generic Router",
            Self::Manual => "Manual Setup",
        }
    }

    /// Der Beobachtungspunkt, den diese Plattform ohne Zusatz-Hardware
    /// hergibt. Nur ein Vorschlag des Setups — der Betreiber kann jeden
    /// Vantage wählen.
    pub fn default_vantage(self) -> Vantage {
        match self {
            // Ein Consumer-Router spiegelt nicht. Der Sensor hängt am LAN wie
            // jedes andere Gerät.
            Self::Fritzbox | Self::Unifi | Self::Generic | Self::Manual => Vantage::LanHost,
            // Firewall-Distributionen: der übliche Aufbau ist ein Sensor am
            // LAN-Segment der Firewall; wer den Sensor auf der Firewall selbst
            // betreibt, wählt im Setup `gateway`.
            Self::Opnsense | Self::Pfsense | Self::Openwrt => Vantage::LanHost,
            Self::Span => Vantage::MirrorPort,
        }
    }

    /// Kann diese Plattform selbst Verkehr spiegeln? `None` = unbekannt.
    ///
    /// Das ist die Frage, an der die maximal erreichbare Sichtbarkeit hängt,
    /// deshalb steht sie hier explizit statt als Prosa in der Doku.
    pub fn supports_port_mirroring(self) -> Option<bool> {
        match self {
            // FRITZ!OS kennt keinen Mirror-Port. (Der Paketmitschnitt unter
            // /html/capture.html ist ein Datei-Download im Browser, kein
            // Spiegel-Port und für einen Sensor nicht nutzbar.)
            Self::Fritzbox => Some(false),
            // UniFi-Switches können Port-Mirroring; die Dream Machine und die
            // Firewall-Distributionen können es je nach Modell/Aufbau.
            Self::Unifi | Self::Opnsense | Self::Pfsense | Self::Openwrt | Self::Span => Some(true),
            Self::Generic | Self::Manual => None,
        }
    }

    /// Was auf dieser Plattform konkret geht — der Text, den das Setup und
    /// `trapd-sensorctl visibility` zeigen. Bewusst ohne Versprechen: hier
    /// steht nur, was der Sensor tatsächlich kann oder was der Betreiber
    /// selbst an der Plattform einstellen müsste.
    pub fn guidance(self) -> &'static [&'static str] {
        match self {
            Self::Fritzbox => &[
                "A FRITZ!Box cannot mirror ports, so the sensor sees broadcast and multicast traffic plus its own — enough for asset discovery, new-device detection and fingerprinting.",
                "The box itself is discovered like any other device (ARP/NDP, DHCP, SSDP); TRAPD does not log into it and needs no FRITZ!Box credentials.",
                "For traffic visibility, put a managed switch with SPAN (or a TAP) between the FRITZ!Box and the rest of the LAN and re-run `trapd-sensorctl setup --profile span`.",
            ],
            Self::Unifi => &[
                "UniFi switches support port mirroring: mirror the uplink port to the sensor's port, then re-run `trapd-sensorctl setup --profile span` to record it.",
                "Without mirroring the sensor still sees broadcast and multicast traffic — asset discovery, new-device detection and fingerprinting work.",
                "TRAPD reads nothing from the UniFi controller and needs no controller credentials.",
            ],
            Self::Opnsense | Self::Pfsense => &[
                "Running the sensor on a host in the firewall's LAN segment gives asset discovery, new-device detection and fingerprinting.",
                "For routed traffic (internet and inter-VLAN), attach the sensor to a mirrored port or run it where the routed traffic passes, then select the `gateway` or `span` vantage.",
                "The firewall itself is discovered passively; TRAPD does not log into it.",
            ],
            Self::Openwrt => &[
                "OpenWrt can mirror traffic (tc/mirred or a bridge mirror port) — configure it on the router, then re-run `trapd-sensorctl setup --profile span`.",
                "Without mirroring the sensor sees broadcast and multicast traffic — asset discovery, new-device detection and fingerprinting work.",
                "The router itself is discovered passively; TRAPD does not log into it.",
            ],
            Self::Span => &[
                "Every frame of the mirrored segment reaches the capture socket: flows, DNS and service discovery work in full.",
                "Visibility is exactly what the switch mirrors — mirroring the uplink port shows internet traffic, mirroring one access port shows only that device.",
                "Promiscuous mode must stay on (`capture.promiscuous = true`), otherwise the socket drops everything not addressed to this host.",
            ],
            Self::Generic => &[
                "Without knowing the platform, TRAPD assumes a plain switched LAN: broadcast and multicast are visible, other hosts' unicast traffic is not.",
                "Asset discovery, new-device detection and fingerprinting work; traffic and DNS visibility need a mirrored port, a TAP, or a vantage on the gateway.",
            ],
            Self::Manual => &[
                "Nothing was recorded about how this sensor is attached — run `trapd-sensorctl setup` so the visibility report reflects reality.",
            ],
        }
    }
}

impl std::fmt::Display for NetworkProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NetworkProfile {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        parse_token(s, Self::ALL, NetworkProfile::as_str, "network profile")
    }
}

/// Der Beobachtungspunkt — wie der Sensor an das Netz angeschlossen ist.
///
/// Das ist die technisch entscheidende Angabe: ein geswitchtes LAN liefert an
/// einen normalen Port nur Broadcast, Multicast und den eigenen Verkehr. Was
/// darüber hinausgeht, hängt daran, wo der Sensor hängt — nicht daran, welche
/// Module eingeschaltet sind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vantage {
    /// Wie ein normales Gerät am LAN. Broadcast/Multicast (ARP, NDP, DHCP,
    /// mDNS, SSDP) plus der eigene Verkehr. Die Vorgabe, weil sie am wenigsten
    /// behauptet.
    #[default]
    LanHost,
    /// SPAN-/Mirror-Port eines Managed Switch.
    MirrorPort,
    /// Passiver Netzwerk-TAP.
    NetworkTap,
    /// Der Sensor sieht den gerouteten Verkehr — er läuft auf dem Gateway
    /// selbst oder an einem Segment, durch das der Uplink führt.
    Gateway,
}

impl Vantage {
    pub const ALL: &'static [Self] = &[
        Self::LanHost,
        Self::MirrorPort,
        Self::NetworkTap,
        Self::Gateway,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LanHost => "lan_host",
            Self::MirrorPort => "mirror_port",
            Self::NetworkTap => "network_tap",
            Self::Gateway => "gateway",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::LanHost => "host on the LAN",
            Self::MirrorPort => "SPAN / mirror port",
            Self::NetworkTap => "network TAP",
            Self::Gateway => "gateway / routed traffic",
        }
    }

    /// Erreicht jeder Frame des Segments die Capture-Socket?
    pub fn sees_all_segment_traffic(self) -> bool {
        matches!(self, Self::MirrorPort | Self::NetworkTap)
    }

    /// Sieht der Sensor den gerouteten Verkehr (Internet, Inter-VLAN)?
    pub fn sees_routed_traffic(self) -> bool {
        self.sees_all_segment_traffic() || self == Self::Gateway
    }

    /// Braucht dieser Beobachtungspunkt den Promiscuous-Modus, um überhaupt
    /// etwas zu liefern? An einem Mirror-Port sind praktisch alle Frames an
    /// fremde MAC-Adressen adressiert — ohne Promiscuous verwirft die NIC sie.
    pub fn requires_promiscuous(self) -> bool {
        self.sees_all_segment_traffic()
    }
}

impl std::fmt::Display for Vantage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Vantage {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        parse_token(s, Self::ALL, Vantage::as_str, "vantage")
    }
}

/// Ein Token gegen die Variantenliste auflösen. Eine Stelle für alle drei
/// Aufzählungen, damit Tokens und Fehlermeldungen nicht auseinanderlaufen.
fn parse_token<T: Copy>(
    input: &str,
    all: &'static [T],
    as_str: fn(T) -> &'static str,
    what: &str,
) -> std::result::Result<T, String> {
    let needle = input.trim().to_ascii_lowercase();
    all.iter()
        .copied()
        .find(|v| as_str(*v) == needle)
        .ok_or_else(|| {
            format!(
                "unknown {what} '{input}' — expected one of: {}",
                all.iter()
                    .copied()
                    .map(as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

/// Der `[deployment]`-Abschnitt der Konfiguration.
///
/// Vollständig optional: fehlt er, gilt "Enterprise, von Hand eingerichtet,
/// Sensor hängt wie ein normales Gerät am LAN" — die konservativste Annahme,
/// die keine Sichtbarkeit behauptet, die niemand geprüft hat.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeploymentConfig {
    pub edition: Edition,
    pub profile: NetworkProfile,
    pub vantage: Vantage,
    /// Das erkannte oder angegebene Standard-Gateway. Rein informativ — der
    /// Sensor verbindet sich nicht von sich aus dorthin.
    pub gateway_ip: Option<IpAddr>,
    /// Das lokale Netz in CIDR-Notation, wie vom Setup erkannt.
    pub lan_cidr: Option<String>,
}

impl DeploymentConfig {
    /// Wurde die Umgebung je erfasst? `false` heißt: die Angaben sind
    /// Vorgaben, keine Feststellungen.
    pub fn is_configured(&self) -> bool {
        self.profile != NetworkProfile::Manual || self.vantage != Vantage::default()
    }

    pub fn validate(&self) -> std::result::Result<(), String> {
        if let Some(cidr) = &self.lan_cidr {
            Cidr::parse(cidr).map_err(|e| format!("invalid deployment.lan_cidr '{cidr}': {e}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Die Tokens landen in der Konfigurationsdatei *und* in CLI-Argumenten.
    /// Liefen `serde` und `FromStr` auseinander, ließe sich ein per CLI
    /// gesetzter Wert nicht mehr laden.
    #[test]
    fn serde_tokens_and_parse_tokens_agree() {
        for edition in Edition::ALL {
            let json = serde_json::to_string(edition).expect("serialize");
            assert_eq!(json, format!("\"{}\"", edition.as_str()));
            assert_eq!(
                Edition::from_str(edition.as_str()).expect("parse"),
                *edition
            );
        }
        for profile in NetworkProfile::ALL {
            let json = serde_json::to_string(profile).expect("serialize");
            assert_eq!(json, format!("\"{}\"", profile.as_str()));
            assert_eq!(
                NetworkProfile::from_str(profile.as_str()).expect("parse"),
                *profile
            );
        }
        for vantage in Vantage::ALL {
            let json = serde_json::to_string(vantage).expect("serialize");
            assert_eq!(json, format!("\"{}\"", vantage.as_str()));
            assert_eq!(
                Vantage::from_str(vantage.as_str()).expect("parse"),
                *vantage
            );
        }
    }

    #[test]
    fn unknown_tokens_list_the_alternatives() {
        let error = NetworkProfile::from_str("fritz-box").expect_err("rejected");
        assert!(error.contains("fritzbox"), "{error}");
        assert!(error.contains("unifi"), "{error}");
    }

    #[test]
    fn tokens_are_case_insensitive_and_trimmed() {
        assert_eq!(
            Edition::from_str("  Homelab ").expect("parse"),
            Edition::Homelab
        );
    }

    #[test]
    fn the_default_deployment_claims_nothing() {
        let deployment = DeploymentConfig::default();
        assert_eq!(deployment.edition, Edition::Enterprise);
        assert_eq!(deployment.profile, NetworkProfile::Manual);
        assert_eq!(deployment.vantage, Vantage::LanHost);
        assert!(!deployment.is_configured());
        assert!(!deployment.vantage.sees_routed_traffic());
    }

    #[test]
    fn a_fritzbox_cannot_mirror_and_says_so() {
        assert_eq!(
            NetworkProfile::Fritzbox.supports_port_mirroring(),
            Some(false)
        );
        assert_eq!(NetworkProfile::Unifi.supports_port_mirroring(), Some(true));
        assert_eq!(NetworkProfile::Generic.supports_port_mirroring(), None);
    }

    #[test]
    fn every_profile_carries_guidance() {
        for profile in NetworkProfile::ALL {
            assert!(
                !profile.guidance().is_empty(),
                "{profile} has no guidance text"
            );
        }
    }

    #[test]
    fn span_is_the_only_default_vantage_that_needs_promiscuous() {
        for profile in NetworkProfile::ALL {
            let vantage = profile.default_vantage();
            assert_eq!(
                vantage.requires_promiscuous(),
                *profile == NetworkProfile::Span,
                "{profile}"
            );
        }
    }

    #[test]
    fn lan_cidr_is_validated() {
        let mut deployment = DeploymentConfig {
            lan_cidr: Some("192.168.178.0/24".into()),
            ..Default::default()
        };
        assert!(deployment.validate().is_ok());

        deployment.lan_cidr = Some("nonsense".into());
        assert!(deployment.validate().is_err());
    }
}
