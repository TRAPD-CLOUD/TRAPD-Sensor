//! Das Beobachtungsmodell des Sensors.
//!
//! Jedes Modul erzeugt [`Observation`]-Werte; alles danach (Queue, Upload,
//! Backend) kennt nur noch diesen einen Typ. Die Varianten sind absichtlich nah
//! an den Tabellen des Netzwerkmoduls im Backend modelliert
//! (`network_observations`, `network_flows`, `network_dns_events`,
//! `network_topology_edges`), damit der stream-processor ohne Rätselraten
//! einsortieren kann.
//!
//! Was hier **nicht** vorkommt, ist genauso Teil des Designs: es gibt keine
//! Variante, die rohe Paketinhalte transportiert. Der Sensor gibt Metadaten und
//! ausgewählte Klartext-Felder weiter, sonst nichts.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Dringlichkeit eines Events. Steuert, was bei vollem Puffer zuerst fällt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// Massendaten. Fallen zuerst — Flows sind ohnehin aggregiert und der
    /// Verlust eines Fensters ist verschmerzbar.
    Bulk = 0,
    /// Der Regelfall: Assets, Dienste, Fingerprints, DNS.
    Standard = 1,
    /// Zustand des Sensors selbst und sicherheitsrelevante Beobachtungen.
    /// Fallen zuletzt, denn ein stiller Sensor ist schlimmer als ein lückenhafter.
    Critical = 2,
}

/// Wie sicher ist eine Aussage? Fingerprinting liefert nie Gewissheit, deshalb
/// trägt jede Erkennung ihren eigenen Wert mit.
pub type Confidence = f32;

/// Eine einzelne Beobachtung.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observation {
    /// Ein Gerät wurde gesehen (IP/MAC), unabhängig davon, wie.
    Asset(AssetObservation),
    /// Ergebnis der Fingerprint-Aggregation für ein Gerät.
    Fingerprint(FingerprintObservation),
    /// Ein erreichbarer Dienst auf einem Gerät.
    Service(ServiceObservation),
    /// Aggregierte Flow-Metadaten eines Zeitfensters.
    Flow(FlowObservation),
    /// Beobachtete DNS-Abfrage.
    Dns(DnsObservation),
    /// Beobachtete DHCP-Zuteilung.
    Dhcp(DhcpObservation),
    /// Kante im Asset-Graph.
    Relationship(RelationshipObservation),
    /// Lebenszeichen und Selbstauskunft des Sensors.
    Heartbeat(HeartbeatObservation),
    /// Zustandsmeldung (Degradation, verlorene Capability, verworfene Events).
    Status(StatusObservation),
}

impl Observation {
    /// Event-Typ im Envelope. Konvention `network.<domäne>.<vorgang>`, passend
    /// zum `class.action`-Schema des Endpoint-Agents.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::Asset(_) => "network.asset.discovered",
            Self::Fingerprint(_) => "network.device.fingerprint",
            Self::Service(_) => "network.service.discovered",
            Self::Flow(_) => "network.flow.metadata",
            Self::Dns(_) => "network.dns.query",
            Self::Dhcp(_) => "network.dhcp.lease",
            Self::Relationship(_) => "network.relationship.observed",
            Self::Heartbeat(_) => "network.sensor.heartbeat",
            Self::Status(_) => "network.sensor.status",
        }
    }

    pub fn priority(&self) -> Priority {
        match self {
            Self::Flow(_) => Priority::Bulk,
            Self::Heartbeat(_) | Self::Status(_) => Priority::Critical,
            _ => Priority::Standard,
        }
    }

    /// Primäre IP der Beobachtung, soweit vorhanden — nur für Logging und
    /// lokale Deduplizierung.
    pub fn primary_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Asset(a) => a.ip,
            Self::Fingerprint(f) => f.ip,
            Self::Service(s) => Some(s.ip),
            Self::Flow(f) => Some(f.source_ip),
            Self::Dns(d) => d.client_ip,
            Self::Dhcp(d) => d.assigned_ip,
            Self::Relationship(r) => r.source_ip,
            Self::Heartbeat(_) | Self::Status(_) => None,
        }
    }
}

/// Woher stammt eine Beobachtung? Wichtig fürs Vertrauensmaß im Backend und für
/// die Frage "hat der Sensor dafür Pakete erzeugt?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    Arp,
    Ndp,
    Dhcp,
    Mdns,
    Ssdp,
    Dns,
    PassiveFlow,
    IcmpProbe,
    TcpConnect,
    Banner,
    Snmp,
}

impl DiscoveryMethod {
    /// Hat dieses Verfahren Pakete ins Netz geschickt?
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::IcmpProbe | Self::TcpConnect | Self::Banner | Self::Snmp
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Ndp => "ndp",
            Self::Dhcp => "dhcp",
            Self::Mdns => "mdns",
            Self::Ssdp => "ssdp",
            Self::Dns => "dns",
            Self::PassiveFlow => "passive_flow",
            Self::IcmpProbe => "icmp_probe",
            Self::TcpConnect => "tcp_connect",
            Self::Banner => "banner",
            Self::Snmp => "snmp",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    /// Normalisiert als `aa:bb:cc:dd:ee:ff`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
    pub method: DiscoveryMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_family: Option<String>,
    pub confidence: Confidence,
    /// Nachvollziehbarkeit: welche Einzelsignale zu diesem Ergebnis geführt
    /// haben. Ohne das ist ein Fingerprint im Dashboard nicht überprüfbar.
    pub evidence: Vec<FingerprintEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintEvidence {
    pub method: DiscoveryMethod,
    /// Kurzbezeichner des Signals, z. B. `mac_oui`, `dhcp_option55`.
    pub signal: String,
    pub value: String,
    pub weight: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceObservation {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: TransportProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Gekürztes, bereinigtes Banner — nie mehr als [`MAX_BANNER_LEN`] Bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    pub method: DiscoveryMethod,
}

/// Banner werden hart gekappt: sie sind ein Identifikationshinweis, kein
/// Datenkanal. Alles darüber wäre faktisch Payload-Mitschnitt.
pub const MAX_BANNER_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl TransportProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowObservation {
    pub source_ip: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    pub dest_ip: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_port: Option<u16>,
    pub protocol: TransportProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub direction: FlowDirection,
    pub bytes: u64,
    pub packets: u64,
    pub duration_ms: u64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowDirection {
    Inbound,
    Outbound,
    Lateral,
}

impl FlowDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::Lateral => "lateral",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsObservation {
    /// Query-Name oder, bei aktivierter Pseudonymisierung, dessen Hash.
    pub query_name: String,
    /// Kennzeichnet, dass `query_name` gehasht ist — sonst wäre im Dashboard
    /// nicht unterscheidbar, ob ein Name kryptisch oder pseudonymisiert ist.
    #[serde(default, skip_serializing_if = "is_false")]
    pub query_name_hashed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_ips: Vec<IpAddr>,
    pub answer_count: u16,
    pub is_nxdomain: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpObservation {
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_class: Option<String>,
    /// Option-55-Fingerprint (Parameter Request List) als kommaseparierte Liste.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param_request_list: Option<String>,
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipObservation {
    pub source_node: String,
    pub dest_node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_ip: Option<IpAddr>,
    pub edge_type: RelationshipType,
    pub observed_count: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    /// Aus Flow-Metadaten abgeleitete Kommunikationsbeziehung.
    TalksTo,
    /// Gerät bezieht seine Adresse von diesem DHCP-Server.
    DhcpServedBy,
    /// Gerät fragt diesen Resolver.
    ResolvesVia,
    /// Gerät bewirbt einen Dienst (mDNS/SSDP).
    AdvertisesService,
    /// Gemeinsames Subnetz.
    SameSubnet,
    /// Gemeinsames VLAN.
    SameVlan,
}

impl RelationshipType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TalksTo => "talks_to",
            Self::DhcpServedBy => "dhcp_served_by",
            Self::ResolvesVia => "resolves_via",
            Self::AdvertisesService => "advertises_service",
            Self::SameSubnet => "same_subnet",
            Self::SameVlan => "same_vlan",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatObservation {
    pub sensor_version: String,
    pub mode: String,
    pub uptime_secs: u64,
    pub interfaces: Vec<InterfaceHealth>,
    pub queue_depth: u64,
    pub queue_bytes: u64,
    pub events_emitted: u64,
    pub events_dropped: u64,
    /// Aktive Erkennung aus, obwohl konfiguriert? Dann steht hier der Grund.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_disabled_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceHealth {
    pub name: String,
    pub up: bool,
    pub promiscuous: bool,
    pub packets_captured: u64,
    /// Vom Kernel verworfene Pakete — der ehrlichste Überlastindikator.
    pub packets_dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusObservation {
    pub level: StatusLevel,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusLevel {
    Info,
    Warning,
    Error,
}

/// Eine Beobachtung mit Identität und Zeitstempel — das, was in die Queue geht.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorEvent {
    /// UUIDv7: zeitsortiert, damit WAL-Reihenfolge und Backend-Dedup ohne
    /// zusätzliches Sortierfeld funktionieren.
    pub event_id: Uuid,
    /// Monoton je Sensor-Lauf. Grundlage der Replay-Erkennung im Backend.
    pub sequence: u64,
    /// RFC3339, UTC.
    pub observed_at: String,
    pub observation: Observation,
}

impl SensorEvent {
    pub fn new(sequence: u64, observation: Observation) -> Self {
        Self {
            event_id: Uuid::now_v7(),
            sequence,
            observed_at: chrono::Utc::now().to_rfc3339(),
            observation,
        }
    }

    pub fn priority(&self) -> Priority {
        self.observation.priority()
    }

    pub fn event_type(&self) -> &'static str {
        self.observation.event_type()
    }
}

/// Kürzt und bereinigt ein Banner: nur druckbares ASCII, harte Längengrenze.
/// Steuerzeichen würden Logs und Dashboard-Darstellung verfälschen, und ein
/// unbegrenztes Banner wäre ein Payload-Kanal durch die Hintertür.
pub fn sanitize_banner(raw: &[u8]) -> Option<String> {
    let cleaned: String = raw
        .iter()
        .take(MAX_BANNER_LEN)
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                ' '
            }
        })
        .collect();
    let trimmed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Normalisiert eine MAC-Adresse auf `aa:bb:cc:dd:ee:ff`.
pub fn normalize_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_ordering_puts_bulk_lowest() {
        assert!(Priority::Bulk < Priority::Standard);
        assert!(Priority::Standard < Priority::Critical);
    }

    #[test]
    fn flows_are_bulk_and_status_is_critical() {
        let flow = Observation::Flow(FlowObservation {
            source_ip: "10.0.0.1".parse().expect("ip"),
            source_port: Some(1234),
            dest_ip: "10.0.0.2".parse().expect("ip"),
            dest_port: Some(443),
            protocol: TransportProtocol::Tcp,
            service: Some("https".into()),
            direction: FlowDirection::Lateral,
            bytes: 100,
            packets: 2,
            duration_ms: 10,
            first_seen: "2026-01-01T00:00:00Z".into(),
            last_seen: "2026-01-01T00:00:01Z".into(),
        });
        assert_eq!(flow.priority(), Priority::Bulk);
        assert_eq!(flow.event_type(), "network.flow.metadata");

        let status = Observation::Status(StatusObservation {
            level: StatusLevel::Warning,
            code: "queue_full".into(),
            message: "dropping bulk events".into(),
            details: BTreeMap::new(),
        });
        assert_eq!(status.priority(), Priority::Critical);
    }

    #[test]
    fn active_methods_are_flagged() {
        assert!(!DiscoveryMethod::Arp.is_active());
        assert!(!DiscoveryMethod::PassiveFlow.is_active());
        assert!(DiscoveryMethod::TcpConnect.is_active());
        assert!(DiscoveryMethod::Snmp.is_active());
    }

    #[test]
    fn banner_is_truncated_and_stripped() {
        let raw = b"SSH-2.0-OpenSSH_9.2\r\n";
        assert_eq!(sanitize_banner(raw).as_deref(), Some("SSH-2.0-OpenSSH_9.2"));

        let long = vec![b'A'; 1000];
        let out = sanitize_banner(&long).expect("banner");
        assert_eq!(out.len(), MAX_BANNER_LEN);

        assert_eq!(
            sanitize_banner(&[0u8, 1, 2]),
            None,
            "control-only is dropped"
        );
    }

    #[test]
    fn mac_normalization_is_lowercase_colon_separated() {
        assert_eq!(
            normalize_mac(&[0xAA, 0xBB, 0x0C, 0xDD, 0xEE, 0xFF]),
            "aa:bb:0c:dd:ee:ff"
        );
    }

    #[test]
    fn sensor_event_ids_are_time_ordered() {
        let a = SensorEvent::new(
            1,
            Observation::Status(StatusObservation {
                level: StatusLevel::Info,
                code: "a".into(),
                message: "a".into(),
                details: BTreeMap::new(),
            }),
        );
        let b = SensorEvent::new(
            2,
            Observation::Status(StatusObservation {
                level: StatusLevel::Info,
                code: "b".into(),
                message: "b".into(),
                details: BTreeMap::new(),
            }),
        );
        assert!(a.event_id < b.event_id, "uuidv7 keeps creation order");
    }

    #[test]
    fn observation_roundtrips_through_json() {
        let obs = Observation::Dns(DnsObservation {
            query_name: "example.com".into(),
            query_name_hashed: false,
            query_type: Some("A".into()),
            response_code: Some("NOERROR".into()),
            client_ip: "192.168.1.10".parse().ok(),
            server_ip: "192.168.1.1".parse().ok(),
            resolved_ips: vec!["93.184.216.34".parse().expect("ip")],
            answer_count: 1,
            is_nxdomain: false,
        });
        let json = serde_json::to_string(&obs).expect("serialize");
        assert!(json.contains("\"kind\":\"dns\""));
        let back: Observation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.event_type(), "network.dns.query");
    }
}
