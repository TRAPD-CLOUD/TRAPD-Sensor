//! Vom Frame zur Beobachtung.
//!
//! Der [`PassiveObserver`] ist die einzige Stelle, an der rohe Bytes auf das
//! Datenmodell treffen. Er entscheidet, welche Module überhaupt hinsehen dürfen
//! (Policy), was davon das Gerät verlässt (Privacy) und wie oft dieselbe
//! Erkenntnis gemeldet wird (Unterdrückung).
//!
//! Die Unterdrückung ist kein Detail: ARP-Verkehr in einem 50-Geräte-Netz sind
//! leicht mehrere Pakete pro Sekunde, und jedes davon "entdeckt" dasselbe
//! Gerät erneut. Ohne ein Zeitfenster pro Aussage bestünde die Telemetrie zu
//! 99 % aus Wiederholungen.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use trapd_sensor_core::config::{EffectivePolicy, PrivacyConfig};
use trapd_sensor_core::model::{
    normalize_mac, AssetObservation, DhcpObservation, DiscoveryMethod, DnsObservation, Observation,
    RelationshipObservation, RelationshipType, ServiceObservation, TransportProtocol,
};

use crate::arp::parse_arp;
use crate::dhcp::{parse_dhcp, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::dns::{parse_dns, DNS_PORT, MDNS_PORT};
use crate::flow::{FlowAggregator, FlowKey};
use crate::frame::{
    parse_ethernet, parse_ipv4, parse_ipv6, parse_tcp, parse_udp, ETHERTYPE_ARP, ETHERTYPE_IPV4,
    ETHERTYPE_IPV6, IP_PROTO_ICMP, IP_PROTO_ICMPV6, IP_PROTO_TCP, IP_PROTO_UDP,
};
use crate::icmpv6::{parse_neighbor_discovery, NeighborDiscovery};
use crate::ssdp::{parse_ssdp, SSDP_PORT};

/// Wie lange dieselbe Aussage nicht erneut gemeldet wird.
const DEFAULT_SUPPRESSION_SECS: i64 = 300;
/// Obergrenze des Unterdrückungs-Caches.
const MAX_SUPPRESSION_ENTRIES: usize = 20_000;

pub struct PassiveObserver {
    interface: String,
    policy: EffectivePolicy,
    flows: FlowAggregator,
    suppression: Suppressor,
    packets_seen: u64,
    packets_parsed: u64,
}

impl PassiveObserver {
    pub fn new(
        interface: impl Into<String>,
        policy: EffectivePolicy,
        flow_window_secs: u64,
        max_flows: usize,
    ) -> Self {
        Self {
            interface: interface.into(),
            policy,
            flows: FlowAggregator::new(flow_window_secs, max_flows),
            suppression: Suppressor::new(DEFAULT_SUPPRESSION_SECS),
            packets_seen: 0,
            packets_parsed: 0,
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn packets_seen(&self) -> u64 {
        self.packets_seen
    }

    pub fn parser_errors(&self) -> u64 {
        self.packets_seen.saturating_sub(self.packets_parsed)
    }

    pub fn tracked_flows(&self) -> usize {
        self.flows.tracked_flows()
    }

    /// Verarbeitet ein Ethernet-Frame.
    pub fn handle_frame(&mut self, data: &[u8], now: DateTime<Utc>) -> Vec<Observation> {
        self.packets_seen += 1;
        let mut out = Vec::new();

        let Some(frame) = parse_ethernet(data) else {
            return out;
        };
        self.packets_parsed += 1;

        match frame.ethertype {
            ETHERTYPE_ARP => {
                if self.policy.passive.arp {
                    self.handle_arp(frame.payload, frame.vlan_id, now, &mut out);
                }
            }
            ETHERTYPE_IPV4 => {
                if let Some(ip) = parse_ipv4(frame.payload) {
                    self.handle_ip(
                        &ip,
                        frame.src_mac,
                        frame.vlan_id,
                        data.len() as u64,
                        now,
                        &mut out,
                    );
                }
            }
            ETHERTYPE_IPV6 => {
                if let Some(ip) = parse_ipv6(frame.payload) {
                    self.handle_ip(
                        &ip,
                        frame.src_mac,
                        frame.vlan_id,
                        data.len() as u64,
                        now,
                        &mut out,
                    );
                }
            }
            _ => {}
        }

        out
    }

    /// Gibt abgelaufene Flow-Fenster ab.
    pub fn expire(&mut self, now: DateTime<Utc>) -> Vec<Observation> {
        self.suppression.prune(now);
        self.flows
            .expire(now)
            .into_iter()
            .map(Observation::Flow)
            .collect()
    }

    /// Gibt alles Ausstehende ab (Shutdown).
    pub fn drain(&mut self) -> Vec<Observation> {
        self.flows
            .drain_all()
            .into_iter()
            .map(Observation::Flow)
            .collect()
    }

    // -- Protokolle --------------------------------------------------------

    fn handle_arp(
        &mut self,
        payload: &[u8],
        vlan_id: Option<u16>,
        now: DateTime<Utc>,
        out: &mut Vec<Observation>,
    ) {
        let Some(arp) = parse_arp(payload) else {
            return;
        };
        if !arp.announces_sender() {
            return;
        }
        let ip = IpAddr::V4(arp.sender_ip);
        if self.is_excluded(ip) {
            return;
        }

        let mac = normalize_mac(&arp.sender_mac);
        if !self.suppression.allow(&format!("arp:{ip}:{mac}"), now) {
            return;
        }

        out.push(Observation::Asset(AssetObservation {
            ip: Some(ip),
            mac: Some(mac),
            hostname: None,
            vlan_id,
            subnet: None,
            method: DiscoveryMethod::Arp,
            interface: Some(self.interface.clone()),
        }));
    }

    fn handle_ip(
        &mut self,
        ip: &crate::frame::IpPacket<'_>,
        source_mac: [u8; 6],
        vlan_id: Option<u16>,
        frame_bytes: u64,
        now: DateTime<Utc>,
        out: &mut Vec<Observation>,
    ) {
        if self.is_excluded(ip.src) || self.is_excluded(ip.dst) {
            return;
        }

        match ip.protocol {
            IP_PROTO_UDP => {
                let Some(udp) = parse_udp(ip.payload) else {
                    return;
                };
                self.handle_udp(ip, &udp, vlan_id, now, out);
                self.record_flow(
                    ip.src,
                    udp.src_port,
                    ip.dst,
                    udp.dst_port,
                    TransportProtocol::Udp,
                    frame_bytes,
                    now,
                );
            }
            IP_PROTO_TCP => {
                let Some(tcp) = parse_tcp(ip.payload) else {
                    return;
                };
                // Ein SYN-ACK ist der Beweis, dass der Port offen ist — passiv
                // gewonnen, ohne ein einziges Paket zu senden. Genau die Art
                // Erkenntnis, für die andere Werkzeuge scannen müssen.
                if tcp.is_syn_ack() {
                    let key = format!("svc:{}:{}", ip.src, tcp.src_port);
                    if self.suppression.allow(&key, now) {
                        out.push(Observation::Service(ServiceObservation {
                            ip: ip.src,
                            port: tcp.src_port,
                            protocol: TransportProtocol::Tcp,
                            service: crate::flow::well_known_service(
                                tcp.src_port,
                                TransportProtocol::Tcp,
                            )
                            .map(str::to_string),
                            banner: None,
                            method: DiscoveryMethod::PassiveFlow,
                        }));
                    }
                }
                self.record_flow(
                    ip.src,
                    tcp.src_port,
                    ip.dst,
                    tcp.dst_port,
                    TransportProtocol::Tcp,
                    frame_bytes,
                    now,
                );
            }
            IP_PROTO_ICMPV6 => {
                self.handle_icmpv6(ip, source_mac, vlan_id, now, out);
                self.record_flow(
                    ip.src,
                    0,
                    ip.dst,
                    0,
                    TransportProtocol::Icmp,
                    frame_bytes,
                    now,
                );
            }
            IP_PROTO_ICMP => {
                self.record_flow(
                    ip.src,
                    0,
                    ip.dst,
                    0,
                    TransportProtocol::Icmp,
                    frame_bytes,
                    now,
                );
            }
            _ => {}
        }
    }

    fn handle_icmpv6(
        &mut self,
        ip: &crate::frame::IpPacket<'_>,
        ethernet_mac: [u8; 6],
        vlan_id: Option<u16>,
        now: DateTime<Utc>,
        out: &mut Vec<Observation>,
    ) {
        let Some(ndp) = parse_neighbor_discovery(ip.payload) else {
            return;
        };
        let (address, option_mac) = match ndp {
            NeighborDiscovery::RouterAdvertisement { source_mac } => (ip.src, source_mac),
            NeighborDiscovery::NeighborSolicitation { source_mac, .. } => (ip.src, source_mac),
            NeighborDiscovery::NeighborAdvertisement { target, target_mac } => {
                (IpAddr::V6(target), target_mac)
            }
        };
        // The Ethernet source is authoritative for this frame and is also
        // available when an NDP sender omits its link-layer option.
        let mac = option_mac.unwrap_or(ethernet_mac);
        if address.is_unspecified() || address.is_multicast() || self.is_excluded(address) {
            return;
        }
        let mac = normalize_mac(&mac);
        if self.suppression.allow(&format!("ndp:{address}:{mac}"), now) {
            out.push(Observation::Asset(AssetObservation {
                ip: Some(address),
                mac: Some(mac),
                hostname: None,
                vlan_id,
                subnet: None,
                method: DiscoveryMethod::Ndp,
                interface: Some(self.interface.clone()),
            }));
        }
    }

    fn handle_udp(
        &mut self,
        ip: &crate::frame::IpPacket<'_>,
        udp: &crate::frame::UdpDatagram<'_>,
        vlan_id: Option<u16>,
        now: DateTime<Utc>,
        out: &mut Vec<Observation>,
    ) {
        let ports = (udp.src_port, udp.dst_port);

        if self.policy.passive.dhcp
            && (ports.0 == DHCP_SERVER_PORT
                || ports.1 == DHCP_SERVER_PORT
                || ports.0 == DHCP_CLIENT_PORT
                || ports.1 == DHCP_CLIENT_PORT)
        {
            self.handle_dhcp(udp.payload, ip.src, vlan_id, now, out);
            return;
        }

        if self.policy.passive.mdns && (ports.0 == MDNS_PORT || ports.1 == MDNS_PORT) {
            self.handle_mdns(udp.payload, ip.src, vlan_id, now, out);
            return;
        }

        if self.policy.passive.ssdp && (ports.0 == SSDP_PORT || ports.1 == SSDP_PORT) {
            self.handle_ssdp(udp.payload, ip.src, vlan_id, now, out);
            return;
        }

        if self.policy.passive.dns && (ports.0 == DNS_PORT || ports.1 == DNS_PORT) {
            self.handle_dns(udp.payload, ip, now, out);
        }
    }

    fn handle_dhcp(
        &mut self,
        payload: &[u8],
        src: IpAddr,
        vlan_id: Option<u16>,
        now: DateTime<Utc>,
        out: &mut Vec<Observation>,
    ) {
        let Some(msg) = parse_dhcp(payload) else {
            return;
        };
        let mac = normalize_mac(&msg.client_mac);
        let assigned = msg.effective_ip().map(IpAddr::V4);

        let key = format!("dhcp:{mac}:{}", msg.message_type.as_str());
        if !self.suppression.allow(&key, now) {
            return;
        }

        out.push(Observation::Dhcp(DhcpObservation {
            mac: mac.clone(),
            assigned_ip: assigned,
            server_ip: msg.server_ip.map(IpAddr::V4),
            hostname: msg.hostname.clone(),
            vendor_class: msg.vendor_class.clone(),
            param_request_list: msg.param_request_list.clone(),
            message_type: msg.message_type.as_str().to_string(),
            lease_seconds: msg.lease_seconds,
        }));

        // Ein bestätigtes Lease ist zugleich eine Asset-Aussage — und die
        // einzige passive Quelle, die IP, MAC *und* Hostnamen zusammen liefert.
        if msg.message_type.confirms_lease() {
            if let Some(ip) = assigned {
                out.push(Observation::Asset(AssetObservation {
                    ip: Some(ip),
                    mac: Some(mac),
                    hostname: msg.hostname.clone(),
                    vlan_id,
                    subnet: None,
                    method: DiscoveryMethod::Dhcp,
                    interface: Some(self.interface.clone()),
                }));

                if let Some(server) = msg.server_ip {
                    out.push(Observation::Relationship(RelationshipObservation {
                        source_node: ip.to_string(),
                        dest_node: server.to_string(),
                        source_ip: Some(ip),
                        dest_ip: Some(IpAddr::V4(server)),
                        edge_type: RelationshipType::DhcpServedBy,
                        observed_count: 1,
                        attributes: Default::default(),
                    }));
                }
            }
        }
        let _ = src;
    }

    fn handle_mdns(
        &mut self,
        payload: &[u8],
        src: IpAddr,
        vlan_id: Option<u16>,
        now: DateTime<Utc>,
        out: &mut Vec<Observation>,
    ) {
        let Some(msg) = parse_dns(payload) else {
            return;
        };
        if !msg.is_response {
            // Eine mDNS-Frage sagt nichts über das Gerät aus, das sie stellt.
            return;
        }

        for service in msg.advertised_services() {
            let key = format!("mdns:{src}:{service}");
            if !self.suppression.allow(&key, now) {
                continue;
            }
            out.push(Observation::Relationship(RelationshipObservation {
                source_node: src.to_string(),
                dest_node: service.clone(),
                source_ip: Some(src),
                dest_ip: None,
                edge_type: RelationshipType::AdvertisesService,
                observed_count: 1,
                attributes: Default::default(),
            }));
        }

        // Der eigene Name eines Geräts steht im `.local`-Record der Antwort.
        if let Some(hostname) = msg
            .answers
            .iter()
            .map(|r| r.name.as_str())
            .find(|n| n.ends_with(".local") && !n.starts_with('_'))
        {
            let key = format!("mdns-host:{src}:{hostname}");
            if self.suppression.allow(&key, now) {
                out.push(Observation::Asset(AssetObservation {
                    ip: Some(src),
                    mac: None,
                    hostname: Some(hostname.to_string()),
                    vlan_id,
                    subnet: None,
                    method: DiscoveryMethod::Mdns,
                    interface: Some(self.interface.clone()),
                }));
            }
        }
    }

    fn handle_ssdp(
        &mut self,
        payload: &[u8],
        src: IpAddr,
        vlan_id: Option<u16>,
        now: DateTime<Utc>,
        out: &mut Vec<Observation>,
    ) {
        let Some(msg) = parse_ssdp(payload) else {
            return;
        };
        if !msg.describes_sender() {
            return;
        }

        let device_type = msg.device_type().unwrap_or("unknown");
        let key = format!("ssdp:{src}:{device_type}");
        if !self.suppression.allow(&key, now) {
            return;
        }

        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert("device_type".to_string(), device_type.to_string());
        if let Some(server) = msg.server() {
            attributes.insert("server".to_string(), server.to_string());
        }
        // `location` wird bewusst mitgegeben, aber nie abgerufen — das Backend
        // zeigt sie an, der Sensor fasst sie nicht an.
        if let Some(location) = msg.location() {
            attributes.insert("location".to_string(), location.to_string());
        }

        out.push(Observation::Asset(AssetObservation {
            ip: Some(src),
            mac: None,
            hostname: None,
            vlan_id,
            subnet: None,
            method: DiscoveryMethod::Ssdp,
            interface: Some(self.interface.clone()),
        }));
        out.push(Observation::Relationship(RelationshipObservation {
            source_node: src.to_string(),
            dest_node: device_type.to_string(),
            source_ip: Some(src),
            dest_ip: None,
            edge_type: RelationshipType::AdvertisesService,
            observed_count: 1,
            attributes,
        }));
    }

    fn handle_dns(
        &mut self,
        payload: &[u8],
        ip: &crate::frame::IpPacket<'_>,
        now: DateTime<Utc>,
        out: &mut Vec<Observation>,
    ) {
        let privacy = &self.policy.privacy;
        let Some(msg) = parse_dns(payload) else {
            return;
        };
        let Some(question) = msg.questions.first() else {
            return;
        };
        if is_excluded_domain(&question.name, &privacy.dns_exclude_domains) {
            return;
        }

        // Bei der Antwort ist der Client das Ziel, bei der Frage die Quelle.
        let (client, server) = if msg.is_response {
            (ip.dst, ip.src)
        } else {
            (ip.src, ip.dst)
        };

        let key = format!("dns:{client}:{}:{}", question.name, msg.is_response);
        if !self.suppression.allow(&key, now) {
            return;
        }

        let query_name = if privacy.hash_dns_names {
            pseudonymize(&question.name)
        } else {
            question.name.clone()
        };

        out.push(Observation::Dns(DnsObservation {
            query_name,
            query_name_hashed: privacy.hash_dns_names,
            query_type: Some(qtype_name(question.qtype).to_string()),
            response_code: msg
                .is_response
                .then(|| msg.response_code_name().to_string()),
            client_ip: Some(client),
            server_ip: Some(server),
            resolved_ips: if privacy.store_dns_answers {
                msg.resolved_addresses()
            } else {
                Vec::new()
            },
            answer_count: msg.answer_count,
            is_nxdomain: msg.is_nxdomain(),
        }));

        if msg.is_response {
            let rel_key = format!("resolver:{client}:{server}");
            if self.suppression.allow(&rel_key, now) {
                out.push(Observation::Relationship(RelationshipObservation {
                    source_node: client.to_string(),
                    dest_node: server.to_string(),
                    source_ip: Some(client),
                    dest_ip: Some(server),
                    edge_type: RelationshipType::ResolvesVia,
                    observed_count: 1,
                    attributes: Default::default(),
                }));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_flow(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        protocol: TransportProtocol,
        bytes: u64,
        now: DateTime<Utc>,
    ) {
        if !self.policy.passive.flows {
            return;
        }
        let key = FlowKey::normalized(src, src_port, dst, dst_port, protocol);
        self.flows.observe(key, bytes, now);
    }

    fn is_excluded(&self, ip: IpAddr) -> bool {
        is_excluded_client(ip, &self.policy.privacy)
    }
}

fn is_excluded_client(ip: IpAddr, privacy: &PrivacyConfig) -> bool {
    privacy
        .exclude_clients
        .iter()
        .filter_map(|c| trapd_sensor_core::config::Cidr::parse(c).ok())
        .any(|cidr| cidr.contains(ip))
}

fn is_excluded_domain(name: &str, excluded: &[String]) -> bool {
    let name = name.to_ascii_lowercase();
    excluded.iter().any(|suffix| {
        let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
        !suffix.is_empty() && (name == suffix || name.ends_with(&format!(".{suffix}")))
    })
}

/// Pseudonymisiert einen Query-Namen.
///
/// Zweck ist, dass keine Klartext-Domain den Host verlässt — Beobachtungen
/// desselben Namens bleiben trotzdem verknüpfbar. Das ist ausdrücklich *keine*
/// Anonymisierung: der Namensraum realer Domains ist klein genug, dass sich ein
/// Hash mit einer Wortliste zurückrechnen lässt. Wer das nicht will, schaltet
/// die DNS-Beobachtung ganz ab (`privacy.dns_observation = false`) — die Option
/// existiert genau dafür.
fn pseudonymize(name: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("h:{hash:016x}")
}

fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        255 => "ANY",
        _ => "OTHER",
    }
}

/// Merkt sich, welche Aussage zuletzt wann gemeldet wurde.
struct Suppressor {
    seen: HashMap<String, DateTime<Utc>>,
    ttl_secs: i64,
}

impl Suppressor {
    fn new(ttl_secs: i64) -> Self {
        Self {
            seen: HashMap::new(),
            ttl_secs,
        }
    }

    /// Darf diese Aussage jetzt gemeldet werden?
    fn allow(&mut self, key: &str, now: DateTime<Utc>) -> bool {
        if let Some(last) = self.seen.get(key) {
            if (now - *last).num_seconds() < self.ttl_secs {
                return false;
            }
        }
        // Bei vollem Cache lieber alles durchlassen als unbegrenzt wachsen: ein
        // Sensor, der wegen seines Duplikat-Caches Speicher frisst, hat das
        // Problem schlimmer gemacht als die Duplikate selbst.
        if self.seen.len() >= MAX_SUPPRESSION_ENTRIES {
            self.seen.clear();
        }
        self.seen.insert(key.to_string(), now);
        true
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let ttl = self.ttl_secs;
        self.seen
            .retain(|_, last| (now - *last).num_seconds() < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trapd_sensor_core::config::{SensorConfig, SensorMode};

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("timestamp")
    }

    fn observer_with(config: SensorConfig) -> PassiveObserver {
        PassiveObserver::new("eth0", config.effective_policy(), 60, 1000)
    }

    fn default_observer() -> PassiveObserver {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::PassiveOnly;
        observer_with(cfg)
    }

    // -- Frame-Bausteine ---------------------------------------------------

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn arp_frame(sender_ip: [u8; 4], sender_mac: [u8; 6]) -> Vec<u8> {
        let mut arp = Vec::new();
        arp.extend_from_slice(&1u16.to_be_bytes());
        arp.extend_from_slice(&0x0800u16.to_be_bytes());
        arp.push(6);
        arp.push(4);
        arp.extend_from_slice(&2u16.to_be_bytes()); // reply
        arp.extend_from_slice(&sender_mac);
        arp.extend_from_slice(&sender_ip);
        arp.extend_from_slice(&[0u8; 6]);
        arp.extend_from_slice(&[192, 168, 1, 1]);
        ethernet(ETHERTYPE_ARP, &arp)
    }

    fn ipv4_frame(protocol: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(payload);
        ethernet(ETHERTYPE_IPV4, &ip)
    }

    fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(payload);
        out
    }

    fn tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
        out.push(0x50);
        out.push(flags);
        out.extend_from_slice(&64240u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&1u16.to_be_bytes()); // A
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out
    }

    // -- Tests -------------------------------------------------------------

    #[test]
    fn arp_reply_produces_an_asset() {
        let mut obs = default_observer();
        let events = obs.handle_frame(&arp_frame([192, 168, 1, 42], [0xaa; 6]), at(0));

        assert_eq!(events.len(), 1);
        match &events[0] {
            Observation::Asset(a) => {
                assert_eq!(a.ip, Some("192.168.1.42".parse().expect("ip")));
                assert_eq!(a.mac.as_deref(), Some("aa:aa:aa:aa:aa:aa"));
                assert_eq!(a.method, DiscoveryMethod::Arp);
                assert_eq!(a.interface.as_deref(), Some("eth0"));
            }
            other => panic!("expected asset, got {other:?}"),
        }
    }

    #[test]
    fn repeated_arp_is_suppressed_then_allowed_again() {
        let mut obs = default_observer();
        let frame = arp_frame([192, 168, 1, 42], [0xaa; 6]);

        assert_eq!(obs.handle_frame(&frame, at(0)).len(), 1);
        assert_eq!(
            obs.handle_frame(&frame, at(10)).len(),
            0,
            "the same device must not be re-announced every few seconds"
        );
        assert_eq!(
            obs.handle_frame(&frame, at(DEFAULT_SUPPRESSION_SECS + 1))
                .len(),
            1,
            "after the window it is news again"
        );
    }

    #[test]
    fn disabled_modules_stay_silent() {
        let mut cfg = SensorConfig::default();
        cfg.passive.arp = false;
        let mut obs = observer_with(cfg);

        assert!(obs
            .handle_frame(&arp_frame([192, 168, 1, 42], [0xaa; 6]), at(0))
            .is_empty());
    }

    #[test]
    fn syn_ack_reveals_an_open_port_without_sending_anything() {
        let mut obs = default_observer();
        let frame = ipv4_frame(
            IP_PROTO_TCP,
            [192, 168, 1, 50],
            [192, 168, 1, 10],
            &tcp(443, 54321, crate::frame::TCP_SYN | crate::frame::TCP_ACK),
        );

        let events = obs.handle_frame(&frame, at(0));
        let service = events
            .iter()
            .find_map(|e| match e {
                Observation::Service(s) => Some(s),
                _ => None,
            })
            .expect("service observation");

        assert_eq!(service.ip, "192.168.1.50".parse::<IpAddr>().expect("ip"));
        assert_eq!(service.port, 443);
        assert_eq!(service.service.as_deref(), Some("https"));
        assert_eq!(
            service.method,
            DiscoveryMethod::PassiveFlow,
            "this must not be attributed to an active probe"
        );
    }

    #[test]
    fn plain_syn_does_not_claim_an_open_port() {
        let mut obs = default_observer();
        let frame = ipv4_frame(
            IP_PROTO_TCP,
            [192, 168, 1, 10],
            [192, 168, 1, 50],
            &tcp(54321, 443, crate::frame::TCP_SYN),
        );
        let events = obs.handle_frame(&frame, at(0));
        assert!(
            !events.iter().any(|e| matches!(e, Observation::Service(_))),
            "a connection attempt proves nothing about the target"
        );
    }

    #[test]
    fn dns_query_is_observed_with_client_and_server() {
        let mut obs = default_observer();
        let frame = ipv4_frame(
            IP_PROTO_UDP,
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            &udp(51000, DNS_PORT, &dns_query("example.com")),
        );

        let events = obs.handle_frame(&frame, at(0));
        let dns = events
            .iter()
            .find_map(|e| match e {
                Observation::Dns(d) => Some(d),
                _ => None,
            })
            .expect("dns observation");

        assert_eq!(dns.query_name, "example.com");
        assert!(!dns.query_name_hashed);
        assert_eq!(dns.client_ip, Some("192.168.1.10".parse().expect("ip")));
        assert_eq!(dns.server_ip, Some("192.168.1.1".parse().expect("ip")));
        assert_eq!(dns.query_type.as_deref(), Some("A"));
    }

    #[test]
    fn dns_observation_can_be_switched_off_entirely() {
        let mut cfg = SensorConfig::default();
        cfg.privacy.dns_observation = false;
        let mut obs = observer_with(cfg);

        let frame = ipv4_frame(
            IP_PROTO_UDP,
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            &udp(51000, DNS_PORT, &dns_query("private.example")),
        );
        let events = obs.handle_frame(&frame, at(0));
        assert!(!events.iter().any(|e| matches!(e, Observation::Dns(_))));
    }

    #[test]
    fn excluded_domains_are_never_reported() {
        let mut cfg = SensorConfig::default();
        cfg.privacy.dns_exclude_domains = vec!["bank.example".into()];
        let mut obs = observer_with(cfg);

        let excluded = ipv4_frame(
            IP_PROTO_UDP,
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            &udp(51000, DNS_PORT, &dns_query("login.bank.example")),
        );
        assert!(!obs
            .handle_frame(&excluded, at(0))
            .iter()
            .any(|e| matches!(e, Observation::Dns(_))));

        let allowed = ipv4_frame(
            IP_PROTO_UDP,
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            &udp(51001, DNS_PORT, &dns_query("example.com")),
        );
        assert!(obs
            .handle_frame(&allowed, at(0))
            .iter()
            .any(|e| matches!(e, Observation::Dns(_))));
    }

    #[test]
    fn domain_exclusion_matches_suffixes_not_substrings() {
        let excluded = vec!["bank.example".to_string()];
        assert!(is_excluded_domain("bank.example", &excluded));
        assert!(is_excluded_domain("login.bank.example", &excluded));
        assert!(
            !is_excluded_domain("notbank.example", &excluded),
            "substring matches would silently swallow unrelated domains"
        );
        assert!(!is_excluded_domain("bank.example.com", &excluded));
    }

    #[test]
    fn hashed_dns_names_are_marked_as_such() {
        let mut cfg = SensorConfig::default();
        cfg.privacy.hash_dns_names = true;
        let mut obs = observer_with(cfg);

        let frame = ipv4_frame(
            IP_PROTO_UDP,
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            &udp(51000, DNS_PORT, &dns_query("secret.example")),
        );
        let events = obs.handle_frame(&frame, at(0));
        let dns = events
            .iter()
            .find_map(|e| match e {
                Observation::Dns(d) => Some(d),
                _ => None,
            })
            .expect("dns observation");

        assert!(dns.query_name_hashed);
        assert!(!dns.query_name.contains("secret"));
        assert_eq!(dns.query_name, pseudonymize("secret.example"));
    }

    #[test]
    fn excluded_clients_are_not_observed_at_all() {
        let mut cfg = SensorConfig::default();
        cfg.privacy.exclude_clients = vec!["192.168.1.10/32".into()];
        let mut obs = observer_with(cfg);

        let frame = ipv4_frame(
            IP_PROTO_UDP,
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            &udp(51000, DNS_PORT, &dns_query("example.com")),
        );
        assert!(
            obs.handle_frame(&frame, at(0)).is_empty(),
            "an excluded client produces no telemetry whatsoever"
        );
        assert_eq!(obs.tracked_flows(), 0, "not even a flow record");
    }

    #[test]
    fn flows_are_aggregated_and_emitted_after_the_window() {
        let mut obs = default_observer();
        for i in 0..5 {
            let frame = ipv4_frame(
                IP_PROTO_TCP,
                [192, 168, 1, 10],
                [93, 184, 216, 34],
                &tcp(54321, 443, crate::frame::TCP_ACK),
            );
            obs.handle_frame(&frame, at(i));
        }

        assert_eq!(obs.tracked_flows(), 1);
        assert!(obs.expire(at(10)).is_empty(), "window still open");

        let expired = obs.expire(at(120));
        assert_eq!(expired.len(), 1);
        match &expired[0] {
            Observation::Flow(f) => {
                assert_eq!(f.packets, 5, "five packets became one observation");
                assert_eq!(
                    f.direction,
                    trapd_sensor_core::model::FlowDirection::Outbound
                );
            }
            other => panic!("expected flow, got {other:?}"),
        }
    }

    #[test]
    fn dhcp_ack_yields_asset_lease_and_server_relationship() {
        let mut dhcp = vec![0u8; 240];
        dhcp[0] = 2;
        dhcp[16..20].copy_from_slice(&[192, 168, 1, 77]);
        dhcp[28..34].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        dhcp[236..240].copy_from_slice(&0x6382_5363u32.to_be_bytes());
        dhcp.extend_from_slice(&[53, 1, 5]); // ACK
        dhcp.extend_from_slice(&[12, 6]);
        dhcp.extend_from_slice(b"laptop");
        dhcp.extend_from_slice(&[54, 4, 192, 168, 1, 1]);
        dhcp.push(255);

        let frame = ipv4_frame(
            IP_PROTO_UDP,
            [192, 168, 1, 1],
            [255, 255, 255, 255],
            &udp(DHCP_SERVER_PORT, DHCP_CLIENT_PORT, &dhcp),
        );

        let mut obs = default_observer();
        let events = obs.handle_frame(&frame, at(0));

        assert!(events.iter().any(|e| matches!(e, Observation::Dhcp(_))));
        let asset = events
            .iter()
            .find_map(|e| match e {
                Observation::Asset(a) => Some(a),
                _ => None,
            })
            .expect("asset from lease");
        assert_eq!(asset.hostname.as_deref(), Some("laptop"));
        assert_eq!(asset.method, DiscoveryMethod::Dhcp);

        let rel = events
            .iter()
            .find_map(|e| match e {
                Observation::Relationship(r) => Some(r),
                _ => None,
            })
            .expect("dhcp server relationship");
        assert_eq!(rel.edge_type, RelationshipType::DhcpServedBy);
        assert_eq!(rel.dest_node, "192.168.1.1");
    }

    #[test]
    fn ssdp_notify_identifies_the_device() {
        let notify = concat!(
            "NOTIFY * HTTP/1.1\r\n",
            "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n",
            "SERVER: Linux/4.9 UPnP/1.0 Samsung-TV/2.0\r\n",
            "LOCATION: http://192.168.1.60:8080/desc.xml\r\n\r\n"
        );
        let frame = ipv4_frame(
            IP_PROTO_UDP,
            [192, 168, 1, 60],
            [239, 255, 255, 250],
            &udp(SSDP_PORT, SSDP_PORT, notify.as_bytes()),
        );

        let mut obs = default_observer();
        let events = obs.handle_frame(&frame, at(0));

        assert!(events.iter().any(|e| matches!(e, Observation::Asset(_))));
        let rel = events
            .iter()
            .find_map(|e| match e {
                Observation::Relationship(r) => Some(r),
                _ => None,
            })
            .expect("service advertisement");
        assert_eq!(rel.edge_type, RelationshipType::AdvertisesService);
        assert_eq!(
            rel.attributes.get("server").map(String::as_str),
            Some("Linux/4.9 UPnP/1.0 Samsung-TV/2.0")
        );
        assert!(
            rel.attributes.contains_key("location"),
            "the URL is reported, never fetched"
        );
    }

    #[test]
    fn garbage_frames_are_ignored_without_panicking() {
        let mut obs = default_observer();
        for frame in [
            vec![],
            vec![0u8; 3],
            vec![0xffu8; 60],
            ethernet(ETHERTYPE_IPV4, &[0x45]),
            ethernet(ETHERTYPE_ARP, &[0x00, 0x01]),
            ipv4_frame(IP_PROTO_UDP, [1, 2, 3, 4], [5, 6, 7, 8], &[0xff, 0xfe]),
        ] {
            let _ = obs.handle_frame(&frame, at(0));
        }
    }

    #[test]
    fn drain_flushes_the_open_flow_window() {
        let mut obs = default_observer();
        obs.handle_frame(
            &ipv4_frame(
                IP_PROTO_TCP,
                [192, 168, 1, 10],
                [192, 168, 1, 20],
                &tcp(54321, 22, crate::frame::TCP_ACK),
            ),
            at(0),
        );
        assert_eq!(obs.drain().len(), 1);
        assert_eq!(obs.tracked_flows(), 0);
    }

    #[test]
    fn suppressor_resets_instead_of_growing_without_bound() {
        let mut s = Suppressor::new(300);
        for i in 0..MAX_SUPPRESSION_ENTRIES + 100 {
            s.allow(&format!("key-{i}"), at(0));
        }
        assert!(s.seen.len() <= MAX_SUPPRESSION_ENTRIES);
    }

    #[test]
    fn suppressor_prunes_expired_entries() {
        let mut s = Suppressor::new(60);
        s.allow("a", at(0));
        s.prune(at(30));
        assert_eq!(s.seen.len(), 1);
        s.prune(at(120));
        assert!(s.seen.is_empty());
    }
}
