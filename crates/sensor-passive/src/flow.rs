//! Flow-Aggregation.
//!
//! Der Sensor meldet keine Pakete, sondern Fenster. Statt je Paket ein Event zu
//! erzeugen, werden Bytes und Paketzahlen pro 5-Tupel gesammelt und erst nach
//! Ablauf des Fensters als *ein* [`FlowObservation`] abgegeben. Das ist der
//! Unterschied zwischen ein paar Events pro Minute und ein paar tausend pro
//! Sekunde — und es ist der Grund, warum der Sensor mit den angepeilten
//! Ressourcen auskommt.
//!
//! Ebenso wichtig: hier entsteht die Zusage "keine Payload". Ein Flow-Eintrag
//! kennt Adressen, Ports, Protokoll und Zähler. Was in der Verbindung
//! transportiert wurde, ist an dieser Stelle bereits verworfen.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use trapd_sensor_core::model::{FlowDirection, FlowObservation, TransportProtocol};

/// Ein Flow, richtungsnormalisiert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub protocol: TransportProtocol,
}

impl FlowKey {
    /// Ordnet die beiden Endpunkte, sodass Hin- und Rückrichtung denselben
    /// Schlüssel ergeben.
    ///
    /// Heuristik: der kleinere Port ist der Dienst. Das stimmt bei
    /// Client-Server-Verkehr fast immer und ist die einzige Zuordnung, die ohne
    /// Verbindungsverfolgung auskommt — echte Zustandsverfolgung würde
    /// Speicher kosten und uns dem Full-Capture näherbringen, das wir gerade
    /// vermeiden wollen.
    pub fn normalized(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: TransportProtocol,
    ) -> Self {
        let src_is_client = match src_port.cmp(&dst_port) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            // Gleiche Ports (z. B. mDNS 5353 ↔ 5353): nach IP ordnen, damit der
            // Schlüssel überhaupt stabil ist.
            std::cmp::Ordering::Equal => src_ip > dst_ip,
        };

        if src_is_client {
            Self {
                client_ip: src_ip,
                client_port: src_port,
                server_ip: dst_ip,
                server_port: dst_port,
                protocol,
            }
        } else {
            Self {
                client_ip: dst_ip,
                client_port: dst_port,
                server_ip: src_ip,
                server_port: src_port,
                protocol,
            }
        }
    }
}

#[derive(Debug, Clone)]
struct FlowState {
    bytes: u64,
    packets: u64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

pub struct FlowAggregator {
    flows: HashMap<FlowKey, FlowState>,
    window_secs: i64,
    max_flows: usize,
    /// Flows, die wegen der Kardinalitätsgrenze nicht angelegt wurden.
    skipped: u64,
}

impl FlowAggregator {
    pub fn new(window_secs: u64, max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            window_secs: window_secs.max(1) as i64,
            max_flows: max_flows.max(1),
            skipped: 0,
        }
    }

    /// Verbucht ein Paket.
    pub fn observe(&mut self, key: FlowKey, bytes: u64, now: DateTime<Utc>) {
        if let Some(state) = self.flows.get_mut(&key) {
            state.bytes += bytes;
            state.packets += 1;
            state.last_seen = now;
            return;
        }

        // Volle Tabelle: neue Flows werden verworfen, bestehende weitergezählt.
        // Bewusst so herum — ein bestehender Flow hat schon Historie, deren
        // Verlust einen halben Datensatz hinterlässt; ein noch unbekannter Flow
        // kostet nur sich selbst. Die Zahl wandert in den Heartbeat.
        if self.flows.len() >= self.max_flows {
            self.skipped += 1;
            return;
        }

        self.flows.insert(
            key,
            FlowState {
                bytes,
                packets: 1,
                first_seen: now,
                last_seen: now,
            },
        );
    }

    /// Gibt alle Flows ab, deren Fenster abgelaufen ist.
    pub fn expire(&mut self, now: DateTime<Utc>) -> Vec<FlowObservation> {
        let window = self.window_secs;
        let mut expired = Vec::new();

        self.flows.retain(|key, state| {
            if (now - state.last_seen).num_seconds() >= window {
                expired.push(to_observation(key, state));
                false
            } else {
                true
            }
        });

        expired
    }

    /// Gibt alles ab — für den Shutdown, damit das laufende Fenster nicht
    /// verloren geht.
    pub fn drain_all(&mut self) -> Vec<FlowObservation> {
        let out: Vec<FlowObservation> = self
            .flows
            .iter()
            .map(|(key, state)| to_observation(key, state))
            .collect();
        self.flows.clear();
        out
    }

    pub fn tracked_flows(&self) -> usize {
        self.flows.len()
    }

    pub fn skipped_flows(&self) -> u64 {
        self.skipped
    }
}

fn to_observation(key: &FlowKey, state: &FlowState) -> FlowObservation {
    FlowObservation {
        source_ip: key.client_ip,
        source_port: Some(key.client_port),
        dest_ip: key.server_ip,
        dest_port: Some(key.server_port),
        protocol: key.protocol,
        service: well_known_service(key.server_port, key.protocol).map(str::to_string),
        direction: classify_direction(key.client_ip, key.server_ip),
        bytes: state.bytes,
        packets: state.packets,
        duration_ms: (state.last_seen - state.first_seen)
            .num_milliseconds()
            .max(0) as u64,
        first_seen: state.first_seen.to_rfc3339(),
        last_seen: state.last_seen.to_rfc3339(),
    }
}

/// Grobe Richtungseinordnung anhand privater Adressbereiche.
///
/// Ohne Kenntnis der eigenen Subnetze ist das eine Heuristik — sie reicht für
/// die Frage "verlässt der Verkehr das Heimnetz?", die der Asset-Graph stellt.
/// Feinere Zonen (VLAN, DMZ) leitet das Backend aus den Subnetz-Beobachtungen
/// ab, wo es den Gesamtüberblick hat.
pub fn classify_direction(client: IpAddr, server: IpAddr) -> FlowDirection {
    match (is_local(client), is_local(server)) {
        (true, true) => FlowDirection::Lateral,
        (true, false) => FlowDirection::Outbound,
        (false, true) => FlowDirection::Inbound,
        // Weder noch: aus Sicht des Sensors durchlaufender Verkehr.
        (false, false) => FlowDirection::Lateral,
    }
}

fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || is_cgnat(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                // fc00::/7 (Unique Local) und fe80::/10 (Link Local)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// 100.64.0.0/10 — Carrier-Grade NAT. Taucht in Homelabs mit Tailscale und bei
/// manchen Providern auf und ist dort faktisch internes Netz.
fn is_cgnat(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..128).contains(&o[1])
}

/// Beschriftung für gängige Ports. Rein kosmetisch für das Dashboard — die
/// Erkennung eines Dienstes läuft über das Fingerprinting, nicht über eine
/// Portnummer.
pub fn well_known_service(port: u16, protocol: TransportProtocol) -> Option<&'static str> {
    match (protocol, port) {
        (TransportProtocol::Tcp, 22) => Some("ssh"),
        (TransportProtocol::Tcp, 25) => Some("smtp"),
        (TransportProtocol::Tcp, 80) => Some("http"),
        (TransportProtocol::Tcp, 143) => Some("imap"),
        (TransportProtocol::Tcp, 443) => Some("https"),
        (TransportProtocol::Tcp, 445) => Some("smb"),
        (TransportProtocol::Tcp, 631) => Some("ipp"),
        (TransportProtocol::Tcp, 3306) => Some("mysql"),
        (TransportProtocol::Tcp, 5432) => Some("postgres"),
        (TransportProtocol::Tcp, 8080) => Some("http-alt"),
        (TransportProtocol::Tcp, 9100) => Some("jetdirect"),
        (TransportProtocol::Udp, 53) | (TransportProtocol::Tcp, 53) => Some("dns"),
        (TransportProtocol::Udp, 67) | (TransportProtocol::Udp, 68) => Some("dhcp"),
        (TransportProtocol::Udp, 123) => Some("ntp"),
        (TransportProtocol::Udp, 161) => Some("snmp"),
        (TransportProtocol::Udp, 1900) => Some("ssdp"),
        (TransportProtocol::Udp, 5353) => Some("mdns"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip")
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("timestamp")
    }

    #[test]
    fn both_directions_map_to_one_flow() {
        let forward = FlowKey::normalized(
            ip("192.168.1.10"),
            54321,
            ip("192.168.1.20"),
            443,
            TransportProtocol::Tcp,
        );
        let reverse = FlowKey::normalized(
            ip("192.168.1.20"),
            443,
            ip("192.168.1.10"),
            54321,
            TransportProtocol::Tcp,
        );

        assert_eq!(forward, reverse, "a flow is one flow, not two half-flows");
        assert_eq!(forward.server_port, 443, "the lower port is the service");
        assert_eq!(forward.client_ip, ip("192.168.1.10"));
    }

    #[test]
    fn equal_ports_still_produce_a_stable_key() {
        let a = FlowKey::normalized(
            ip("192.168.1.10"),
            5353,
            ip("192.168.1.20"),
            5353,
            TransportProtocol::Udp,
        );
        let b = FlowKey::normalized(
            ip("192.168.1.20"),
            5353,
            ip("192.168.1.10"),
            5353,
            TransportProtocol::Udp,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn packets_accumulate_into_one_observation() {
        let mut agg = FlowAggregator::new(60, 1000);
        let key = FlowKey::normalized(
            ip("192.168.1.10"),
            50000,
            ip("192.168.1.1"),
            53,
            TransportProtocol::Udp,
        );

        agg.observe(key, 100, at(0));
        agg.observe(key, 250, at(5));
        agg.observe(key, 150, at(10));
        assert_eq!(agg.tracked_flows(), 1);

        let expired = agg.expire(at(90));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].bytes, 500);
        assert_eq!(expired[0].packets, 3);
        assert_eq!(expired[0].duration_ms, 10_000);
        assert_eq!(expired[0].service.as_deref(), Some("dns"));
    }

    #[test]
    fn active_flows_are_not_expired_early() {
        let mut agg = FlowAggregator::new(60, 1000);
        let key = FlowKey::normalized(
            ip("10.0.0.1"),
            40000,
            ip("10.0.0.2"),
            22,
            TransportProtocol::Tcp,
        );

        agg.observe(key, 100, at(0));
        assert!(agg.expire(at(30)).is_empty(), "window has not elapsed");

        agg.observe(key, 100, at(50));
        assert!(
            agg.expire(at(80)).is_empty(),
            "traffic refreshes the window instead of ending it"
        );
        assert_eq!(agg.expire(at(120)).len(), 1);
    }

    #[test]
    fn cardinality_limit_protects_existing_flows() {
        let mut agg = FlowAggregator::new(60, 2);
        let a = FlowKey::normalized(
            ip("10.0.0.1"),
            5000,
            ip("10.0.0.9"),
            80,
            TransportProtocol::Tcp,
        );
        let b = FlowKey::normalized(
            ip("10.0.0.2"),
            5000,
            ip("10.0.0.9"),
            80,
            TransportProtocol::Tcp,
        );
        let c = FlowKey::normalized(
            ip("10.0.0.3"),
            5000,
            ip("10.0.0.9"),
            80,
            TransportProtocol::Tcp,
        );

        agg.observe(a, 10, at(0));
        agg.observe(b, 10, at(0));
        agg.observe(c, 10, at(0)); // über der Grenze
        agg.observe(a, 90, at(1)); // bestehender Flow zählt weiter

        assert_eq!(agg.tracked_flows(), 2);
        assert_eq!(agg.skipped_flows(), 1);

        let expired = agg.expire(at(120));
        let total: u64 = expired.iter().map(|f| f.bytes).sum();
        assert_eq!(total, 110, "existing flows keep counting");
    }

    #[test]
    fn drain_all_empties_the_table() {
        let mut agg = FlowAggregator::new(60, 1000);
        agg.observe(
            FlowKey::normalized(
                ip("10.0.0.1"),
                5000,
                ip("10.0.0.2"),
                443,
                TransportProtocol::Tcp,
            ),
            42,
            at(0),
        );

        let drained = agg.drain_all();
        assert_eq!(drained.len(), 1);
        assert_eq!(agg.tracked_flows(), 0, "shutdown must not strand a window");
    }

    #[test]
    fn direction_reflects_where_traffic_goes() {
        assert_eq!(
            classify_direction(ip("192.168.1.10"), ip("192.168.1.20")),
            FlowDirection::Lateral
        );
        assert_eq!(
            classify_direction(ip("192.168.1.10"), ip("93.184.216.34")),
            FlowDirection::Outbound
        );
        assert_eq!(
            classify_direction(ip("93.184.216.34"), ip("192.168.1.10")),
            FlowDirection::Inbound
        );
    }

    #[test]
    fn local_ranges_cover_rfc1918_cgnat_and_ipv6_ula() {
        assert!(is_local(ip("10.1.2.3")));
        assert!(is_local(ip("172.16.0.1")));
        assert!(is_local(ip("192.168.0.1")));
        assert!(is_local(ip("169.254.1.1")), "link-local");
        assert!(is_local(ip("100.64.0.1")), "cgnat / tailscale");
        assert!(is_local(ip("fd00::1")), "ipv6 unique local");
        assert!(is_local(ip("fe80::1")), "ipv6 link local");

        assert!(!is_local(ip("8.8.8.8")));
        assert!(!is_local(ip("2606:4700::1")));
        assert!(!is_local(ip("100.128.0.1")), "just outside cgnat");
    }

    #[test]
    fn unknown_ports_get_no_service_label() {
        assert_eq!(well_known_service(51820, TransportProtocol::Udp), None);
        assert_eq!(
            well_known_service(443, TransportProtocol::Tcp),
            Some("https")
        );
        assert_eq!(
            well_known_service(443, TransportProtocol::Udp),
            None,
            "protocol matters, not just the number"
        );
    }
}
