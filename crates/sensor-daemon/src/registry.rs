//! Das Gedächtnis des Sensors zwischen zwei Paketen.
//!
//! Ein Fingerprint entsteht selten aus einem einzelnen Paket. Die MAC kommt aus
//! ARP, der Hostname Minuten später aus DHCP, die Dienstliste irgendwann aus
//! mDNS. Diese Registry sammelt diese Bruchstücke je Gerät und lässt die
//! Fingerprint-Engine erst darüber laufen, wenn sich etwas geändert hat.
//!
//! Zwei Dinge hält sie klein: eine Obergrenze für die Zahl der Geräte (ein
//! Sensor an einem Uplink sieht sonst das halbe Internet) und ein Verfallsdatum
//! für Einträge, die lange still sind.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use trapd_sensor_core::model::{FingerprintObservation, Observation};
use trapd_sensor_fingerprint::{DeviceSignals, FingerprintEngine};

/// Schlüssel eines Geräts. Die MAC ist die belastbarere Identität — IP-Adressen
/// wandern per DHCP, MACs bleiben (von Randomisierung abgesehen).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DeviceKey {
    Mac(String),
    Ip(IpAddr),
}

struct Entry {
    signals: DeviceSignals,
    last_seen: DateTime<Utc>,
    /// Hat sich seit der letzten Auswertung etwas geändert?
    dirty: bool,
    /// Zuletzt gemeldete Zuversicht — verhindert, dass dieselbe Aussage
    /// wieder und wieder rausgeht.
    last_confidence: f32,
}

pub struct DeviceRegistry {
    devices: HashMap<DeviceKey, Entry>,
    engine: FingerprintEngine,
    max_devices: usize,
    ttl_secs: i64,
}

impl DeviceRegistry {
    pub fn new(engine: FingerprintEngine, max_devices: usize, ttl_secs: i64) -> Self {
        Self {
            devices: HashMap::new(),
            engine,
            max_devices: max_devices.max(1),
            ttl_secs,
        }
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Verbucht eine Beobachtung. Nicht jede trägt etwas zum Fingerprint bei —
    /// Flows und DNS-Abfragen etwa sagen nichts über das Gerät selbst aus.
    pub fn observe(&mut self, observation: &Observation, now: DateTime<Utc>) {
        match observation {
            Observation::Asset(asset) => {
                let Some(key) = key_for(asset.mac.as_deref(), asset.ip) else {
                    return;
                };
                let Some(entry) = self.entry(key, asset.ip, asset.mac.clone(), now) else {
                    return;
                };
                if entry.signals.hostname.is_none() {
                    if let Some(hostname) = &asset.hostname {
                        entry.signals.hostname = Some(hostname.clone());
                        entry.dirty = true;
                    }
                }
            }
            Observation::Dhcp(dhcp) => {
                let Some(entry) = self.entry(
                    DeviceKey::Mac(dhcp.mac.clone()),
                    dhcp.assigned_ip,
                    Some(dhcp.mac.clone()),
                    now,
                ) else {
                    return;
                };
                if let Some(prl) = &dhcp.param_request_list {
                    if entry.signals.dhcp_param_request_list.as_deref() != Some(prl.as_str()) {
                        entry.signals.dhcp_param_request_list = Some(prl.clone());
                        entry.dirty = true;
                    }
                }
                if let Some(class) = &dhcp.vendor_class {
                    if entry.signals.dhcp_vendor_class.is_none() {
                        entry.signals.dhcp_vendor_class = Some(class.clone());
                        entry.dirty = true;
                    }
                }
                if let Some(hostname) = &dhcp.hostname {
                    if entry.signals.hostname.is_none() {
                        entry.signals.hostname = Some(hostname.clone());
                        entry.dirty = true;
                    }
                }
            }
            Observation::Service(service) => {
                let Some(entry) =
                    self.entry(DeviceKey::Ip(service.ip), Some(service.ip), None, now)
                else {
                    return;
                };
                if let Some(banner) = &service.banner {
                    let before = entry.signals.banners.len();
                    entry.signals.add_banner(banner.clone());
                    if entry.signals.banners.len() != before {
                        entry.dirty = true;
                    }
                }
            }
            Observation::Relationship(rel) => {
                use trapd_sensor_core::model::RelationshipType;
                if rel.edge_type != RelationshipType::AdvertisesService {
                    return;
                }
                let Some(ip) = rel.source_ip else {
                    return;
                };
                let Some(entry) = self.entry(DeviceKey::Ip(ip), Some(ip), None, now) else {
                    return;
                };

                // SSDP liefert seine Angaben über die Attribute, mDNS über den
                // Zielknoten der Kante.
                if let Some(device_type) = rel.attributes.get("device_type") {
                    if entry.signals.ssdp_device_type.is_none() {
                        entry.signals.ssdp_device_type = Some(device_type.clone());
                        entry.dirty = true;
                    }
                    if let Some(server) = rel.attributes.get("server") {
                        entry.signals.ssdp_server = Some(server.clone());
                    }
                } else {
                    let before = entry.signals.mdns_services.len();
                    entry.signals.add_mdns_service(rel.dest_node.clone());
                    if entry.signals.mdns_services.len() != before {
                        entry.dirty = true;
                    }
                }
            }
            // Flows, DNS-Abfragen, Heartbeats und Statusmeldungen sagen nichts
            // über die Beschaffenheit eines Geräts aus.
            _ => {}
        }
    }

    /// Wertet alle veränderten Geräte aus.
    ///
    /// Gemeldet wird nur, was neu oder deutlich sicherer ist als zuletzt —
    /// sonst bestünde die Telemetrie aus demselben Fingerprint im Minutentakt.
    pub fn evaluate_dirty(&mut self) -> Vec<FingerprintObservation> {
        let mut out = Vec::new();
        for entry in self.devices.values_mut() {
            if !entry.dirty {
                continue;
            }
            entry.dirty = false;

            let Some(fingerprint) = self.engine.evaluate(&entry.signals) else {
                continue;
            };
            if fingerprint.confidence <= entry.last_confidence + f32::EPSILON
                && entry.last_confidence > 0.0
            {
                continue;
            }
            entry.last_confidence = fingerprint.confidence;
            out.push(fingerprint);
        }
        out
    }

    /// Entfernt Geräte, die lange nichts mehr von sich hören ließen.
    pub fn prune(&mut self, now: DateTime<Utc>) -> usize {
        let ttl = self.ttl_secs;
        let before = self.devices.len();
        self.devices
            .retain(|_, entry| (now - entry.last_seen).num_seconds() < ttl);
        before - self.devices.len()
    }

    fn entry(
        &mut self,
        key: DeviceKey,
        ip: Option<IpAddr>,
        mac: Option<String>,
        now: DateTime<Utc>,
    ) -> Option<&mut Entry> {
        if !self.devices.contains_key(&key) {
            // Volle Registry: erst aufräumen, dann notfalls ablehnen. Ein
            // unbegrenzt wachsendes Gerätegedächtnis wäre auf einem Raspberry Pi
            // der erste Grund für einen OOM-Kill.
            if self.devices.len() >= self.max_devices {
                self.prune(now);
            }
            if self.devices.len() >= self.max_devices {
                tracing::warn!(
                    max_devices = self.max_devices,
                    "device registry is full — not tracking further devices"
                );
                return None;
            }
            self.devices.insert(
                key.clone(),
                Entry {
                    signals: DeviceSignals::new(ip, mac.clone()),
                    last_seen: now,
                    dirty: true,
                    last_confidence: 0.0,
                },
            );
        }

        let entry = self.devices.get_mut(&key)?;
        entry.last_seen = now;
        if entry.signals.ip.is_none() && ip.is_some() {
            entry.signals.ip = ip;
            entry.dirty = true;
        }
        if entry.signals.mac.is_none() && mac.is_some() {
            entry.signals.mac = mac;
            entry.dirty = true;
        }
        Some(entry)
    }
}

fn key_for(mac: Option<&str>, ip: Option<IpAddr>) -> Option<DeviceKey> {
    if let Some(mac) = mac {
        return Some(DeviceKey::Mac(mac.to_string()));
    }
    ip.map(DeviceKey::Ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trapd_sensor_core::model::{
        AssetObservation, DhcpObservation, DiscoveryMethod, RelationshipObservation,
        RelationshipType, ServiceObservation, TransportProtocol,
    };

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("timestamp")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip")
    }

    fn registry() -> DeviceRegistry {
        DeviceRegistry::new(FingerprintEngine::with_builtin_oui(), 1000, 3600)
    }

    fn asset(mac: Option<&str>, ip_addr: Option<&str>, hostname: Option<&str>) -> Observation {
        Observation::Asset(AssetObservation {
            ip: ip_addr.map(ip),
            mac: mac.map(str::to_string),
            hostname: hostname.map(str::to_string),
            vlan_id: None,
            subnet: None,
            method: DiscoveryMethod::Arp,
            interface: Some("eth0".into()),
        })
    }

    #[test]
    fn signals_from_different_packets_accumulate_into_one_device() {
        let mut reg = registry();

        reg.observe(
            &asset(Some("b8:27:eb:11:22:33"), Some("192.168.1.5"), None),
            at(0),
        );
        reg.observe(
            &Observation::Dhcp(DhcpObservation {
                mac: "b8:27:eb:11:22:33".into(),
                assigned_ip: Some(ip("192.168.1.5")),
                server_ip: None,
                hostname: Some("pi-hole".into()),
                vendor_class: None,
                param_request_list: Some("1,28,2,3,15,6,119,12,44,47,26,121,42".into()),
                message_type: "ack".into(),
                lease_seconds: Some(3600),
            }),
            at(30),
        );

        assert_eq!(reg.len(), 1, "MAC and DHCP describe the same device");

        let fingerprints = reg.evaluate_dirty();
        assert_eq!(fingerprints.len(), 1);
        let fp = &fingerprints[0];
        assert_eq!(fp.vendor.as_deref(), Some("Raspberry Pi Foundation"));
        assert_eq!(fp.os_family.as_deref(), Some("Linux"));
    }

    #[test]
    fn unchanged_devices_are_not_re_reported() {
        let mut reg = registry();
        reg.observe(
            &asset(Some("00:50:56:aa:bb:cc"), Some("192.168.1.60"), None),
            at(0),
        );

        assert_eq!(reg.evaluate_dirty().len(), 1, "first evaluation reports");
        assert!(
            reg.evaluate_dirty().is_empty(),
            "nothing changed, nothing to say"
        );

        // Dieselbe Beobachtung erneut ändert nichts am Wissensstand.
        reg.observe(
            &asset(Some("00:50:56:aa:bb:cc"), Some("192.168.1.60"), None),
            at(60),
        );
        assert!(reg.evaluate_dirty().is_empty());
    }

    #[test]
    fn a_stronger_fingerprint_is_reported_again() {
        let mut reg = registry();
        reg.observe(&asset(None, Some("192.168.1.20"), None), at(0));
        let first = reg.evaluate_dirty();
        assert!(first.is_empty(), "a bare IP says nothing");

        reg.observe(
            &Observation::Relationship(RelationshipObservation {
                source_node: "192.168.1.20".into(),
                dest_node: "printer._ipp._tcp.local".into(),
                source_ip: Some(ip("192.168.1.20")),
                dest_ip: None,
                edge_type: RelationshipType::AdvertisesService,
                observed_count: 1,
                attributes: Default::default(),
            }),
            at(10),
        );

        let second = reg.evaluate_dirty();
        assert_eq!(second.len(), 1);
        assert_eq!(
            second[0].device_type.as_deref(),
            Some(trapd_sensor_fingerprint::device_type::PRINTER)
        );
    }

    #[test]
    fn ssdp_attributes_feed_the_fingerprint() {
        let mut reg = registry();
        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert(
            "device_type".to_string(),
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_string(),
        );
        attributes.insert("server".to_string(), "AVM FRITZ!Box UPnP/1.0".to_string());

        reg.observe(
            &Observation::Relationship(RelationshipObservation {
                source_node: "192.168.1.1".into(),
                dest_node: "urn:schemas-upnp-org:device:InternetGatewayDevice:1".into(),
                source_ip: Some(ip("192.168.1.1")),
                dest_ip: None,
                edge_type: RelationshipType::AdvertisesService,
                observed_count: 1,
                attributes,
            }),
            at(0),
        );

        let fps = reg.evaluate_dirty();
        assert_eq!(fps.len(), 1);
        assert_eq!(
            fps[0].device_type.as_deref(),
            Some(trapd_sensor_fingerprint::device_type::ROUTER)
        );
        assert_eq!(fps[0].model.as_deref(), Some("AVM FRITZ!Box UPnP/1.0"));
    }

    #[test]
    fn banners_from_active_probes_are_collected() {
        let mut reg = registry();
        reg.observe(
            &Observation::Service(ServiceObservation {
                ip: ip("192.168.1.7"),
                port: 22,
                protocol: TransportProtocol::Tcp,
                service: Some("ssh".into()),
                banner: Some("SSH-2.0-dropbear_2022.83".into()),
                method: DiscoveryMethod::Banner,
            }),
            at(0),
        );

        let fps = reg.evaluate_dirty();
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].os_family.as_deref(), Some("Linux (embedded)"));
    }

    #[test]
    fn flows_and_dns_do_not_create_devices() {
        use trapd_sensor_core::model::{DnsObservation, FlowDirection, FlowObservation};
        let mut reg = registry();

        reg.observe(
            &Observation::Flow(FlowObservation {
                source_ip: ip("192.168.1.10"),
                source_port: Some(1234),
                dest_ip: ip("8.8.8.8"),
                dest_port: Some(443),
                protocol: TransportProtocol::Tcp,
                service: None,
                direction: FlowDirection::Outbound,
                bytes: 100,
                packets: 2,
                duration_ms: 10,
                first_seen: "2026-01-01T00:00:00Z".into(),
                last_seen: "2026-01-01T00:00:01Z".into(),
            }),
            at(0),
        );
        reg.observe(
            &Observation::Dns(DnsObservation {
                query_name: "example.com".into(),
                query_name_hashed: false,
                query_type: Some("A".into()),
                response_code: None,
                client_ip: Some(ip("192.168.1.10")),
                server_ip: Some(ip("192.168.1.1")),
                resolved_ips: vec![],
                answer_count: 0,
                is_nxdomain: false,
            }),
            at(0),
        );

        assert_eq!(
            reg.len(),
            0,
            "traffic metadata says nothing about what a device is"
        );
    }

    #[test]
    fn stale_devices_are_pruned() {
        let mut reg = DeviceRegistry::new(FingerprintEngine::with_builtin_oui(), 1000, 300);
        reg.observe(
            &asset(Some("aa:bb:cc:dd:ee:ff"), Some("10.0.0.1"), None),
            at(0),
        );
        assert_eq!(reg.len(), 1);

        assert_eq!(reg.prune(at(100)), 0, "still fresh");
        assert_eq!(reg.prune(at(500)), 1, "expired");
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn the_registry_refuses_to_grow_without_bound() {
        let mut reg = DeviceRegistry::new(FingerprintEngine::with_builtin_oui(), 3, 3600);
        for i in 0..50u8 {
            reg.observe(
                &asset(
                    Some(&format!("aa:bb:cc:dd:ee:{i:02x}")),
                    Some(&format!("10.0.0.{i}")),
                    None,
                ),
                at(0),
            );
        }
        assert!(
            reg.len() <= 3,
            "a sensor on an uplink must not try to remember the internet"
        );
    }

    #[test]
    fn devices_are_keyed_by_mac_when_available() {
        let mut reg = registry();
        // Dasselbe Gerät, zwei IPs (DHCP-Wechsel).
        reg.observe(
            &asset(Some("aa:bb:cc:11:22:33"), Some("192.168.1.10"), None),
            at(0),
        );
        reg.observe(
            &asset(Some("aa:bb:cc:11:22:33"), Some("192.168.1.11"), None),
            at(60),
        );

        assert_eq!(
            reg.len(),
            1,
            "a DHCP change does not create a second device"
        );
    }
}
