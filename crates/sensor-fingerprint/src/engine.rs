//! Die Aggregation: aus Einzelsignalen wird ein Fingerprint.
//!
//! Der Sensor sammelt über die Zeit [`DeviceSignals`] zu einem Gerät — ein
//! ARP-Paket hier, eine DHCP-Anfrage dort, später eine mDNS-Ankündigung. Erst
//! wenn genug beisammen ist, entsteht daraus eine Aussage.
//!
//! Zwei Regeln bestimmen das Ergebnis:
//!
//! * **Keine Einzelquelle entscheidet.** Das stärkste Signal setzt den Wert, die
//!   übrigen bestätigen oder widersprechen ihm. Bestätigung hebt die
//!   Zuversicht, Widerspruch senkt sie.
//! * **Jede Aussage trägt ihre Belege mit.** Ein Fingerprint ohne `evidence` ist
//!   im Dashboard nicht überprüfbar und damit wertlos — der Analyst muss sehen
//!   können, *warum* dort "Drucker" steht.

use std::collections::BTreeMap;
use std::net::IpAddr;

use trapd_sensor_core::model::{
    Confidence, DiscoveryMethod, FingerprintEvidence, FingerprintObservation,
};

use crate::oui::OuiDatabase;
use crate::signature::{
    match_contains, BANNER_HINTS, DHCP_FINGERPRINTS, MDNS_SERVICE_TYPES, SSDP_DEVICE_TYPES,
    VENDOR_CLASS_HINTS, VENDOR_DEVICE_TYPES,
};

/// Unterhalb dieser Zuversicht wird kein Fingerprint gemeldet. Lieber kein
/// Gerätetyp als ein falscher.
pub const MIN_REPORTABLE_CONFIDENCE: Confidence = 0.35;

/// Alles, was der Sensor über ein Gerät gesammelt hat.
#[derive(Debug, Clone, Default)]
pub struct DeviceSignals {
    pub ip: Option<IpAddr>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    /// DHCP Option 55.
    pub dhcp_param_request_list: Option<String>,
    /// DHCP Option 60.
    pub dhcp_vendor_class: Option<String>,
    /// Beworbene mDNS-Dienste.
    pub mdns_services: Vec<String>,
    /// UPnP-`deviceType`.
    pub ssdp_device_type: Option<String>,
    /// SSDP-`SERVER`-Kopfzeile.
    pub ssdp_server: Option<String>,
    /// Banner offener Dienste (nur im aktiven Modus gefüllt).
    pub banners: Vec<String>,
    /// SNMP `sysDescr`.
    pub snmp_sys_descr: Option<String>,
}

impl DeviceSignals {
    pub fn new(ip: Option<IpAddr>, mac: Option<String>) -> Self {
        Self {
            ip,
            mac,
            ..Default::default()
        }
    }

    /// Gibt es überhaupt etwas auszuwerten?
    pub fn is_empty(&self) -> bool {
        self.mac.is_none()
            && self.dhcp_param_request_list.is_none()
            && self.dhcp_vendor_class.is_none()
            && self.mdns_services.is_empty()
            && self.ssdp_device_type.is_none()
            && self.ssdp_server.is_none()
            && self.banners.is_empty()
            && self.snmp_sys_descr.is_none()
    }

    pub fn add_mdns_service(&mut self, service: impl Into<String>) {
        let service = service.into();
        if !self.mdns_services.contains(&service) {
            self.mdns_services.push(service);
        }
    }

    pub fn add_banner(&mut self, banner: impl Into<String>) {
        let banner = banner.into();
        if !self.banners.contains(&banner) {
            self.banners.push(banner);
        }
    }
}

/// Ein einzelnes gewichtetes Votum.
#[derive(Debug, Clone)]
struct Vote {
    value: String,
    weight: f32,
    evidence: FingerprintEvidence,
}

pub struct FingerprintEngine {
    oui: OuiDatabase,
}

impl FingerprintEngine {
    pub fn new(oui: OuiDatabase) -> Self {
        Self { oui }
    }

    pub fn with_builtin_oui() -> Self {
        Self::new(OuiDatabase::builtin())
    }

    /// Wertet die gesammelten Signale aus.
    ///
    /// `None`, wenn nichts Belastbares zusammenkommt — der Normalfall bei einem
    /// Gerät, von dem bislang nur ein ARP-Paket vorliegt.
    pub fn evaluate(&self, signals: &DeviceSignals) -> Option<FingerprintObservation> {
        if signals.is_empty() {
            return None;
        }

        let mut evidence = Vec::new();
        let mut device_votes: Vec<Vote> = Vec::new();
        let mut os_votes: Vec<Vote> = Vec::new();
        let mut vendor: Option<String> = None;

        // --- Stufe 1: MAC-OUI (passiv, sehr zuverlässig) ---
        if let Some(mac) = &signals.mac {
            if let Some(found) = self.oui.lookup(mac) {
                vendor = Some(found.to_string());
                evidence.push(FingerprintEvidence {
                    method: DiscoveryMethod::Arp,
                    signal: "mac_oui".into(),
                    value: found.to_string(),
                    weight: 0.9,
                });

                if let Some((kind, weight)) = VENDOR_DEVICE_TYPES
                    .iter()
                    .find(|(v, _, _)| *v == found)
                    .map(|(_, k, w)| (*k, *w))
                {
                    device_votes.push(Vote {
                        value: kind.to_string(),
                        weight,
                        evidence: FingerprintEvidence {
                            method: DiscoveryMethod::Arp,
                            signal: "vendor_device_type".into(),
                            value: kind.to_string(),
                            weight,
                        },
                    });
                }
            } else if OuiDatabase::is_locally_administered(mac) {
                // Eine erfundene MAC ist selbst eine Information: Container,
                // VPN oder ein Gerät mit Adressrandomisierung.
                evidence.push(FingerprintEvidence {
                    method: DiscoveryMethod::Arp,
                    signal: "mac_locally_administered".into(),
                    value: "true".into(),
                    weight: 0.3,
                });
            }
        }

        // --- Stufe 1: DHCP-Fingerprint (passiv, zuverlässig für den Stack) ---
        if let Some(prl) = &signals.dhcp_param_request_list {
            if let Some((os, weight)) = DHCP_FINGERPRINTS
                .iter()
                .find(|(sig, _, _)| *sig == prl)
                .map(|(_, os, w)| (*os, *w))
            {
                os_votes.push(Vote {
                    value: os.to_string(),
                    weight,
                    evidence: FingerprintEvidence {
                        method: DiscoveryMethod::Dhcp,
                        signal: "dhcp_option55".into(),
                        value: os.to_string(),
                        weight,
                    },
                });
            } else {
                // Unbekannte Signatur: als Beleg festhalten, aber nichts
                // behaupten. So wächst die Tabelle aus echten Daten statt aus
                // Vermutungen.
                evidence.push(FingerprintEvidence {
                    method: DiscoveryMethod::Dhcp,
                    signal: "dhcp_option55_unknown".into(),
                    value: prl.clone(),
                    weight: 0.0,
                });
            }
        }

        if let Some(class) = &signals.dhcp_vendor_class {
            let lower = class.to_ascii_lowercase();
            if let Some((os, kind, weight)) = VENDOR_CLASS_HINTS
                .iter()
                .find(|(needle, _, _, _)| lower.contains(needle))
                .map(|(_, os, kind, w)| (*os, *kind, *w))
            {
                if !os.is_empty() {
                    os_votes.push(Vote {
                        value: os.to_string(),
                        weight,
                        evidence: FingerprintEvidence {
                            method: DiscoveryMethod::Dhcp,
                            signal: "dhcp_vendor_class".into(),
                            value: class.clone(),
                            weight,
                        },
                    });
                }
                device_votes.push(Vote {
                    value: kind.to_string(),
                    weight,
                    evidence: FingerprintEvidence {
                        method: DiscoveryMethod::Dhcp,
                        signal: "dhcp_vendor_class".into(),
                        value: class.clone(),
                        weight,
                    },
                });
            }
        }

        // --- Stufe 2: mDNS (das Gerät sagt selbst, was es kann) ---
        for service in &signals.mdns_services {
            if let Some((kind, weight)) = match_contains(service, MDNS_SERVICE_TYPES) {
                device_votes.push(Vote {
                    value: kind.to_string(),
                    weight,
                    evidence: FingerprintEvidence {
                        method: DiscoveryMethod::Mdns,
                        signal: "mdns_service".into(),
                        value: service.clone(),
                        weight,
                    },
                });
            }
        }

        // --- Stufe 2: SSDP ---
        if let Some(urn) = &signals.ssdp_device_type {
            if let Some((kind, weight)) = match_contains(urn, SSDP_DEVICE_TYPES) {
                device_votes.push(Vote {
                    value: kind.to_string(),
                    weight,
                    evidence: FingerprintEvidence {
                        method: DiscoveryMethod::Ssdp,
                        signal: "ssdp_device_type".into(),
                        value: urn.clone(),
                        weight,
                    },
                });
            }
        }
        if let Some(server) = &signals.ssdp_server {
            evidence.push(FingerprintEvidence {
                method: DiscoveryMethod::Ssdp,
                signal: "ssdp_server".into(),
                value: server.clone(),
                weight: 0.4,
            });
        }

        // --- Stufe 3: Banner und SNMP (nur aktiv erhoben) ---
        for banner in &signals.banners {
            if let Some((os, weight)) = match_contains(banner, BANNER_HINTS) {
                os_votes.push(Vote {
                    value: os.to_string(),
                    weight,
                    evidence: FingerprintEvidence {
                        method: DiscoveryMethod::Banner,
                        signal: "service_banner".into(),
                        value: banner.clone(),
                        weight,
                    },
                });
            }
        }
        if let Some(descr) = &signals.snmp_sys_descr {
            evidence.push(FingerprintEvidence {
                method: DiscoveryMethod::Snmp,
                signal: "snmp_sys_descr".into(),
                value: descr.chars().take(200).collect(),
                weight: 0.7,
            });
        }

        let (device_type, device_confidence) = resolve(&mut evidence, device_votes);
        let (os_family, os_confidence) = resolve(&mut evidence, os_votes);

        // Gesamt-Zuversicht: das stärkste Einzelergebnis, angehoben durch den
        // Hersteller, wenn er bekannt ist.
        let mut confidence = device_confidence.max(os_confidence);
        if vendor.is_some() {
            confidence = (confidence + 0.1).min(1.0);
        }

        // Gemeldet wird nur, wenn mindestens *eine* Schlussfolgerung
        // herausgekommen ist. Belege ohne Ergebnis — etwa eine unbekannte
        // DHCP-Signatur oder eine randomisierte MAC — sind für sich genommen
        // keine Beobachtung, sondern Rauschen; sie fahren mit, sobald es etwas
        // zu berichten gibt.
        if device_type.is_none() && os_family.is_none() && vendor.is_none() {
            return None;
        }
        if confidence < MIN_REPORTABLE_CONFIDENCE && device_type.is_some() {
            // Zu dünn für eine Typaussage — Hersteller darf trotzdem stehen.
            return Some(FingerprintObservation {
                ip: signals.ip,
                mac: signals.mac.clone(),
                vendor,
                device_type: None,
                model: None,
                os_family,
                confidence,
                evidence,
            });
        }

        Some(FingerprintObservation {
            ip: signals.ip,
            mac: signals.mac.clone(),
            vendor,
            device_type,
            model: signals.ssdp_server.clone(),
            os_family,
            confidence,
            evidence,
        })
    }
}

/// Wertet die Stimmen einer Kategorie aus.
///
/// Mehrere Quellen, die dasselbe sagen, verstärken sich (aber gedeckelt);
/// widersprechende Quellen dämpfen das Ergebnis. So bekommt ein Gerät, bei dem
/// mDNS "Drucker" und der Hersteller "NAS" nahelegt, eine sichtbar niedrigere
/// Zuversicht statt einer willkürlichen Entscheidung.
fn resolve(evidence: &mut Vec<FingerprintEvidence>, votes: Vec<Vote>) -> (Option<String>, f32) {
    if votes.is_empty() {
        return (None, 0.0);
    }

    let mut totals: BTreeMap<String, f32> = BTreeMap::new();
    let mut best_single: BTreeMap<String, f32> = BTreeMap::new();
    for vote in &votes {
        *totals.entry(vote.value.clone()).or_insert(0.0) += vote.weight;
        let slot = best_single.entry(vote.value.clone()).or_insert(0.0);
        if vote.weight > *slot {
            *slot = vote.weight;
        }
        evidence.push(vote.evidence.clone());
    }

    let Some((winner, winner_total)) = totals
        .iter()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(k, v)| (k.clone(), *v))
    else {
        return (None, 0.0);
    };

    let runner_up = totals
        .iter()
        .filter(|(k, _)| **k != winner)
        .map(|(_, v)| *v)
        .fold(0.0_f32, f32::max);

    let base = best_single.get(&winner).copied().unwrap_or(0.0);
    // Zusatzbestätigung über das stärkste Einzelsignal hinaus, gedeckelt.
    let support = (winner_total - base).min(0.3);
    let confidence = (base + support - runner_up * 0.5).clamp(0.0, 1.0);

    (Some(winner), confidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::device_type;

    fn engine() -> FingerprintEngine {
        FingerprintEngine::with_builtin_oui()
    }

    fn ip(s: &str) -> Option<IpAddr> {
        s.parse().ok()
    }

    #[test]
    fn nothing_in_nothing_out() {
        let signals = DeviceSignals::default();
        assert!(engine().evaluate(&signals).is_none());
    }

    #[test]
    fn a_bare_mac_yields_the_vendor_only() {
        let signals = DeviceSignals::new(ip("192.168.1.5"), Some("b8:27:eb:11:22:33".into()));
        let fp = engine().evaluate(&signals).expect("fingerprint");

        assert_eq!(fp.vendor.as_deref(), Some("Raspberry Pi Foundation"));
        assert_eq!(fp.device_type.as_deref(), Some(device_type::COMPUTER));
        assert!(fp.evidence.iter().any(|e| e.signal == "mac_oui"));
    }

    #[test]
    fn mdns_service_identifies_a_printer() {
        let mut signals = DeviceSignals::new(ip("192.168.1.20"), None);
        signals.add_mdns_service("HP LaserJet._ipp._tcp.local");

        let fp = engine().evaluate(&signals).expect("fingerprint");
        assert_eq!(fp.device_type.as_deref(), Some(device_type::PRINTER));
        assert!(
            fp.confidence >= 0.8,
            "a self-advertised IPP service is strong"
        );
        assert!(fp.evidence.iter().any(|e| e.signal == "mdns_service"));
    }

    #[test]
    fn agreeing_sources_raise_confidence() {
        let mut single = DeviceSignals::new(ip("192.168.1.20"), None);
        single.add_mdns_service("printer._ipp._tcp.local");
        let alone = engine().evaluate(&single).expect("fingerprint").confidence;

        let mut combined = DeviceSignals::new(ip("192.168.1.20"), Some("00:80:77:11:22:33".into()));
        combined.add_mdns_service("printer._ipp._tcp.local");
        combined.ssdp_device_type = Some("urn:schemas-upnp-org:device:Printer:1".into());
        let together = engine().evaluate(&combined).expect("fingerprint");

        assert_eq!(together.device_type.as_deref(), Some(device_type::PRINTER));
        assert_eq!(together.vendor.as_deref(), Some("Brother"));
        assert!(
            together.confidence > alone,
            "three sources agreeing must beat one: {} vs {alone}",
            together.confidence
        );
    }

    #[test]
    fn disagreeing_sources_lower_confidence() {
        // Synology-MAC (NAS) trifft auf eine Cast-Ankündigung (Media).
        let mut signals = DeviceSignals::new(ip("192.168.1.30"), Some("00:11:32:aa:bb:cc".into()));
        signals.add_mdns_service("device._googlecast._tcp.local");

        let fp = engine().evaluate(&signals).expect("fingerprint");
        assert!(
            fp.confidence < 0.9,
            "contradicting signals must not produce a confident answer: {}",
            fp.confidence
        );
        assert!(
            fp.evidence.len() >= 3,
            "both sides of the contradiction stay visible in the evidence"
        );
    }

    #[test]
    fn dhcp_option55_identifies_the_os_family() {
        let mut signals = DeviceSignals::new(ip("192.168.1.10"), None);
        signals.dhcp_param_request_list = Some("1,3,6,15,26,28,51,58,59,43".into());

        let fp = engine().evaluate(&signals).expect("fingerprint");
        assert_eq!(fp.os_family.as_deref(), Some("Android"));
        assert!(fp.evidence.iter().any(|e| e.signal == "dhcp_option55"));
    }

    /// Eine unbekannte Signatur darf nichts behaupten. Für sich allein ergibt
    /// sie keine Beobachtung — sobald aber etwas anderes greift, fährt sie als
    /// Beleg mit, damit die Signaturtabelle aus echten Daten wachsen kann.
    #[test]
    fn unknown_dhcp_signature_alone_produces_nothing() {
        let mut signals = DeviceSignals::new(ip("192.168.1.10"), None);
        signals.dhcp_param_request_list = Some("99,98,97".into());

        assert!(
            engine().evaluate(&signals).is_none(),
            "evidence without a conclusion is noise, not an observation"
        );
    }

    #[test]
    fn unknown_dhcp_signature_rides_along_once_something_else_matches() {
        let mut signals = DeviceSignals::new(ip("192.168.1.10"), Some("b8:27:eb:11:22:33".into()));
        signals.dhcp_param_request_list = Some("99,98,97".into());

        let fp = engine().evaluate(&signals).expect("fingerprint");
        assert_eq!(fp.os_family, None, "no claim from an unknown signature");
        assert!(fp
            .evidence
            .iter()
            .any(|e| e.signal == "dhcp_option55_unknown" && e.value == "99,98,97"));
    }

    #[test]
    fn a_randomised_mac_alone_says_nothing() {
        let signals = DeviceSignals::new(ip("192.168.1.99"), Some("02:aa:bb:cc:dd:ee".into()));
        assert!(
            engine().evaluate(&signals).is_none(),
            "an unidentifiable device is not a finding"
        );
    }

    #[test]
    fn randomised_macs_are_flagged_when_reported() {
        let mut signals = DeviceSignals::new(ip("192.168.1.99"), Some("02:aa:bb:cc:dd:ee".into()));
        signals.add_mdns_service("phone._companion-link._tcp.local");
        signals.dhcp_param_request_list = Some("1,3,6,15,26,28,51,58,59,43".into());

        let fp = engine().evaluate(&signals).expect("fingerprint");
        assert_eq!(fp.vendor, None, "a locally administered MAC has no vendor");
        assert_eq!(fp.os_family.as_deref(), Some("Android"));
        assert!(fp
            .evidence
            .iter()
            .any(|e| e.signal == "mac_locally_administered"));
    }

    #[test]
    fn vmware_mac_identifies_a_virtual_machine() {
        let signals = DeviceSignals::new(ip("192.168.1.60"), Some("00:50:56:12:34:56".into()));
        let fp = engine().evaluate(&signals).expect("fingerprint");

        assert_eq!(fp.vendor.as_deref(), Some("VMware"));
        assert_eq!(
            fp.device_type.as_deref(),
            Some(device_type::VIRTUAL_MACHINE)
        );
        assert!(fp.confidence >= 0.85);
    }

    #[test]
    fn ssdp_gateway_is_recognised_as_a_router() {
        let mut signals = DeviceSignals::new(ip("192.168.1.1"), None);
        signals.ssdp_device_type =
            Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".into());
        signals.ssdp_server = Some("AVM FRITZ!Box UPnP/1.0".into());

        let fp = engine().evaluate(&signals).expect("fingerprint");
        assert_eq!(fp.device_type.as_deref(), Some(device_type::ROUTER));
        assert_eq!(fp.model.as_deref(), Some("AVM FRITZ!Box UPnP/1.0"));
    }

    #[test]
    fn banner_contributes_an_os_hint() {
        let mut signals = DeviceSignals::new(ip("192.168.1.7"), None);
        signals.add_banner("SSH-2.0-dropbear_2022.83");

        let fp = engine().evaluate(&signals).expect("fingerprint");
        assert_eq!(fp.os_family.as_deref(), Some("Linux (embedded)"));
        assert!(fp
            .evidence
            .iter()
            .any(|e| e.method == DiscoveryMethod::Banner));
    }

    #[test]
    fn every_fingerprint_carries_its_evidence() {
        let mut signals = DeviceSignals::new(ip("192.168.1.20"), Some("00:11:32:aa:bb:cc".into()));
        signals.add_mdns_service("nas._smb._tcp.local");
        signals.dhcp_param_request_list = Some("1,28,2,3,15,6,119,12,44,47,26,121,42".into());

        let fp = engine().evaluate(&signals).expect("fingerprint");
        assert!(
            !fp.evidence.is_empty(),
            "an unexplainable fingerprint is not reviewable"
        );
        for e in &fp.evidence {
            assert!(!e.signal.is_empty());
            assert!(!e.value.is_empty());
        }
    }

    #[test]
    fn confidence_always_stays_within_bounds() {
        let mut signals = DeviceSignals::new(ip("192.168.1.20"), Some("00:11:32:aa:bb:cc".into()));
        for i in 0..20 {
            signals.add_mdns_service(format!("dev{i}._smb._tcp.local"));
        }
        let fp = engine().evaluate(&signals).expect("fingerprint");
        assert!(
            (0.0..=1.0).contains(&fp.confidence),
            "confidence {} left the 0..1 range",
            fp.confidence
        );
    }

    #[test]
    fn duplicate_signals_are_deduplicated_before_voting() {
        let mut signals = DeviceSignals::new(ip("192.168.1.20"), None);
        signals.add_mdns_service("printer._ipp._tcp.local");
        signals.add_mdns_service("printer._ipp._tcp.local");
        assert_eq!(signals.mdns_services.len(), 1);

        signals.add_banner("SSH-2.0-OpenSSH_9.2");
        signals.add_banner("SSH-2.0-OpenSSH_9.2");
        assert_eq!(signals.banners.len(), 1);
    }
}
