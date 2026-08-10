//! Signaturtabellen: welches Signal deutet auf welches Gerät.
//!
//! Die Tabellen sind bewusst kurz und konservativ. Ein Fingerprint, der oft
//! *irgendetwas* rät, ist schlechter als einer, der selten etwas sagt und dann
//! stimmt — falsche Gerätetypen wandern in den Asset-Graph und von dort in
//! Detections. Was hier nicht sicher zuzuordnen ist, bleibt unbestimmt.

/// Gerätetypen, die der Sensor vergibt. Bewusst grob: die feinere Einordnung
/// macht das Backend, das über alle Quellen verfügt.
pub mod device_type {
    pub const ROUTER: &str = "router";
    pub const PRINTER: &str = "printer";
    pub const NAS: &str = "nas";
    pub const MEDIA: &str = "media_device";
    pub const SMART_HOME: &str = "smart_home";
    pub const IOT: &str = "iot";
    pub const COMPUTER: &str = "computer";
    pub const MOBILE: &str = "mobile";
    pub const VIRTUAL_MACHINE: &str = "virtual_machine";
    pub const NETWORK_DEVICE: &str = "network_device";
    pub const CAMERA: &str = "camera";
}

/// mDNS-Dienstnamen → Gerätetyp.
///
/// Das ist die verlässlichste Zuordnung im ganzen Modul: ein Gerät, das
/// `_googlecast._tcp` bewirbt, *ist* ein Cast-Empfänger. Es behauptet das über
/// sich selbst, unaufgefordert und in einem standardisierten Format.
pub const MDNS_SERVICE_TYPES: &[(&str, &str, f32)] = &[
    ("_googlecast._tcp", device_type::MEDIA, 0.9),
    ("_airplay._tcp", device_type::MEDIA, 0.9),
    ("_raop._tcp", device_type::MEDIA, 0.85),
    ("_spotify-connect._tcp", device_type::MEDIA, 0.8),
    ("_sonos._tcp", device_type::MEDIA, 0.9),
    ("_ipp._tcp", device_type::PRINTER, 0.9),
    ("_ipps._tcp", device_type::PRINTER, 0.9),
    ("_printer._tcp", device_type::PRINTER, 0.9),
    ("_pdl-datastream._tcp", device_type::PRINTER, 0.85),
    ("_scanner._tcp", device_type::PRINTER, 0.8),
    ("_hap._tcp", device_type::SMART_HOME, 0.85),
    ("_homekit._tcp", device_type::SMART_HOME, 0.85),
    ("_hue._tcp", device_type::SMART_HOME, 0.85),
    ("_esphomelib._tcp", device_type::IOT, 0.9),
    ("_matter._tcp", device_type::SMART_HOME, 0.85),
    ("_smb._tcp", device_type::NAS, 0.6),
    ("_afpovertcp._tcp", device_type::NAS, 0.7),
    ("_nfs._tcp", device_type::NAS, 0.6),
    ("_workstation._tcp", device_type::COMPUTER, 0.7),
    ("_ssh._tcp", device_type::COMPUTER, 0.5),
    ("_sftp-ssh._tcp", device_type::COMPUTER, 0.5),
    ("_rfb._tcp", device_type::COMPUTER, 0.5),
];

/// UPnP-`deviceType`-URNs → Gerätetyp.
pub const SSDP_DEVICE_TYPES: &[(&str, &str, f32)] = &[
    ("internetgatewaydevice", device_type::ROUTER, 0.9),
    ("wandevice", device_type::ROUTER, 0.7),
    ("wanconnectiondevice", device_type::ROUTER, 0.7),
    ("mediarenderer", device_type::MEDIA, 0.85),
    ("mediaserver", device_type::MEDIA, 0.8),
    ("printer", device_type::PRINTER, 0.9),
    ("scanner", device_type::PRINTER, 0.8),
    ("digitalsecuritycamera", device_type::CAMERA, 0.9),
];

/// DHCP-Option-55-Signaturen → Betriebssystem-Familie.
///
/// Die Reihenfolge der angeforderten Optionen ist je DHCP-Client
/// charakteristisch. Die Zuordnung gilt dem *Client-Stack*, nicht dem Produkt —
/// deshalb ein mittleres Gewicht: viele eingebettete Geräte nutzen dieselben
/// Bibliotheken wie ein Desktop-Linux.
pub const DHCP_FINGERPRINTS: &[(&str, &str, f32)] = &[
    ("1,3,6,15,31,33,43,44,46,47,119,121,249,252", "Windows", 0.7),
    ("1,15,3,6,44,46,47,31,33,121,249,43", "Windows", 0.65),
    ("1,3,6,15,119,95,252,44,46", "macOS", 0.65),
    ("1,121,3,6,15,119,252", "macOS/iOS", 0.6),
    ("1,3,6,15,26,28,51,58,59,43", "Android", 0.7),
    ("1,3,6,15,28,33,51,58,59,119", "Android", 0.6),
    ("1,28,2,3,15,6,119,12,44,47,26,121,42", "Linux", 0.7),
    ("1,3,6,12,15,28,42,121,249,33,252", "Linux", 0.6),
    ("1,3,6,12,15,17,23,28,29,31,33,40,41,42", "Linux", 0.55),
    ("1,3,6,15,66,67", "Embedded/PXE", 0.6),
];

/// Vendor-Class-Kennungen (DHCP Option 60) → Hinweis.
pub const VENDOR_CLASS_HINTS: &[(&str, &str, &str, f32)] = &[
    ("msft", "Windows", device_type::COMPUTER, 0.6),
    ("android-dhcp", "Android", device_type::MOBILE, 0.8),
    ("dhcpcd", "Linux", device_type::COMPUTER, 0.4),
    ("udhcp", "Linux (embedded)", device_type::IOT, 0.5),
    ("hp ", "", device_type::PRINTER, 0.5),
    ("epson", "", device_type::PRINTER, 0.7),
    ("brother", "", device_type::PRINTER, 0.7),
    ("canon", "", device_type::PRINTER, 0.6),
];

/// Hersteller → Gerätetyp, wo der Hersteller praktisch nur eine Sorte Gerät baut.
pub const VENDOR_DEVICE_TYPES: &[(&str, &str, f32)] = &[
    ("Raspberry Pi Foundation", device_type::COMPUTER, 0.6),
    ("Raspberry Pi Trading", device_type::COMPUTER, 0.6),
    ("Synology", device_type::NAS, 0.8),
    ("QNAP", device_type::NAS, 0.8),
    ("Western Digital", device_type::NAS, 0.5),
    ("Brother", device_type::PRINTER, 0.75),
    ("Seiko Epson", device_type::PRINTER, 0.7),
    ("AVM", device_type::ROUTER, 0.75),
    ("Ubiquiti", device_type::NETWORK_DEVICE, 0.7),
    ("Netgear", device_type::NETWORK_DEVICE, 0.6),
    ("D-Link", device_type::NETWORK_DEVICE, 0.55),
    ("Cisco", device_type::NETWORK_DEVICE, 0.6),
    ("Cisco-Linksys", device_type::NETWORK_DEVICE, 0.6),
    ("Philips Lighting", device_type::SMART_HOME, 0.8),
    ("Espressif", device_type::IOT, 0.75),
    ("VMware", device_type::VIRTUAL_MACHINE, 0.9),
    ("QEMU/KVM", device_type::VIRTUAL_MACHINE, 0.9),
    ("Oracle VirtualBox", device_type::VIRTUAL_MACHINE, 0.9),
    ("Microsoft Hyper-V", device_type::VIRTUAL_MACHINE, 0.9),
    ("Xen", device_type::VIRTUAL_MACHINE, 0.9),
];

/// Banner-Präfixe → Betriebssystem-/Produkthinweis.
pub const BANNER_HINTS: &[(&str, &str, f32)] = &[
    ("SSH-2.0-OpenSSH", "Unix-like", 0.5),
    ("SSH-2.0-dropbear", "Linux (embedded)", 0.6),
    ("SSH-2.0-ROSSSH", "MikroTik RouterOS", 0.8),
    ("220 ProFTPD", "Unix-like", 0.4),
    ("220 Microsoft FTP", "Windows", 0.7),
];

/// Sucht in einer `(needle, value, weight)`-Tabelle nach einem Teilstring.
pub fn match_contains<'a>(
    haystack: &str,
    table: &'a [(&'a str, &'a str, f32)],
) -> Option<(&'a str, f32)> {
    let lower = haystack.to_ascii_lowercase();
    table
        .iter()
        .find(|(needle, _, _)| lower.contains(&needle.to_ascii_lowercase()))
        .map(|(_, value, weight)| (*value, *weight))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdns_services_map_to_device_types() {
        let (kind, weight) =
            match_contains("appletv._airplay._tcp.local", MDNS_SERVICE_TYPES).expect("match");
        assert_eq!(kind, device_type::MEDIA);
        assert!(weight >= 0.8);

        let (kind, _) =
            match_contains("HP LaserJet._ipp._tcp.local", MDNS_SERVICE_TYPES).expect("match");
        assert_eq!(kind, device_type::PRINTER);
    }

    #[test]
    fn ssdp_urns_map_to_device_types() {
        let (kind, _) = match_contains(
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            SSDP_DEVICE_TYPES,
        )
        .expect("match");
        assert_eq!(kind, device_type::ROUTER);
    }

    #[test]
    fn unknown_signals_match_nothing() {
        assert!(match_contains("_totally-unknown._tcp.local", MDNS_SERVICE_TYPES).is_none());
        assert!(match_contains("urn:custom:device:Thing:1", SSDP_DEVICE_TYPES).is_none());
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(match_contains("_GOOGLECAST._TCP.local", MDNS_SERVICE_TYPES).is_some());
    }

    #[test]
    fn every_weight_is_a_sane_probability() {
        for (_, _, w) in MDNS_SERVICE_TYPES
            .iter()
            .chain(SSDP_DEVICE_TYPES)
            .chain(DHCP_FINGERPRINTS)
            .chain(VENDOR_DEVICE_TYPES)
            .chain(BANNER_HINTS)
        {
            assert!(
                *w > 0.0 && *w <= 1.0,
                "weight {w} is outside the 0..1 range"
            );
        }
        for (_, _, _, w) in VENDOR_CLASS_HINTS {
            assert!(*w > 0.0 && *w <= 1.0);
        }
    }

    #[test]
    fn virtualisation_vendors_are_recognised_with_high_confidence() {
        for vendor in ["VMware", "QEMU/KVM", "Xen"] {
            let (kind, weight) = VENDOR_DEVICE_TYPES
                .iter()
                .find(|(v, _, _)| *v == vendor)
                .map(|(_, k, w)| (*k, *w))
                .expect("vendor present");
            assert_eq!(kind, device_type::VIRTUAL_MACHINE);
            assert!(weight >= 0.85, "a VMware MAC is not ambiguous");
        }
    }
}
