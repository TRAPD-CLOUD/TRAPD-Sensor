//! DHCP-Beobachtung (BOOTP + Optionen).
//!
//! DHCP ist die zuverlässigste passive Quelle für *Namen* und *Gerätetyp*: der
//! Client nennt seinen Hostnamen (Option 12), oft seine Vendor-Klasse (60) und
//! — am aufschlussreichsten — die Liste der Optionen, die er anfordert (55).
//! Diese Reihenfolge ist je Betriebssystem-Stack charakteristisch und damit ein
//! belastbarer Fingerprint, ohne dass ein einziges Paket gesendet werden muss.
//!
//! Ausgelesen wird ausschließlich diese Handvoll Optionen. Der Rest des
//! Pakets — insbesondere alles, was Nutzerdaten tragen könnte — wird nicht
//! angefasst.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::frame::be32;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

const MAGIC_COOKIE: u32 = 0x6382_5363;
const OPTION_PAD: u8 = 0;
const OPTION_END: u8 = 255;

const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_HOSTNAME: u8 = 12;
const OPT_VENDOR_CLASS: u8 = 60;
const OPT_PARAM_REQUEST_LIST: u8 = 55;
const OPT_LEASE_TIME: u8 = 51;
const OPT_SERVER_ID: u8 = 54;
const OPT_REQUESTED_IP: u8 = 50;

/// Wie viele Optionen höchstens gelesen werden. Ein Paket mit mehr als das ist
/// keine echte DHCP-Nachricht mehr.
const MAX_OPTIONS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    pub message_type: DhcpMessageType,
    pub client_mac: [u8; 6],
    /// Vom Server zugewiesene Adresse (`yiaddr`).
    pub your_ip: Option<Ipv4Addr>,
    /// Vom Client gewünschte Adresse (Option 50) — bei einem REQUEST die
    /// eigentliche Aussage, denn `yiaddr` ist dort noch leer.
    pub requested_ip: Option<Ipv4Addr>,
    pub server_ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    /// Option 55 als kommaseparierte Liste, Reihenfolge erhalten.
    pub param_request_list: Option<String>,
    pub lease_seconds: Option<u32>,
}

impl DhcpMessage {
    /// Die Adresse, die dieses Paket dem Client zuordnet — je nach Nachrichtentyp
    /// aus unterschiedlichen Feldern.
    pub fn effective_ip(&self) -> Option<Ipv4Addr> {
        self.your_ip
            .filter(|ip| !ip.is_unspecified())
            .or(self.requested_ip)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Other(u8),
}

impl DhcpMessageType {
    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            other => Self::Other(other),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Offer => "offer",
            Self::Request => "request",
            Self::Decline => "decline",
            Self::Ack => "ack",
            Self::Nak => "nak",
            Self::Release => "release",
            Self::Inform => "inform",
            Self::Other(_) => "other",
        }
    }

    /// Belegt diese Nachricht eine tatsächlich vergebene Adresse?
    pub fn confirms_lease(self) -> bool {
        matches!(self, Self::Ack)
    }
}

pub fn parse_dhcp(data: &[u8]) -> Option<DhcpMessage> {
    // BOOTP-Fixteil ist 236 Byte, danach folgt der Magic Cookie.
    let client_mac: [u8; 6] = data.get(28..34)?.try_into().ok()?;
    let your_ip = Ipv4Addr::from(<[u8; 4]>::try_from(data.get(16..20)?).ok()?);

    if be32(data.get(236..240)?) != MAGIC_COOKIE {
        return None;
    }

    let options = parse_options(data.get(240..)?);

    let message_type = options
        .get(&OPT_MESSAGE_TYPE)
        .and_then(|v| v.first())
        .map(|c| DhcpMessageType::from_code(*c))?;

    Some(DhcpMessage {
        message_type,
        client_mac,
        your_ip: Some(your_ip).filter(|ip| !ip.is_unspecified()),
        requested_ip: options.get(&OPT_REQUESTED_IP).and_then(|v| to_ipv4(v)),
        server_ip: options.get(&OPT_SERVER_ID).and_then(|v| to_ipv4(v)),
        hostname: options.get(&OPT_HOSTNAME).and_then(|v| to_text(v)),
        vendor_class: options.get(&OPT_VENDOR_CLASS).and_then(|v| to_text(v)),
        param_request_list: options.get(&OPT_PARAM_REQUEST_LIST).map(|v| {
            v.iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(",")
        }),
        lease_seconds: options
            .get(&OPT_LEASE_TIME)
            .filter(|v| v.len() >= 4)
            .map(|v| be32(v)),
    })
}

fn parse_options(mut data: &[u8]) -> BTreeMap<u8, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut seen = 0usize;

    while let Some((&code, rest)) = data.split_first() {
        if code == OPTION_END {
            break;
        }
        if code == OPTION_PAD {
            data = rest;
            continue;
        }
        seen += 1;
        if seen > MAX_OPTIONS {
            break;
        }
        let Some((&len, rest)) = rest.split_first() else {
            break;
        };
        let len = usize::from(len);
        // Eine Längenangabe, die über das Paket hinausreicht, beendet das
        // Parsen — sie ist entweder Trunkierung oder Absicht.
        let Some(value) = rest.get(..len) else {
            break;
        };
        out.entry(code).or_insert_with(|| value.to_vec());
        data = &rest[len..];
    }
    out
}

fn to_ipv4(value: &[u8]) -> Option<Ipv4Addr> {
    let bytes: [u8; 4] = value.get(..4)?.try_into().ok()?;
    Some(Ipv4Addr::from(bytes))
}

/// Textoptionen enthalten fremde Bytes. Nur druckbares ASCII wird übernommen,
/// alles andere verworfen — ein Hostname mit Steuerzeichen hat im Dashboard und
/// in Logs nichts verloren.
fn to_text(value: &[u8]) -> Option<String> {
    let text: String = value
        .iter()
        .take_while(|&&b| b != 0)
        .filter(|&&b| (0x20..0x7f).contains(&b))
        .map(|&b| b as char)
        .collect();
    let trimmed = text.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DhcpBuilder {
        yiaddr: [u8; 4],
        chaddr: [u8; 6],
        options: Vec<(u8, Vec<u8>)>,
    }

    impl DhcpBuilder {
        fn new() -> Self {
            Self {
                yiaddr: [0, 0, 0, 0],
                chaddr: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
                options: Vec::new(),
            }
        }

        fn yiaddr(mut self, ip: [u8; 4]) -> Self {
            self.yiaddr = ip;
            self
        }

        fn option(mut self, code: u8, value: Vec<u8>) -> Self {
            self.options.push((code, value));
            self
        }

        fn build(self) -> Vec<u8> {
            let mut out = vec![0u8; 240];
            out[0] = 2; // BOOTREPLY
            out[1] = 1; // Ethernet
            out[2] = 6; // hlen
            out[16..20].copy_from_slice(&self.yiaddr);
            out[28..34].copy_from_slice(&self.chaddr);
            out[236..240].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            for (code, value) in self.options {
                out.push(code);
                out.push(value.len() as u8);
                out.extend_from_slice(&value);
            }
            out.push(OPTION_END);
            out
        }
    }

    #[test]
    fn dhcp_ack_yields_lease_hostname_and_fingerprint() {
        let packet = DhcpBuilder::new()
            .yiaddr([192, 168, 1, 50])
            .option(OPT_MESSAGE_TYPE, vec![5]) // ACK
            .option(OPT_HOSTNAME, b"nas-01".to_vec())
            .option(OPT_VENDOR_CLASS, b"udhcp 1.36".to_vec())
            .option(OPT_PARAM_REQUEST_LIST, vec![1, 3, 6, 15, 28])
            .option(OPT_LEASE_TIME, 86400u32.to_be_bytes().to_vec())
            .option(OPT_SERVER_ID, vec![192, 168, 1, 1])
            .build();

        let msg = parse_dhcp(&packet).expect("parse");
        assert_eq!(msg.message_type, DhcpMessageType::Ack);
        assert!(msg.message_type.confirms_lease());
        assert_eq!(msg.your_ip, Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(msg.effective_ip(), Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(msg.hostname.as_deref(), Some("nas-01"));
        assert_eq!(msg.vendor_class.as_deref(), Some("udhcp 1.36"));
        assert_eq!(msg.param_request_list.as_deref(), Some("1,3,6,15,28"));
        assert_eq!(msg.lease_seconds, Some(86400));
        assert_eq!(msg.server_ip, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(msg.client_mac, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    }

    /// Beim REQUEST steht die Adresse in Option 50, nicht in `yiaddr`.
    #[test]
    fn request_uses_the_requested_ip_option() {
        let packet = DhcpBuilder::new()
            .option(OPT_MESSAGE_TYPE, vec![3])
            .option(OPT_REQUESTED_IP, vec![10, 0, 0, 77])
            .build();

        let msg = parse_dhcp(&packet).expect("parse");
        assert_eq!(msg.message_type, DhcpMessageType::Request);
        assert_eq!(msg.your_ip, None);
        assert_eq!(msg.effective_ip(), Some(Ipv4Addr::new(10, 0, 0, 77)));
        assert!(!msg.message_type.confirms_lease());
    }

    #[test]
    fn padding_options_are_skipped() {
        let mut packet = DhcpBuilder::new().option(OPT_MESSAGE_TYPE, vec![1]).build();
        // PAD-Bytes vor dem END einfügen.
        packet.pop();
        packet.extend_from_slice(&[OPTION_PAD, OPTION_PAD, OPTION_PAD]);
        packet.push(OPT_HOSTNAME);
        packet.push(3);
        packet.extend_from_slice(b"pi4");
        packet.push(OPTION_END);

        let msg = parse_dhcp(&packet).expect("parse");
        assert_eq!(msg.hostname.as_deref(), Some("pi4"));
    }

    #[test]
    fn hostname_with_control_characters_is_sanitised() {
        let packet = DhcpBuilder::new()
            .option(OPT_MESSAGE_TYPE, vec![5])
            .option(OPT_HOSTNAME, b"ho\x07st\x1b[31m".to_vec())
            .build();

        let msg = parse_dhcp(&packet).expect("parse");
        assert_eq!(
            msg.hostname.as_deref(),
            Some("host[31m"),
            "control bytes must never reach logs or the dashboard"
        );
    }

    #[test]
    fn option_length_beyond_the_packet_stops_parsing() {
        let mut packet = DhcpBuilder::new().option(OPT_MESSAGE_TYPE, vec![5]).build();
        packet.pop();
        packet.push(OPT_HOSTNAME);
        packet.push(200); // behauptet 200 Byte, liefert 2
        packet.extend_from_slice(b"ab");

        let msg = parse_dhcp(&packet).expect("parse");
        assert_eq!(msg.message_type, DhcpMessageType::Ack);
        assert_eq!(msg.hostname, None, "the bogus option is dropped, not read");
    }

    #[test]
    fn packet_without_magic_cookie_is_not_dhcp() {
        let mut packet = DhcpBuilder::new().option(OPT_MESSAGE_TYPE, vec![1]).build();
        packet[236] = 0;
        assert!(parse_dhcp(&packet).is_none());
    }

    #[test]
    fn packet_without_message_type_is_rejected() {
        let packet = DhcpBuilder::new()
            .option(OPT_HOSTNAME, b"x".to_vec())
            .build();
        assert!(parse_dhcp(&packet).is_none());
    }

    #[test]
    fn truncated_packets_return_none() {
        let full = DhcpBuilder::new().option(OPT_MESSAGE_TYPE, vec![5]).build();
        for len in [0, 10, 33, 100, 235, 239] {
            assert!(
                parse_dhcp(&full[..len]).is_none(),
                "len {len} must not parse"
            );
        }
    }

    #[test]
    fn absurd_option_counts_are_bounded() {
        let mut packet = DhcpBuilder::new().option(OPT_MESSAGE_TYPE, vec![5]).build();
        packet.pop();
        for _ in 0..500 {
            packet.push(200); // unbekannte Option
            packet.push(1);
            packet.push(0);
        }
        packet.push(OPTION_END);

        // Muss terminieren und ein Ergebnis liefern, nicht hängen.
        let msg = parse_dhcp(&packet).expect("parse");
        assert_eq!(msg.message_type, DhcpMessageType::Ack);
    }
}
