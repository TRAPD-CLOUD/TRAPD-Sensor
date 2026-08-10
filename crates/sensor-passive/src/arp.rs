//! ARP-Beobachtung.
//!
//! Die ergiebigste passive Quelle in einem Broadcast-Segment: jedes Gerät, das
//! kommuniziert, fragt oder beantwortet ARP, und beides trägt IP *und* MAC. Der
//! Sensor muss dafür kein Paket senden — er hört einfach zu, was ohnehin an
//! alle geht.

use std::net::Ipv4Addr;

use crate::frame::be16;

/// Nur Ethernet/IPv4-ARP ist relevant; alles andere ignorieren wir.
const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;

pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    pub fn is_request(&self) -> bool {
        self.operation == ARP_REQUEST
    }

    pub fn is_reply(&self) -> bool {
        self.operation == ARP_REPLY
    }

    /// Ein "ARP Probe" (Sender-IP 0.0.0.0) sagt nur, dass jemand eine Adresse
    /// sucht — er belegt keine Zuordnung und darf kein Asset anlegen.
    pub fn announces_sender(&self) -> bool {
        !self.sender_ip.is_unspecified() && self.sender_mac != [0u8; 6]
    }
}

pub fn parse_arp(data: &[u8]) -> Option<ArpPacket> {
    let htype = be16(data.get(0..2)?);
    let ptype = be16(data.get(2..4)?);
    let hlen = *data.get(4)?;
    let plen = *data.get(5)?;

    if htype != HTYPE_ETHERNET || ptype != PTYPE_IPV4 || hlen != 6 || plen != 4 {
        return None;
    }

    let operation = be16(data.get(6..8)?);
    let sender_mac: [u8; 6] = data.get(8..14)?.try_into().ok()?;
    let sender_ip = Ipv4Addr::from(<[u8; 4]>::try_from(data.get(14..18)?).ok()?);
    let target_mac: [u8; 6] = data.get(18..24)?.try_into().ok()?;
    let target_ip = Ipv4Addr::from(<[u8; 4]>::try_from(data.get(24..28)?).ok()?);

    Some(ArpPacket {
        operation,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp(operation: u16, sender_ip: [u8; 4], sender_mac: [u8; 6]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        out.extend_from_slice(&PTYPE_IPV4.to_be_bytes());
        out.push(6);
        out.push(4);
        out.extend_from_slice(&operation.to_be_bytes());
        out.extend_from_slice(&sender_mac);
        out.extend_from_slice(&sender_ip);
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&[192, 168, 1, 1]);
        out
    }

    #[test]
    fn arp_reply_yields_ip_and_mac() {
        let packet = arp(
            ARP_REPLY,
            [192, 168, 1, 42],
            [0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33],
        );
        let parsed = parse_arp(&packet).expect("parse");

        assert!(parsed.is_reply());
        assert!(!parsed.is_request());
        assert_eq!(parsed.sender_ip, Ipv4Addr::new(192, 168, 1, 42));
        assert_eq!(parsed.sender_mac, [0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]);
        assert!(parsed.announces_sender());
    }

    #[test]
    fn arp_request_also_identifies_its_sender() {
        let packet = arp(ARP_REQUEST, [192, 168, 1, 7], [0x02, 0, 0, 0, 0, 1]);
        let parsed = parse_arp(&packet).expect("parse");
        assert!(parsed.is_request());
        assert!(
            parsed.announces_sender(),
            "a request still proves the sender exists"
        );
        assert_eq!(parsed.target_ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    /// Ein Gerät, das seine Adresse erst sucht, ist noch kein Asset.
    #[test]
    fn arp_probe_with_unspecified_sender_announces_nothing() {
        let packet = arp(ARP_REQUEST, [0, 0, 0, 0], [0x02, 0, 0, 0, 0, 1]);
        let parsed = parse_arp(&packet).expect("parse");
        assert!(!parsed.announces_sender());
    }

    #[test]
    fn zero_mac_is_not_an_announcement() {
        let packet = arp(ARP_REPLY, [192, 168, 1, 5], [0u8; 6]);
        assert!(!parse_arp(&packet).expect("parse").announces_sender());
    }

    #[test]
    fn non_ethernet_ipv4_arp_is_ignored() {
        let mut packet = arp(ARP_REPLY, [10, 0, 0, 1], [1, 2, 3, 4, 5, 6]);
        packet[1] = 2; // htype != Ethernet
        assert!(parse_arp(&packet).is_none());

        let mut wrong_ptype = arp(ARP_REPLY, [10, 0, 0, 1], [1, 2, 3, 4, 5, 6]);
        wrong_ptype[3] = 0x35; // ptype != IPv4
        assert!(parse_arp(&wrong_ptype).is_none());

        let mut wrong_len = arp(ARP_REPLY, [10, 0, 0, 1], [1, 2, 3, 4, 5, 6]);
        wrong_len[4] = 8; // hlen != 6
        assert!(parse_arp(&wrong_len).is_none());
    }

    #[test]
    fn truncated_arp_returns_none() {
        let full = arp(ARP_REPLY, [10, 0, 0, 1], [1, 2, 3, 4, 5, 6]);
        for len in 0..full.len() {
            assert!(
                parse_arp(&full[..len]).is_none(),
                "len {len} must not parse"
            );
        }
        assert!(parse_arp(&full).is_some());
    }
}
