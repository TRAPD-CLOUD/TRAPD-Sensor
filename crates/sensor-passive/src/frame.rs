//! Header-Parser für Ethernet, VLAN, IPv4/IPv6, TCP und UDP.
//!
//! Alle Funktionen sind rein, ohne Allokation und geben `None` zurück, sobald
//! etwas nicht passt. Ein Sensor liest fremde Bytes von der Leitung — jede
//! Längenangabe darin ist erst einmal eine Behauptung. Deshalb wird hier
//! ausschließlich über `get()` zugegriffen, nie indiziert: ein verkürztes oder
//! bösartig konstruiertes Paket führt zu `None`, nie zu einem Panic.
//!
//! Gelesen werden nur Header. Die Nutzlast wird als Slice weitergereicht, und
//! nur die Protokoll-Module, die ausdrücklich Klartextfelder auswerten dürfen
//! (DHCP, DNS, SSDP), sehen sie überhaupt an.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// QinQ (802.1ad) — kommt in größeren Netzen vor.
pub const ETHERTYPE_QINQ: u16 = 0x88a8;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_ICMPV6: u8 = 58;

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;
/// Mehr als zwei Tags (QinQ) ist in der Praxis keine gültige Konstellation,
/// sondern ein Versuch, den Parser im Kreis laufen zu lassen.
const MAX_VLAN_TAGS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    /// Äußerstes VLAN-Tag, falls vorhanden.
    pub vlan_id: Option<u16>,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse_ethernet(data: &[u8]) -> Option<EthernetFrame<'_>> {
    let dst_mac: [u8; 6] = data.get(0..6)?.try_into().ok()?;
    let src_mac: [u8; 6] = data.get(6..12)?.try_into().ok()?;
    let mut ethertype = be16(data.get(12..14)?);
    let mut offset = ETHERNET_HEADER_LEN;
    let mut vlan_id = None;

    let mut tags = 0;
    while matches!(ethertype, ETHERTYPE_VLAN | ETHERTYPE_QINQ) {
        if tags >= MAX_VLAN_TAGS {
            return None;
        }
        let tci = be16(data.get(offset..offset + 2)?);
        if vlan_id.is_none() {
            // Untere 12 Bit sind die VLAN-ID; darüber stehen PCP und DEI.
            vlan_id = Some(tci & 0x0fff);
        }
        ethertype = be16(data.get(offset + 2..offset + 4)?);
        offset += VLAN_TAG_LEN;
        tags += 1;
    }

    Some(EthernetFrame {
        dst_mac,
        src_mac,
        vlan_id,
        ethertype,
        payload: data.get(offset..)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    /// TTL (v4) bzw. Hop Limit (v6) — schwaches, aber kostenloses OS-Signal.
    pub ttl: u8,
    pub payload: &'a [u8],
}

pub fn parse_ipv4(data: &[u8]) -> Option<IpPacket<'_>> {
    let version_ihl = *data.first()?;
    if version_ihl >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(version_ihl & 0x0f) * 4;
    if header_len < 20 {
        return None;
    }
    let total_len = usize::from(be16(data.get(2..4)?));
    let ttl = *data.get(8)?;
    let protocol = *data.get(9)?;
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(data.get(12..16)?).ok()?);
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(data.get(16..20)?).ok()?);

    // `total_len` ist die Angabe des Absenders. Sie kann über den tatsächlich
    // erfassten Bytes liegen (Snaplen!) oder gelogen sein — deshalb wird sie
    // gegen das Vorhandene begrenzt statt ihr zu vertrauen. Bewusst kein
    // `clamp`: bei einem Paket, das kürzer ist als sein eigener Header, wäre
    // dort `min > max` und `clamp` würde panicken.
    let end = total_len.max(header_len).min(data.len());
    let payload = data.get(header_len..end)?;

    Some(IpPacket {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol,
        ttl,
        payload,
    })
}

pub fn parse_ipv6(data: &[u8]) -> Option<IpPacket<'_>> {
    if data.first()? >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(be16(data.get(4..6)?));
    let next_header = *data.get(6)?;
    let hop_limit = *data.get(7)?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(data.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(data.get(24..40)?).ok()?);

    let end = (40 + payload_len).min(data.len());
    let payload = data.get(40..end)?;

    // Extension-Header werden bewusst nicht aufgelöst: der Sensor braucht
    // Adressen und, wenn direkt vorhanden, den Transport-Header. Eine
    // vollständige Header-Kette zu durchlaufen wäre eine eigene Angriffsfläche
    // für wenig Zusatznutzen.
    Some(IpPacket {
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        protocol: next_header,
        ttl: hop_limit,
        payload,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(data: &[u8]) -> Option<UdpDatagram<'_>> {
    let src_port = be16(data.get(0..2)?);
    let dst_port = be16(data.get(2..4)?);
    let length = usize::from(be16(data.get(4..6)?));
    // Header sind 8 Byte; kürzere Längenangaben sind ungültig. Kein `clamp`,
    // siehe `parse_ipv4` — ein 6-Byte-Fragment würde sonst panicken.
    let end = length.max(8).min(data.len());
    Some(UdpDatagram {
        src_port,
        dst_port,
        payload: data.get(8..end)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    /// Fenstergröße — geht als schwaches Stack-Signal ins Fingerprinting ein.
    pub window: u16,
    pub payload: &'a [u8],
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

impl TcpSegment<'_> {
    /// Verbindungsaufbau eines Clients (SYN ohne ACK) — der Moment, in dem ein
    /// Flow beginnt.
    pub fn is_syn(&self) -> bool {
        self.flags & TCP_SYN != 0 && self.flags & TCP_ACK == 0
    }

    /// Antwort des Servers: hier ist belegt, dass der Port offen ist.
    pub fn is_syn_ack(&self) -> bool {
        self.flags & TCP_SYN != 0 && self.flags & TCP_ACK != 0
    }

    pub fn is_reset(&self) -> bool {
        self.flags & TCP_RST != 0
    }
}

pub fn parse_tcp(data: &[u8]) -> Option<TcpSegment<'_>> {
    if data.len() < 20 {
        return None;
    }
    let src_port = be16(data.get(0..2)?);
    let dst_port = be16(data.get(2..4)?);
    let data_offset = usize::from(data.get(12)? >> 4) * 4;
    if data_offset < 20 {
        return None;
    }
    let flags = *data.get(13)?;
    let window = be16(data.get(14..16)?);
    let payload = data.get(data_offset..).unwrap_or(&[]);

    Some(TcpSegment {
        src_port,
        dst_port,
        flags,
        window,
        payload,
    })
}

pub(crate) fn be16(bytes: &[u8]) -> u16 {
    match bytes {
        [a, b, ..] => u16::from_be_bytes([*a, *b]),
        _ => 0,
    }
}

pub(crate) fn be32(bytes: &[u8]) -> u32 {
    match bytes {
        [a, b, c, d, ..] => u32::from_be_bytes([*a, *b, *c, *d]),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet-Header mit frei wählbarem Ethertype.
    fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst (broadcast)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
        ];
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn plain_ethernet_frame_is_parsed() {
        let frame = eth(ETHERTYPE_IPV4, &[0xde, 0xad]);
        let parsed = parse_ethernet(&frame).expect("parse");

        assert_eq!(parsed.src_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(parsed.dst_mac, [0xff; 6]);
        assert_eq!(parsed.ethertype, ETHERTYPE_IPV4);
        assert_eq!(parsed.vlan_id, None);
        assert_eq!(parsed.payload, &[0xde, 0xad]);
    }

    #[test]
    fn vlan_tag_is_unwrapped_and_reported() {
        let mut tagged = vec![0x00, 0x64]; // TCI: PCP 0, VLAN 100
        tagged.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        tagged.extend_from_slice(&[0xbe, 0xef]);

        let frame = eth(ETHERTYPE_VLAN, &tagged);
        let parsed = parse_ethernet(&frame).expect("parse");

        assert_eq!(parsed.vlan_id, Some(100));
        assert_eq!(parsed.ethertype, ETHERTYPE_IPV4);
        assert_eq!(parsed.payload, &[0xbe, 0xef]);
    }

    #[test]
    fn qinq_reports_the_outer_vlan() {
        let mut inner = vec![0x00, 0x0a];
        inner.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        inner.extend_from_slice(&[0x01]);

        let mut outer = vec![0x00, 0x14]; // VLAN 20
        outer.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        outer.extend_from_slice(&inner);

        let frame = eth(ETHERTYPE_QINQ, &outer);
        let parsed = parse_ethernet(&frame).expect("parse");
        assert_eq!(
            parsed.vlan_id,
            Some(20),
            "the outer tag identifies the segment"
        );
        assert_eq!(parsed.ethertype, ETHERTYPE_IPV4);
    }

    #[test]
    fn endless_vlan_stacking_is_refused() {
        // Drei Tags — jenseits von allem Gültigen und ein klassischer Versuch,
        // einen Parser zum Kreisen zu bringen.
        let mut nested = Vec::new();
        for _ in 0..3 {
            nested.extend_from_slice(&[0x00, 0x01]);
            nested.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        }
        nested.extend_from_slice(&[0x00]);
        assert!(parse_ethernet(&eth(ETHERTYPE_VLAN, &nested)).is_none());
    }

    #[test]
    fn truncated_frames_return_none_instead_of_panicking() {
        for len in 0..14 {
            let truncated = vec![0u8; len];
            assert!(
                parse_ethernet(&truncated).is_none(),
                "len {len} must not parse"
            );
        }
    }

    fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut out = vec![0x45, 0x00];
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, protocol, 0x00, 0x00]);
        out.extend_from_slice(&[192, 168, 1, 10]);
        out.extend_from_slice(&[192, 168, 1, 1]);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn ipv4_header_is_parsed() {
        let packet = ipv4(IP_PROTO_UDP, &[1, 2, 3, 4]);
        let parsed = parse_ipv4(&packet).expect("parse");

        assert_eq!(parsed.src, "192.168.1.10".parse::<IpAddr>().expect("ip"));
        assert_eq!(parsed.dst, "192.168.1.1".parse::<IpAddr>().expect("ip"));
        assert_eq!(parsed.protocol, IP_PROTO_UDP);
        assert_eq!(parsed.ttl, 64);
        assert_eq!(parsed.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn ipv4_with_options_skips_them() {
        let mut packet = ipv4(IP_PROTO_TCP, &[]);
        packet[0] = 0x46; // IHL 6 → 24 Byte Header
        packet.splice(20..20, [0u8; 4]);
        packet[2..4].copy_from_slice(&24u16.to_be_bytes());
        packet.extend_from_slice(&[0xaa]);

        let parsed = parse_ipv4(&packet).expect("parse");
        assert_eq!(parsed.payload.len(), 0, "total_len covers only the header");
    }

    /// Ein Absender kann jede Länge behaupten. Der Parser darf ihr nicht folgen.
    #[test]
    fn lying_total_length_cannot_read_past_the_buffer() {
        let mut packet = ipv4(IP_PROTO_UDP, &[1, 2]);
        packet[2..4].copy_from_slice(&60000u16.to_be_bytes());

        let parsed = parse_ipv4(&packet).expect("parse");
        assert_eq!(
            parsed.payload,
            &[1, 2],
            "clamped to what was actually captured"
        );
    }

    #[test]
    fn ipv4_rejects_wrong_version_and_short_header() {
        let mut packet = ipv4(IP_PROTO_UDP, &[]);
        packet[0] = 0x65; // Version 6 in einem v4-Parser
        assert!(parse_ipv4(&packet).is_none());

        let mut short_ihl = ipv4(IP_PROTO_UDP, &[]);
        short_ihl[0] = 0x43; // IHL 3 → 12 Byte, unmöglich
        assert!(parse_ipv4(&short_ihl).is_none());
    }

    #[test]
    fn ipv6_header_is_parsed() {
        let mut packet = vec![0x60, 0x00, 0x00, 0x00];
        packet.extend_from_slice(&2u16.to_be_bytes()); // payload len
        packet.push(IP_PROTO_UDP);
        packet.push(64); // hop limit
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet.extend_from_slice(&[0xab, 0xcd]);

        let parsed = parse_ipv6(&packet).expect("parse");
        assert_eq!(parsed.src, "2001:db8::1".parse::<IpAddr>().expect("ip"));
        assert_eq!(parsed.dst, "2001:db8::2".parse::<IpAddr>().expect("ip"));
        assert_eq!(parsed.protocol, IP_PROTO_UDP);
        assert_eq!(parsed.payload, &[0xab, 0xcd]);
    }

    #[test]
    fn truncated_ip_headers_return_none() {
        for len in 0..20 {
            assert!(parse_ipv4(&vec![0x45u8; len]).is_none(), "v4 len {len}");
        }
        for len in 0..40 {
            let mut buf = vec![0u8; len];
            if let Some(first) = buf.first_mut() {
                *first = 0x60;
            }
            assert!(parse_ipv6(&buf).is_none(), "v6 len {len}");
        }
    }

    #[test]
    fn udp_datagram_is_parsed() {
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&68u16.to_be_bytes());
        datagram.extend_from_slice(&67u16.to_be_bytes());
        datagram.extend_from_slice(&12u16.to_be_bytes()); // 8 header + 4 payload
        datagram.extend_from_slice(&[0x00, 0x00]);
        datagram.extend_from_slice(&[1, 2, 3, 4]);

        let parsed = parse_udp(&datagram).expect("parse");
        assert_eq!(parsed.src_port, 68);
        assert_eq!(parsed.dst_port, 67);
        assert_eq!(parsed.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn udp_with_bogus_length_is_clamped() {
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&53u16.to_be_bytes());
        datagram.extend_from_slice(&53u16.to_be_bytes());
        datagram.extend_from_slice(&9999u16.to_be_bytes());
        datagram.extend_from_slice(&[0x00, 0x00]);
        datagram.extend_from_slice(&[0xaa]);

        assert_eq!(parse_udp(&datagram).expect("parse").payload, &[0xaa]);
    }

    fn tcp(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&443u16.to_be_bytes());
        out.extend_from_slice(&54321u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 1]); // seq
        out.extend_from_slice(&[0, 0, 0, 0]); // ack
        out.push(0x50); // data offset 5 → 20 Byte
        out.push(flags);
        out.extend_from_slice(&64240u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]); // checksum + urgent
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn tcp_flags_identify_handshake_stages() {
        let syn_bytes = tcp(TCP_SYN, &[]);
        let syn = parse_tcp(&syn_bytes).expect("parse");
        assert!(syn.is_syn());
        assert!(!syn.is_syn_ack());

        let syn_ack_bytes = tcp(TCP_SYN | TCP_ACK, &[]);
        let syn_ack = parse_tcp(&syn_ack_bytes).expect("parse");
        assert!(syn_ack.is_syn_ack());
        assert!(!syn_ack.is_syn());

        let rst_bytes = tcp(TCP_RST | TCP_ACK, &[]);
        let rst = parse_tcp(&rst_bytes).expect("parse");
        assert!(rst.is_reset());

        assert_eq!(syn.window, 64240);
    }

    #[test]
    fn tcp_payload_starts_after_the_options() {
        let mut segment = tcp(TCP_PSH | TCP_ACK, &[]);
        segment[12] = 0x60; // data offset 6 → 24 Byte
        segment.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // NOP-Optionen
        segment.extend_from_slice(b"hello");

        let parsed = parse_tcp(&segment).expect("parse");
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn tcp_with_impossible_data_offset_is_rejected() {
        let mut segment = tcp(TCP_SYN, &[]);
        segment[12] = 0x10; // data offset 1 → 4 Byte
        assert!(parse_tcp(&segment).is_none());
    }

    #[test]
    fn truncated_transport_headers_return_none() {
        for len in 0..8 {
            assert!(parse_udp(&vec![0u8; len]).is_none(), "udp len {len}");
        }
        for len in 0..20 {
            assert!(parse_tcp(&vec![0u8; len]).is_none(), "tcp len {len}");
        }
    }
}
