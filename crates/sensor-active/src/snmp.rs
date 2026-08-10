//! Minimal, bounded SNMPv2c GET client. It never emits SET or WALK requests.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

pub const MAX_SNMP_PACKET: usize = 8 * 1024;
const OIDS: [&[u8]; 4] = [
    &[43, 6, 1, 2, 1, 1, 1, 0], // sysDescr.0 (1.3 prefix folded into 43)
    &[43, 6, 1, 2, 1, 1, 2, 0], // sysObjectID.0
    &[43, 6, 1, 2, 1, 1, 5, 0], // sysName.0
    &[43, 6, 1, 2, 1, 1, 6, 0], // sysLocation.0
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnmpResult {
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
    pub sys_name: Option<String>,
    pub sys_location: Option<String>,
}

pub async fn get_system(
    target: IpAddr,
    community: &str,
    request_id: i32,
    timeout: Duration,
) -> io::Result<Option<SnmpResult>> {
    if community.is_empty() || community.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid SNMP community length",
        ));
    }
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    let request = build_get_request(community.as_bytes(), request_id)?;
    socket
        .send_to(&request, SocketAddr::new(target, 161))
        .await?;
    let mut buf = [0u8; MAX_SNMP_PACKET];
    let received = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;
    let (len, peer) = match received {
        Err(_) => return Ok(None),
        Ok(result) => result?,
    };
    if peer.ip() != target {
        return Ok(None);
    }
    Ok(parse_response(
        &buf[..len],
        community.as_bytes(),
        request_id,
    ))
}

pub fn build_get_request(community: &[u8], request_id: i32) -> io::Result<Vec<u8>> {
    let mut varbinds = Vec::new();
    for oid in OIDS {
        let mut varbind = tlv(0x06, oid)?;
        varbind.extend_from_slice(&tlv(0x05, &[])?);
        varbinds.extend_from_slice(&tlv(0x30, &varbind)?);
    }
    let vars = tlv(0x30, &varbinds)?;
    let mut pdu = integer(request_id);
    pdu.extend_from_slice(&integer(0));
    pdu.extend_from_slice(&integer(0));
    pdu.extend_from_slice(&vars);
    let pdu = tlv(0xa0, &pdu)?; // GET only
    let mut message = integer(1); // SNMPv2c
    message.extend_from_slice(&tlv(0x04, community)?);
    message.extend_from_slice(&pdu);
    let packet = tlv(0x30, &message)?;
    if packet.len() > MAX_SNMP_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SNMP packet too large",
        ));
    }
    Ok(packet)
}

pub fn parse_response(data: &[u8], community: &[u8], request_id: i32) -> Option<SnmpResult> {
    if data.len() > MAX_SNMP_PACKET {
        return None;
    }
    let mut outer = Reader::new(data).constructed(0x30)?;
    if outer.integer()? != 1 || outer.bytes(0x04)? != community {
        return None;
    }
    let mut pdu = outer.constructed(0xa2)?;
    if pdu.integer()? != request_id || pdu.integer()? != 0 {
        return None;
    }
    let _error_index = pdu.integer()?;
    let mut list = pdu.constructed(0x30)?;
    let mut result = SnmpResult::default();
    let mut count = 0;
    while !list.empty() {
        count += 1;
        if count > OIDS.len() {
            return None;
        }
        let mut varbind = list.constructed(0x30)?;
        let oid = varbind.bytes(0x06)?;
        let (tag, value) = varbind.any()?;
        if !varbind.empty() {
            return None;
        }
        let text = match tag {
            0x04 => bounded_text(value),
            0x06 => Some(format_oid(value)?),
            // noSuchObject/noSuchInstance are valid absent values.
            0x80 | 0x81 => None,
            _ => None,
        };
        match OIDS.iter().position(|candidate| *candidate == oid)? {
            0 => result.sys_descr = text,
            1 => result.sys_object_id = text,
            2 => result.sys_name = text,
            3 => result.sys_location = text,
            _ => return None,
        }
    }
    Some(result)
}

fn bounded_text(value: &[u8]) -> Option<String> {
    let value = value.get(..value.len().min(256))?;
    let text: String = value
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                char::from(*b)
            } else {
                ' '
            }
        })
        .collect();
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    (!text.is_empty()).then_some(text)
}

fn format_oid(value: &[u8]) -> Option<String> {
    let first = *value.first()?;
    let mut parts = vec![u32::from(first / 40), u32::from(first % 40)];
    let mut current = 0u32;
    for &byte in value.get(1..)? {
        current = current
            .checked_mul(128)?
            .checked_add(u32::from(byte & 0x7f))?;
        if byte & 0x80 == 0 {
            parts.push(current);
            current = 0;
        }
        if parts.len() > 64 {
            return None;
        }
    }
    if current != 0 {
        return None;
    }
    Some(
        parts
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn integer(value: i32) -> Vec<u8> {
    tlv(0x02, &value.to_be_bytes()).unwrap_or_default()
}
fn tlv(tag: u8, value: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else if value.len() <= u16::MAX as usize {
        out.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]);
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BER value too large",
        ));
    }
    out.extend_from_slice(value);
    Ok(out)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn empty(&self) -> bool {
        self.pos == self.data.len()
    }
    fn any(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.data.get(self.pos)?;
        self.pos += 1;
        let first = *self.data.get(self.pos)?;
        self.pos += 1;
        let len = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 2 {
                return None;
            }
            let mut len = 0usize;
            for _ in 0..n {
                len = len
                    .checked_mul(256)?
                    .checked_add(usize::from(*self.data.get(self.pos)?))?;
                self.pos += 1;
            }
            len
        };
        let end = self.pos.checked_add(len)?;
        let value = self.data.get(self.pos..end)?;
        self.pos = end;
        Some((tag, value))
    }
    fn bytes(&mut self, wanted: u8) -> Option<&'a [u8]> {
        let (tag, value) = self.any()?;
        (tag == wanted).then_some(value)
    }
    fn constructed(&mut self, tag: u8) -> Option<Reader<'a>> {
        Some(Reader::new(self.bytes(tag)?))
    }
    fn integer(&mut self) -> Option<i32> {
        let b = self.bytes(0x02)?;
        if b.is_empty() || b.len() > 4 {
            return None;
        }
        let mut value = if b[0] & 0x80 != 0 { -1i32 } else { 0 };
        for byte in b {
            value = value.checked_shl(8)? | i32::from(*byte);
        }
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn get_contains_only_get_pdu() {
        let p = build_get_request(b"secret", 7).unwrap();
        assert!(p.contains(&0xa0));
        assert!(!p.contains(&0xa3));
    }
    #[test]
    fn malformed_packets_never_parse() {
        for len in 0..24 {
            assert_eq!(parse_response(&vec![0xff; len], b"x", 1), None);
        }
    }
    #[test]
    fn rejects_wrong_community() {
        let mut vars = Vec::new();
        let mut vb = tlv(0x06, OIDS[2]).unwrap();
        vb.extend(tlv(0x04, b"router").unwrap());
        vars.extend(tlv(0x30, &vb).unwrap());
        let mut pdu = integer(9);
        pdu.extend(integer(0));
        pdu.extend(integer(0));
        pdu.extend(tlv(0x30, &vars).unwrap());
        let mut msg = integer(1);
        msg.extend(tlv(0x04, b"private").unwrap());
        msg.extend(tlv(0xa2, &pdu).unwrap());
        let packet = tlv(0x30, &msg).unwrap();
        assert_eq!(parse_response(&packet, b"public", 9), None);
        assert_eq!(
            parse_response(&packet, b"private", 9)
                .unwrap()
                .sys_name
                .as_deref(),
            Some("router")
        );
    }
}
