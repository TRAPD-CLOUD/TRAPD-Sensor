//! DNS- und mDNS-Parser.
//!
//! Beide sprechen dasselbe Wire-Format; der Unterschied ist der Port (53 vs.
//! 5353) und was man damit anfängt: klassisches DNS liefert Auflösungsverhalten,
//! mDNS liefert Gerätenamen und beworbene Dienste.
//!
//! ## Namenskompression
//!
//! DNS erlaubt Zeiger auf frühere Namen. Naiv umgesetzt ist das eine
//! Endlosschleife, sobald ein Paket auf sich selbst zeigt — eine klassische
//! Parser-Falle. Hier gelten deshalb drei Regeln: ein Zeiger muss *rückwärts*
//! zeigen, die Zahl der Sprünge ist begrenzt, und die Zahl der Labels ebenso.
//!
//! ## Datensparsamkeit
//!
//! Gelesen werden Query-Namen, Antworttypen und Adressen. Der Sensor
//! rekonstruiert keine Sitzungen und speichert keine Payload; was er hier
//! weitergibt, entscheidet die Privacy-Policy im aufrufenden Modul.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::frame::be16;

pub const DNS_PORT: u16 = 53;
pub const MDNS_PORT: u16 = 5353;

pub const RTYPE_A: u16 = 1;
pub const RTYPE_PTR: u16 = 12;
pub const RTYPE_TXT: u16 = 16;
pub const RTYPE_AAAA: u16 = 28;
pub const RTYPE_SRV: u16 = 33;

/// Höchstens so viele Kompressions-Sprünge je Name.
const MAX_POINTER_JUMPS: usize = 16;
/// Höchstens so viele Labels je Name (DNS erlaubt 255 Byte gesamt).
const MAX_LABELS: usize = 64;
/// Höchstens so viele Einträge je Abschnitt — schützt vor aufgeblähten
/// Zählerfeldern in einem konstruierten Paket.
const MAX_RECORDS_PER_SECTION: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub response_code: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    /// Gemeldete Antwortzahl aus dem Header (kann über den geparsten Einträgen
    /// liegen, wenn das Paket durch den Snaplen gekürzt wurde).
    pub answer_count: u16,
}

impl DnsMessage {
    pub fn is_nxdomain(&self) -> bool {
        self.response_code == 3
    }

    pub fn response_code_name(&self) -> &'static str {
        match self.response_code {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => "OTHER",
        }
    }

    /// Alle in den Antworten enthaltenen Adressen.
    pub fn resolved_addresses(&self) -> Vec<std::net::IpAddr> {
        self.answers
            .iter()
            .filter_map(|r| match &r.data {
                DnsRecordData::A(ip) => Some(std::net::IpAddr::V4(*ip)),
                DnsRecordData::Aaaa(ip) => Some(std::net::IpAddr::V6(*ip)),
                _ => None,
            })
            .collect()
    }

    /// Von einem Gerät per mDNS beworbene Dienstnamen (PTR/SRV).
    pub fn advertised_services(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                DnsRecordData::Ptr(name) => Some(name.clone()),
                DnsRecordData::Srv { target, .. } => Some(target.clone()),
                _ => None,
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: DnsRecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    Txt(Vec<String>),
    Srv {
        port: u16,
        target: String,
    },
    /// Alles Übrige wird als Typ vermerkt, aber nicht ausgewertet.
    Other,
}

pub fn parse_dns(data: &[u8]) -> Option<DnsMessage> {
    // Der DNS-Header ist genau 12 Byte. Ohne diese Prüfung würde ein
    // 8-Byte-Fragment als gültige Nachricht mit null Fragen durchgehen — die
    // Zählerfelder wären dann schlicht nicht vorhanden statt null.
    if data.len() < 12 {
        return None;
    }
    let id = be16(data.get(0..2)?);
    let flags = be16(data.get(2..4)?);
    let qdcount = usize::from(be16(data.get(4..6)?));
    let ancount = be16(data.get(6..8)?);

    let is_response = flags & 0x8000 != 0;
    let response_code = (flags & 0x000f) as u8;

    let mut pos = 12;
    let mut questions = Vec::new();
    for _ in 0..qdcount.min(MAX_RECORDS_PER_SECTION) {
        let (name, next) = read_name(data, pos)?;
        let qtype = be16(data.get(next..next + 2)?);
        // qclass überspringen
        pos = next + 4;
        questions.push(DnsQuestion { name, qtype });
    }

    // Antworten sind Beiwerk: ein durch den Snaplen abgeschnittenes Paket soll
    // die bereits gelesene Frage nicht entwerten.
    let mut answers = Vec::new();
    for _ in 0..usize::from(ancount).min(MAX_RECORDS_PER_SECTION) {
        match read_record(data, pos) {
            Some((record, next)) => {
                answers.push(record);
                pos = next;
            }
            None => break,
        }
    }

    Some(DnsMessage {
        id,
        is_response,
        response_code,
        questions,
        answers,
        answer_count: ancount,
    })
}

fn read_record(data: &[u8], pos: usize) -> Option<(DnsRecord, usize)> {
    let (name, next) = read_name(data, pos)?;
    let rtype = be16(data.get(next..next + 2)?);
    let ttl = crate::frame::be32(data.get(next + 4..next + 8)?);
    let rdlength = usize::from(be16(data.get(next + 8..next + 10)?));
    let rdata_start = next + 10;
    let rdata = data.get(rdata_start..rdata_start + rdlength)?;

    let parsed = match rtype {
        RTYPE_A => <[u8; 4]>::try_from(rdata)
            .ok()
            .map(|b| DnsRecordData::A(Ipv4Addr::from(b)))
            .unwrap_or(DnsRecordData::Other),
        RTYPE_AAAA => <[u8; 16]>::try_from(rdata)
            .ok()
            .map(|b| DnsRecordData::Aaaa(Ipv6Addr::from(b)))
            .unwrap_or(DnsRecordData::Other),
        // PTR/SRV-Ziele dürfen komprimiert sein und damit in den Bereich vor
        // `rdata` zeigen — deshalb wird über das ganze Paket gelesen.
        RTYPE_PTR => read_name(data, rdata_start)
            .map(|(n, _)| DnsRecordData::Ptr(n))
            .unwrap_or(DnsRecordData::Other),
        RTYPE_SRV => {
            let port = be16(rdata.get(4..6)?);
            let target = read_name(data, rdata_start + 6)
                .map(|(n, _)| n)
                .unwrap_or_default();
            DnsRecordData::Srv { port, target }
        }
        RTYPE_TXT => DnsRecordData::Txt(read_txt_strings(rdata)),
        _ => DnsRecordData::Other,
    };

    Some((
        DnsRecord {
            name,
            rtype,
            ttl,
            data: parsed,
        },
        rdata_start + rdlength,
    ))
}

/// Liest einen (möglicherweise komprimierten) Namen.
///
/// Gibt den Namen und die Position *im Datenstrom* zurück, an der es nach dem
/// Namen weitergeht — bei einem Zeiger also hinter den zwei Zeigerbytes, nicht
/// hinter dem Sprungziel.
fn read_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = start;
    let mut jumps = 0usize;
    let mut stream_end: Option<usize> = None;

    loop {
        let len = *data.get(cursor)?;

        if len & 0xc0 == 0xc0 {
            let target = ((usize::from(len) & 0x3f) << 8) | usize::from(*data.get(cursor + 1)?);
            stream_end.get_or_insert(cursor + 2);
            // Ein Zeiger darf nur zurückweisen. Alles andere erlaubt Zyklen.
            if target >= cursor {
                return None;
            }
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return None;
            }
            cursor = target;
            continue;
        }

        if len == 0 {
            stream_end.get_or_insert(cursor + 1);
            break;
        }

        let label_start = cursor + 1;
        let label_end = label_start + usize::from(len);
        let label = data.get(label_start..label_end)?;
        labels.push(sanitize_label(label));
        cursor = label_end;

        if labels.len() > MAX_LABELS {
            return None;
        }
    }

    Some((labels.join("."), stream_end?))
}

/// Labels enthalten fremde Bytes. Nur druckbares ASCII wird übernommen —
/// Query-Namen landen in Logs und im Dashboard.
fn sanitize_label(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) && b != b'.' {
                (b as char).to_ascii_lowercase()
            } else {
                '?'
            }
        })
        .collect()
}

fn read_txt_strings(rdata: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(&len) = rdata.get(pos) {
        let start = pos + 1;
        let end = start + usize::from(len);
        let Some(chunk) = rdata.get(start..end) else {
            break;
        };
        let text: String = chunk
            .iter()
            .filter(|&&b| (0x20..0x7f).contains(&b))
            .map(|&b| b as char)
            .collect();
        if !text.is_empty() {
            out.push(text);
        }
        pos = end;
        if out.len() >= MAX_LABELS {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Kodiert einen Namen als DNS-Labels.
    fn name(n: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in n.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn header(id: u16, flags: u16, qdcount: u16, ancount: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&qdcount.to_be_bytes());
        out.extend_from_slice(&ancount.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // nscount
        out.extend_from_slice(&0u16.to_be_bytes()); // arcount
        out
    }

    fn query(n: &str, qtype: u16) -> Vec<u8> {
        let mut out = header(0x1234, 0x0100, 1, 0);
        out.extend_from_slice(&name(n));
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out
    }

    #[test]
    fn query_name_and_type_are_extracted() {
        let packet = query("example.com", RTYPE_A);
        let msg = parse_dns(&packet).expect("parse");

        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, RTYPE_A);
        assert_eq!(msg.response_code_name(), "NOERROR");
    }

    #[test]
    fn names_are_lowercased() {
        let packet = query("ExAmPlE.CoM", RTYPE_A);
        let msg = parse_dns(&packet).expect("parse");
        assert_eq!(msg.questions[0].name, "example.com");
    }

    #[test]
    fn a_record_answers_are_resolved() {
        let mut packet = header(1, 0x8180, 1, 1);
        packet.extend_from_slice(&name("host.local"));
        packet.extend_from_slice(&RTYPE_A.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        // Antwort mit Zeiger auf den Namen in der Frage (Offset 12).
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&RTYPE_A.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[93, 184, 216, 34]);

        let msg = parse_dns(&packet).expect("parse");
        assert!(msg.is_response);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "host.local", "pointer resolved");
        assert_eq!(msg.answers[0].ttl, 300);
        assert_eq!(
            msg.resolved_addresses(),
            vec!["93.184.216.34".parse::<std::net::IpAddr>().expect("ip")]
        );
    }

    #[test]
    fn aaaa_records_are_resolved() {
        let mut packet = header(1, 0x8180, 0, 1);
        packet.extend_from_slice(&name("v6.example"));
        packet.extend_from_slice(&RTYPE_AAAA.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&16u16.to_be_bytes());
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let msg = parse_dns(&packet).expect("parse");
        assert_eq!(
            msg.resolved_addresses(),
            vec!["2001:db8::1".parse::<std::net::IpAddr>().expect("ip")]
        );
    }

    #[test]
    fn nxdomain_is_recognised() {
        let mut packet = header(1, 0x8183, 1, 0); // rcode 3
        packet.extend_from_slice(&name("nope.invalid"));
        packet.extend_from_slice(&RTYPE_A.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        let msg = parse_dns(&packet).expect("parse");
        assert!(msg.is_nxdomain());
        assert_eq!(msg.response_code_name(), "NXDOMAIN");
    }

    #[test]
    fn mdns_ptr_and_srv_reveal_advertised_services() {
        let mut packet = header(0, 0x8400, 0, 2);
        // PTR: _airplay._tcp.local → Apple TV._airplay._tcp.local
        packet.extend_from_slice(&name("_airplay._tcp.local"));
        packet.extend_from_slice(&RTYPE_PTR.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        let ptr_target = name("appletv._airplay._tcp.local");
        packet.extend_from_slice(&(ptr_target.len() as u16).to_be_bytes());
        packet.extend_from_slice(&ptr_target);

        // SRV mit Port 7000
        packet.extend_from_slice(&name("appletv._airplay._tcp.local"));
        packet.extend_from_slice(&RTYPE_SRV.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        let srv_target = name("appletv.local");
        packet.extend_from_slice(&((6 + srv_target.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes()); // priority
        packet.extend_from_slice(&0u16.to_be_bytes()); // weight
        packet.extend_from_slice(&7000u16.to_be_bytes());
        packet.extend_from_slice(&srv_target);

        let msg = parse_dns(&packet).expect("parse");
        assert_eq!(msg.answers.len(), 2);
        assert_eq!(
            msg.answers[0].data,
            DnsRecordData::Ptr("appletv._airplay._tcp.local".into())
        );
        assert_eq!(
            msg.answers[1].data,
            DnsRecordData::Srv {
                port: 7000,
                target: "appletv.local".into()
            }
        );
        assert!(msg
            .advertised_services()
            .contains(&"appletv._airplay._tcp.local".to_string()));
    }

    #[test]
    fn txt_records_are_split_into_strings() {
        let mut packet = header(0, 0x8400, 0, 1);
        packet.extend_from_slice(&name("printer._ipp._tcp.local"));
        packet.extend_from_slice(&RTYPE_TXT.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());

        let mut rdata = Vec::new();
        for s in ["ty=HP LaserJet", "product=(HP)"] {
            rdata.push(s.len() as u8);
            rdata.extend_from_slice(s.as_bytes());
        }
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);

        let msg = parse_dns(&packet).expect("parse");
        assert_eq!(
            msg.answers[0].data,
            DnsRecordData::Txt(vec!["ty=HP LaserJet".into(), "product=(HP)".into()])
        );
    }

    /// Ein Zeiger auf sich selbst ist der Klassiker unter den DNS-Parser-Bomben.
    #[test]
    fn self_referential_pointer_does_not_hang() {
        let mut packet = header(1, 0x0100, 1, 0);
        packet.extend_from_slice(&[0xc0, 0x0c]); // Offset 12 = diese Position
        packet.extend_from_slice(&RTYPE_A.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        assert!(parse_dns(&packet).is_none(), "must refuse, not loop");
    }

    #[test]
    fn forward_pointer_is_refused() {
        let mut packet = header(1, 0x0100, 1, 0);
        packet.extend_from_slice(&[0xc0, 0x20]); // zeigt nach vorne
        packet.extend_from_slice(&RTYPE_A.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.resize(64, 0);

        assert!(parse_dns(&packet).is_none());
    }

    #[test]
    fn pointer_chains_are_bounded() {
        // Kette rückwärts zeigender Zeiger, länger als erlaubt.
        let mut packet = header(1, 0x0100, 1, 0);
        packet.push(1);
        packet.push(b'a');
        packet.push(0);
        let mut previous = 12u16;
        for _ in 0..MAX_POINTER_JUMPS + 4 {
            let here = packet.len() as u16;
            packet.extend_from_slice(&(0xc000 | previous).to_be_bytes());
            previous = here;
        }
        // Die Frage beginnt am letzten Zeiger.
        let mut with_question = header(1, 0x0100, 1, 0);
        with_question.extend_from_slice(&packet[12..]);

        // Terminiert in jedem Fall — ob mit None oder mit gekürztem Ergebnis.
        let _ = parse_dns(&with_question);
    }

    #[test]
    fn truncated_answers_do_not_discard_the_question() {
        // Header behauptet 5 Antworten, das Paket endet nach der Frage —
        // genau das passiert bei einem knappen Snaplen.
        let mut packet = header(1, 0x8180, 1, 5);
        packet.extend_from_slice(&name("cut.example"));
        packet.extend_from_slice(&RTYPE_A.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        let msg = parse_dns(&packet).expect("parse");
        assert_eq!(msg.questions[0].name, "cut.example");
        assert!(msg.answers.is_empty());
        assert_eq!(msg.answer_count, 5, "the header count is reported as seen");
    }

    #[test]
    fn label_with_control_bytes_is_sanitised() {
        let mut packet = header(1, 0x0100, 1, 0);
        packet.push(4);
        packet.extend_from_slice(&[b'a', 0x00, 0x1b, b'b']);
        packet.push(0);
        packet.extend_from_slice(&RTYPE_A.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        let msg = parse_dns(&packet).expect("parse");
        assert_eq!(msg.questions[0].name, "a??b");
    }

    #[test]
    fn truncated_headers_return_none() {
        for len in 0..12 {
            assert!(parse_dns(&vec![0u8; len]).is_none(), "len {len}");
        }
    }

    #[test]
    fn absurd_question_counts_are_bounded() {
        let mut packet = header(1, 0x0100, u16::MAX, 0);
        packet.extend_from_slice(&name("a.b"));
        packet.extend_from_slice(&RTYPE_A.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        // Nach der einen echten Frage ist Schluss; das Ergebnis ist None
        // (unvollständig), aber der Parser terminiert.
        let _ = parse_dns(&packet);
    }
}
