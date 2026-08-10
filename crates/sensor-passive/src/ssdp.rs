//! SSDP-/UPnP-Beobachtung.
//!
//! SSDP ist HTTP-artiger Klartext über UDP 1900. Geräte kündigen sich dort von
//! selbst an — mit Gerätetyp (`NT`/`ST`), Betriebssystem-/Stack-Kennung
//! (`SERVER`) und einer Beschreibungs-URL (`LOCATION`). Für die Erkennung von
//! IoT-Geräten, Smart-TVs, Druckern und NAS ist das die ergiebigste passive
//! Quelle nach mDNS.
//!
//! Der Sensor liest nur die Kopfzeilen. Die `LOCATION`-URL wird **nicht**
//! abgerufen: das wäre eine aktive Handlung und gehört damit nicht in den
//! passiven Pfad — auch nicht "nur einmal kurz".

use std::collections::BTreeMap;

pub const SSDP_PORT: u16 = 1900;

/// Obergrenzen gegen aufgeblähte Nachrichten.
const MAX_HEADERS: usize = 32;
const MAX_VALUE_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsdpKind {
    /// Gerät kündigt sich an (`NOTIFY`).
    Notify,
    /// Jemand sucht Geräte (`M-SEARCH`).
    Search,
    /// Antwort auf eine Suche.
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpMessage {
    pub kind: SsdpKind,
    /// Kopfzeilen mit großgeschriebenen Namen.
    pub headers: BTreeMap<String, String>,
}

impl SsdpMessage {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_uppercase())
            .map(|s| s.as_str())
    }

    /// Gerätetyp: `NT` bei Ankündigungen, `ST` bei Antworten.
    pub fn device_type(&self) -> Option<&str> {
        self.header("NT").or_else(|| self.header("ST"))
    }

    /// `SERVER` trägt typischerweise `OS/Version UPnP/1.0 Produkt/Version` —
    /// der brauchbarste Einzelhinweis in einer SSDP-Nachricht.
    pub fn server(&self) -> Option<&str> {
        self.header("SERVER")
    }

    pub fn location(&self) -> Option<&str> {
        self.header("LOCATION")
    }

    pub fn usn(&self) -> Option<&str> {
        self.header("USN")
    }

    /// Sagt diese Nachricht etwas über das *sendende* Gerät aus?
    ///
    /// Eine Suche (`M-SEARCH`) tut das kaum: sie verrät nur, dass jemand sucht.
    /// Daraus ein Gerät abzuleiten, produziert Rauschen statt Erkenntnis.
    pub fn describes_sender(&self) -> bool {
        matches!(self.kind, SsdpKind::Notify | SsdpKind::Response)
    }
}

pub fn parse_ssdp(data: &[u8]) -> Option<SsdpMessage> {
    // Nur ASCII-Klartext; alles andere ist kein SSDP.
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));

    let start_line = lines.next()?.trim();
    let kind = if start_line.starts_with("NOTIFY") {
        SsdpKind::Notify
    } else if start_line.starts_with("M-SEARCH") {
        SsdpKind::Search
    } else if start_line.starts_with("HTTP/1.") {
        SsdpKind::Response
    } else {
        return None;
    };

    let mut headers = BTreeMap::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if headers.len() >= MAX_HEADERS {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_uppercase();
        let value: String = value
            .trim()
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(MAX_VALUE_LEN)
            .collect();
        if name.is_empty() || value.is_empty() {
            continue;
        }
        headers.entry(name).or_insert(value);
    }

    Some(SsdpMessage { kind, headers })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOTIFY: &str = concat!(
        "NOTIFY * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "CACHE-CONTROL: max-age=1800\r\n",
        "LOCATION: http://192.168.1.60:8080/description.xml\r\n",
        "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n",
        "NTS: ssdp:alive\r\n",
        "SERVER: Linux/4.9 UPnP/1.0 Samsung-TV/2.0\r\n",
        "USN: uuid:abcd-1234::urn:schemas-upnp-org:device:MediaRenderer:1\r\n",
        "\r\n"
    );

    #[test]
    fn notify_reveals_device_type_and_server() {
        let msg = parse_ssdp(NOTIFY.as_bytes()).expect("parse");

        assert_eq!(msg.kind, SsdpKind::Notify);
        assert!(msg.describes_sender());
        assert_eq!(
            msg.device_type(),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1")
        );
        assert_eq!(msg.server(), Some("Linux/4.9 UPnP/1.0 Samsung-TV/2.0"));
        assert_eq!(
            msg.location(),
            Some("http://192.168.1.60:8080/description.xml")
        );
        assert!(msg.usn().is_some());
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let msg = parse_ssdp(NOTIFY.as_bytes()).expect("parse");
        assert_eq!(msg.header("server"), msg.header("SERVER"));
        assert_eq!(msg.header("Location"), msg.location());
    }

    #[test]
    fn search_requests_describe_nobody() {
        let search = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\n\r\n";
        let msg = parse_ssdp(search.as_bytes()).expect("parse");

        assert_eq!(msg.kind, SsdpKind::Search);
        assert!(
            !msg.describes_sender(),
            "a search says nothing about the searcher's device type"
        );
    }

    #[test]
    fn search_response_falls_back_to_st() {
        let response = "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:Printer:1\r\nSERVER: HP/1.0\r\n\r\n";
        let msg = parse_ssdp(response.as_bytes()).expect("parse");

        assert_eq!(msg.kind, SsdpKind::Response);
        assert!(msg.describes_sender());
        assert_eq!(
            msg.device_type(),
            Some("urn:schemas-upnp-org:device:Printer:1")
        );
    }

    #[test]
    fn bare_newlines_are_accepted() {
        let msg = parse_ssdp(b"NOTIFY * HTTP/1.1\nNT: test\nSERVER: x\n").expect("parse");
        assert_eq!(msg.device_type(), Some("test"));
    }

    #[test]
    fn non_ssdp_payloads_are_rejected() {
        assert!(parse_ssdp(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
        assert!(
            parse_ssdp(&[0xff, 0xfe, 0x00]).is_none(),
            "binary is not SSDP"
        );
        assert!(parse_ssdp(b"").is_none());
    }

    #[test]
    fn header_values_are_sanitised_and_bounded() {
        let mut raw = String::from("NOTIFY * HTTP/1.1\r\n");
        raw.push_str(&format!("SERVER: {}\r\n", "A".repeat(1000)));
        raw.push_str("NT: ok\r\n\r\n");

        let msg = parse_ssdp(raw.as_bytes()).expect("parse");
        assert_eq!(msg.server().expect("server").len(), MAX_VALUE_LEN);
    }

    #[test]
    fn header_floods_are_bounded() {
        let mut raw = String::from("NOTIFY * HTTP/1.1\r\n");
        for i in 0..500 {
            raw.push_str(&format!("X-Custom-{i}: value\r\n"));
        }
        let msg = parse_ssdp(raw.as_bytes()).expect("parse");
        assert!(msg.headers.len() <= MAX_HEADERS);
    }

    #[test]
    fn duplicate_headers_keep_the_first_value() {
        let raw = "NOTIFY * HTTP/1.1\r\nNT: first\r\nNT: second\r\n\r\n";
        let msg = parse_ssdp(raw.as_bytes()).expect("parse");
        assert_eq!(msg.device_type(), Some("first"));
    }

    #[test]
    fn lines_without_a_colon_are_skipped() {
        let raw = "NOTIFY * HTTP/1.1\r\ngarbage line\r\nNT: still-here\r\n\r\n";
        let msg = parse_ssdp(raw.as_bytes()).expect("parse");
        assert_eq!(msg.device_type(), Some("still-here"));
    }
}
