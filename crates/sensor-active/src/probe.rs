//! Die aktiven Proben.
//!
//! Alles hier erzeugt Pakete — und läuft deshalb nur unter drei Bedingungen:
//! der Betriebsmodus erlaubt es, der Betreiber hat quittiert, und das Ziel
//! liegt in einem freigegebenen CIDR. Geprüft wird das nicht hier, sondern
//! zentral in [`EffectivePolicy::may_probe`](trapd_sensor_core::EffectivePolicy::may_probe);
//! dieses Modul führt aus, was der [`Scanner`](crate::scanner::Scanner) freigegeben hat.
//!
//! Die Verfahren sind bewusst die unauffälligsten, die es gibt:
//!
//! * **ICMP Echo** — dasselbe, was `ping` tut.
//! * **TCP Connect** — ein vollständiger Verbindungsaufbau über den normalen
//!   Socket-Pfad, danach sauberer Abbau. Kein SYN-Stealth mit Raw Sockets: das
//!   hinterlässt halboffene Verbindungen und ist genau die Technik, die ein
//!   Werkzeug zum Scanner macht.
//! * **Banner** — lesen, was der Dienst von sich aus schickt. Es wird nichts
//!   gesendet, um eine Antwort zu provozieren.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Ergebnis einer TCP-Probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    /// Verbindung kam zustande.
    Open,
    /// Aktiv abgelehnt (RST) — der Host lebt, der Port ist zu.
    Closed,
    /// Keine Antwort im Zeitfenster.
    Filtered,
}

#[derive(Debug, Clone)]
pub struct PortProbeResult {
    pub port: u16,
    pub state: PortState,
    /// Nur bei `Open` und nur, wenn Banner-Grab erlaubt ist.
    pub banner: Option<String>,
}

/// Baut eine TCP-Verbindung auf und baut sie sofort wieder ab.
pub async fn tcp_connect(ip: IpAddr, port: u16, timeout: Duration) -> PortProbeResult {
    let addr = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            PortProbeResult {
                port,
                state: PortState::Open,
                banner: None,
            }
        }
        // Ein abgelehnter Verbindungsversuch ist ebenfalls Information: der Host
        // ist erreichbar, nur dieser Dienst läuft nicht.
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => PortProbeResult {
            port,
            state: PortState::Closed,
            banner: None,
        },
        Ok(Err(_)) | Err(_) => PortProbeResult {
            port,
            state: PortState::Filtered,
            banner: None,
        },
    }
}

/// Wie viele Bytes höchstens aus einem Banner gelesen werden.
const BANNER_READ_LIMIT: usize = 512;

/// Verbindet und liest, was der Dienst unaufgefordert schickt.
///
/// Es wird **nichts** gesendet. Viele Dienste (SSH, SMTP, FTP) begrüßen von
/// selbst; wer schweigt, bleibt unbeschrieben. Ein Probe-Payload zu senden, um
/// eine Antwort zu erzwingen, wäre die Grenze zum Scanner — und bei
/// empfindlichen Geräten (OT, alte Drucker) ein echtes Risiko.
pub async fn tcp_banner(ip: IpAddr, port: u16, timeout: Duration) -> PortProbeResult {
    let addr = SocketAddr::new(ip, port);
    let connect = tokio::time::timeout(timeout, TcpStream::connect(addr)).await;

    let mut stream = match connect {
        Ok(Ok(s)) => s,
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            return PortProbeResult {
                port,
                state: PortState::Closed,
                banner: None,
            }
        }
        Ok(Err(_)) | Err(_) => {
            return PortProbeResult {
                port,
                state: PortState::Filtered,
                banner: None,
            }
        }
    };

    let mut buf = vec![0u8; BANNER_READ_LIMIT];
    let banner = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => trapd_sensor_core::model::sanitize_banner(&buf[..n]),
        _ => None,
    };

    PortProbeResult {
        port,
        state: PortState::Open,
        banner,
    }
}

/// Schickt ein ICMP Echo Request und wartet auf die Antwort.
///
/// Genutzt wird — wo möglich — ein "Ping-Socket" (`SOCK_DGRAM` +
/// `IPPROTO_ICMP`). Den darf ein unprivilegierter Prozess öffnen, sofern
/// `net.ipv4.ping_group_range` seine Gruppe einschließt; der Kernel erledigt
/// dabei ID-Vergabe und Zuordnung. Fällt das aus, wird auf einen Raw Socket
/// zurückgegriffen, der `CAP_NET_RAW` braucht.
pub async fn icmp_echo(ip: IpAddr, timeout: Duration) -> io::Result<bool> {
    let IpAddr::V4(target) = ip else {
        // IPv6-Erreichbarkeit wird passiv über NDP ermittelt; ein eigener
        // ICMPv6-Pfad lohnt den zusätzlichen unsafe-Code hier nicht.
        return Ok(false);
    };

    tokio::task::spawn_blocking(move || icmp_echo_blocking(target, timeout))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?
}

fn icmp_echo_blocking(target: std::net::Ipv4Addr, timeout: Duration) -> io::Result<bool> {
    let socket = IcmpSocket::open()?;
    socket.set_timeout(timeout)?;

    let id = (std::process::id() & 0xffff) as u16;
    let seq = 1u16;
    let request = build_echo_request(id, seq);
    socket.send_to(&request, target)?;

    let mut buf = [0u8; 256];
    match socket.recv(&mut buf) {
        Ok(n) => Ok(is_echo_reply(&buf[..n])),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Baut ein ICMP Echo Request (Typ 8) mit korrekter Prüfsumme.
pub fn build_echo_request(id: u16, seq: u16) -> Vec<u8> {
    let mut packet = vec![
        8, // Type: Echo Request
        0, // Code
        0, 0, // Checksum (später)
    ];
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    // Kleine, feste Nutzlast — genug, damit gängige Stacks antworten.
    packet.extend_from_slice(b"TRAPD-SENSOR");

    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Ist das eine Echo-Antwort? Der Kernel liefert beim Ping-Socket den reinen
/// ICMP-Teil, beim Raw Socket den vollständigen IP-Header davor.
pub fn is_echo_reply(data: &[u8]) -> bool {
    if data.first() == Some(&0) {
        return true;
    }
    if data.first().map(|b| b >> 4) == Some(4) {
        let header_len = usize::from(data[0] & 0x0f) * 4;
        return data.get(header_len) == Some(&0);
    }
    false
}

/// Prüfsumme nach RFC 1071.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Dünner Wrapper um einen ICMP-Socket.
struct IcmpSocket {
    fd: libc::c_int,
}

impl IcmpSocket {
    fn open() -> io::Result<Self> {
        // Zuerst der unprivilegierte Weg.
        // SAFETY: reiner Syscall mit Konstanten, Rückgabewert wird geprüft.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMP,
            )
        };
        if fd >= 0 {
            return Ok(Self { fd });
        }

        // SAFETY: wie oben; braucht CAP_NET_RAW.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMP,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        // SAFETY: gültiger Zeiger auf ein `timeval` mit passender Längenangabe.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn send_to(&self, data: &[u8], target: std::net::Ipv4Addr) -> io::Result<()> {
        // SAFETY: genullte `sockaddr_in`, nur gültige Felder gesetzt; die an
        // sendto() übergebene Länge passt zum Typ.
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from_ne_bytes(target.octets());

        let sent = unsafe {
            libc::sendto(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` ist ein gültiger, beschreibbarer Slice.
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl Drop for IcmpSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` stammt aus socket() und wird genau einmal geschlossen.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn checksum_matches_rfc1071_example() {
        // Bekanntes Beispiel aus RFC 1071, Abschnitt 3.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_handles_an_odd_length() {
        // Darf nicht panicken und muss stabil sein.
        let a = internet_checksum(&[0x01, 0x02, 0x03]);
        let b = internet_checksum(&[0x01, 0x02, 0x03]);
        assert_eq!(a, b);
    }

    #[test]
    fn echo_request_is_well_formed_and_self_consistent() {
        let packet = build_echo_request(0x1234, 7);

        assert_eq!(packet[0], 8, "type must be Echo Request");
        assert_eq!(packet[1], 0, "code must be 0");
        assert_eq!(&packet[4..6], &0x1234u16.to_be_bytes());
        assert_eq!(&packet[6..8], &7u16.to_be_bytes());

        // Über ein Paket mit gültiger Prüfsumme gerechnet ergibt sich 0.
        assert_eq!(
            internet_checksum(&packet),
            0,
            "a packet carrying its own checksum must verify to zero"
        );
    }

    #[test]
    fn echo_replies_are_recognised_in_both_socket_flavours() {
        // Ping-Socket: reiner ICMP-Teil.
        assert!(is_echo_reply(&[0, 0, 0, 0, 0, 1, 0, 1]));

        // Raw Socket: IPv4-Header (20 Byte) davor.
        let mut raw = vec![
            0x45u8, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        ];
        raw.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 1]);
        assert!(is_echo_reply(&raw));

        // Destination Unreachable (Typ 3) ist keine Echo-Antwort.
        assert!(!is_echo_reply(&[3, 1, 0, 0]));
        assert!(!is_echo_reply(&[]));
    }

    #[tokio::test]
    async fn connect_probe_finds_a_listening_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = tcp_connect(addr.ip(), addr.port(), Duration::from_secs(2)).await;
        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.port, addr.port());
        assert_eq!(result.banner, None, "a connect probe reads nothing");
    }

    #[tokio::test]
    async fn connect_probe_reports_a_refused_port_as_closed() {
        // Einen Port binden und sofort freigeben — danach lehnt der Kernel ab.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        let result = tcp_connect(addr.ip(), addr.port(), Duration::from_secs(2)).await;
        assert_eq!(
            result.state,
            PortState::Closed,
            "a refused connection proves the host is up"
        );
    }

    #[tokio::test]
    async fn probe_timeout_yields_filtered() {
        // 203.0.113.0/24 ist für Dokumentation reserviert und wird nicht geroutet.
        let result = tcp_connect(
            "203.0.113.1".parse().expect("ip"),
            9,
            Duration::from_millis(150),
        )
        .await;
        assert_eq!(result.state, PortState::Filtered);
    }

    #[tokio::test]
    async fn banner_grab_reads_what_the_service_offers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.2p1\r\n").await;
            }
        });

        let result = tcp_banner(addr.ip(), addr.port(), Duration::from_secs(2)).await;
        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.banner.as_deref(), Some("SSH-2.0-OpenSSH_9.2p1"));
    }

    #[tokio::test]
    async fn a_silent_service_yields_no_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                // Verbindung offen halten, aber schweigen.
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(stream);
            }
        });

        let result = tcp_banner(addr.ip(), addr.port(), Duration::from_millis(200)).await;
        assert_eq!(result.state, PortState::Open, "the port is still open");
        assert_eq!(
            result.banner, None,
            "nothing is sent to coax an answer out of a silent service"
        );
    }

    #[tokio::test]
    async fn oversized_banners_are_truncated() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(&vec![b'A'; 10_000]).await;
            }
        });

        let result = tcp_banner(addr.ip(), addr.port(), Duration::from_secs(2)).await;
        let banner = result.banner.expect("banner");
        assert!(
            banner.len() <= trapd_sensor_core::model::MAX_BANNER_LEN,
            "a banner is an identification hint, not a data channel"
        );
    }

    #[tokio::test]
    async fn icmp_to_ipv6_is_not_attempted() {
        let reachable = icmp_echo("::1".parse().expect("ip"), Duration::from_millis(100))
            .await
            .expect("no error");
        assert!(!reachable, "IPv6 reachability comes from passive NDP");
    }
}
