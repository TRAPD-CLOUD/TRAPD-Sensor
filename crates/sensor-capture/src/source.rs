//! Paketquelle: ein `AF_PACKET`-Socket je Interface.
//!
//! Der Socket wird bewusst direkt über `libc` geöffnet statt über eine
//! Capture-Bibliothek. Das hält die Abhängigkeitskette kurz (ein Sensor mit
//! erhöhten Rechten sollte wenig fremden Code enthalten) und gibt Zugriff auf
//! `PACKET_STATISTICS` — die vom Kernel verworfenen Pakete sind der ehrlichste
//! Überlastindikator, den wir haben, und gehören in den Heartbeat.
//!
//! ## Filterung
//!
//! Gefiltert wird in v0.1 im Userspace ([`trapd-sensor-passive`]), nicht per
//! `SO_ATTACH_FILTER` im Kernel. Der Parser verwirft uninteressante Pakete nach
//! wenigen Byte-Vergleichen, was für Homelab-Lasten reicht; ein handgeschriebenes
//! BPF-Programm wäre schwer zu prüfen und ein stiller Fehler darin würde
//! Verkehr unbemerkt verschlucken. Die Naht dafür ist [`AfPacketSource::open`] —
//! ein Kernel-Filter lässt sich dort nachrüsten, ohne den Rest anzufassen.
//! Bei höheren Lasten (siehe Performance-Ziele) ist das die erste Stellschraube.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::time::Duration;

use crate::error::{CaptureError, Result};

/// Zähler eines Interfaces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureStats {
    pub packets_captured: u64,
    /// Vom Kernel verworfen, weil der Empfangspuffer voll war.
    pub packets_dropped: u64,
    pub bytes_captured: u64,
}

/// Woher der Sensor Pakete bekommt.
pub trait PacketSource: Send {
    fn interface(&self) -> &str;

    /// Liest das nächste Paket. `Ok(0)` bedeutet "Timeout, nichts da" — kein
    /// Fehler, sondern der Normalfall in einem ruhigen Netz.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;

    fn stats(&mut self) -> CaptureStats;
}

/// Ein `AF_PACKET`-Socket im Promiscuous-Modus.
pub struct AfPacketSource {
    fd: RawFd,
    interface: String,
    promiscuous: bool,
    stats: CaptureStats,
}

impl AfPacketSource {
    /// Öffnet einen Capture-Socket auf `interface`.
    ///
    /// Benötigt `CAP_NET_RAW`; für `promiscuous` zusätzlich `CAP_NET_ADMIN`.
    /// Fehlen sie, kommt ein `PermissionDenied` mit dem Hinweis darauf zurück —
    /// das ist der mit Abstand häufigste Fehlstart eines Sensors.
    pub fn open(interface: &str, promiscuous: bool, read_timeout: Duration) -> Result<Self> {
        let ifindex = if_nametoindex(interface)?;

        // SAFETY: reiner Syscall mit Konstanten; der Rückgabewert wird geprüft.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(if err.kind() == io::ErrorKind::PermissionDenied {
                CaptureError::MissingCapability {
                    interface: interface.to_string(),
                    needed: "CAP_NET_RAW",
                }
            } else {
                CaptureError::Open {
                    interface: interface.to_string(),
                    source: err,
                }
            });
        }

        let mut source = Self {
            fd,
            interface: interface.to_string(),
            promiscuous: false,
            stats: CaptureStats::default(),
        };

        source.bind(ifindex)?;
        source.set_read_timeout(read_timeout)?;
        if promiscuous {
            source.enable_promiscuous(ifindex)?;
        }

        tracing::info!(
            interface,
            promiscuous = source.promiscuous,
            "capture socket ready"
        );
        Ok(source)
    }

    fn bind(&self, ifindex: u32) -> Result<()> {
        // SAFETY: `sockaddr_ll` wird vollständig genullt und nur mit gültigen
        // Werten befüllt; die an bind() übergebene Länge passt zum Typ.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex as i32;

        let rc = unsafe {
            libc::bind(
                self.fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(CaptureError::Open {
                interface: self.interface.clone(),
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    /// Timeout statt blockierendem Empfang: die Capture-Schleife muss auch in
    /// einem stillen Netz regelmäßig auf das Shutdown-Signal schauen können.
    fn set_read_timeout(&self, timeout: Duration) -> Result<()> {
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
            return Err(CaptureError::Open {
                interface: self.interface.clone(),
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn enable_promiscuous(&mut self, ifindex: u32) -> Result<()> {
        // SAFETY: genullte `packet_mreq`, nur gültige Felder gesetzt.
        let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
        mreq.mr_ifindex = ifindex as i32;
        mreq.mr_type = libc::PACKET_MR_PROMISC as u16;

        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq as *const libc::packet_mreq as *const libc::c_void,
                std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::PermissionDenied {
                return Err(CaptureError::MissingCapability {
                    interface: self.interface.clone(),
                    needed: "CAP_NET_ADMIN",
                });
            }
            return Err(CaptureError::Open {
                interface: self.interface.clone(),
                source: err,
            });
        }
        self.promiscuous = true;
        Ok(())
    }

    pub fn is_promiscuous(&self) -> bool {
        self.promiscuous
    }

    /// Holt die Kernel-Zähler. Der Kernel setzt sie beim Lesen zurück, daher
    /// werden sie hier aufsummiert — sonst zeigte der Heartbeat nur das
    /// Intervall seit dem letzten Abruf.
    fn refresh_kernel_stats(&mut self) {
        // SAFETY: genullte Struktur, `len` passt; Rückgabewert wird geprüft.
        let mut stats: libc::tpacket_stats = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut stats as *mut libc::tpacket_stats as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 {
            self.stats.packets_dropped += u64::from(stats.tp_drops);
        }
    }
}

impl PacketSource for AfPacketSource {
    fn interface(&self) -> &str {
        &self.interface
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        // SAFETY: `buf` ist ein gültiger, beschreibbarer Slice der angegebenen Länge.
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                // Kein Paket im Zeitfenster — der Normalfall.
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Ok(0),
                // Durch ein Signal unterbrochen; der Aufrufer versucht es erneut.
                io::ErrorKind::Interrupted => Ok(0),
                _ => Err(CaptureError::Read {
                    interface: self.interface.clone(),
                    source: err,
                }),
            };
        }
        let n = n as usize;
        if n > 0 {
            self.stats.packets_captured += 1;
            self.stats.bytes_captured += n as u64;
        }
        Ok(n)
    }

    fn stats(&mut self) -> CaptureStats {
        self.refresh_kernel_stats();
        self.stats
    }
}

impl Drop for AfPacketSource {
    fn drop(&mut self) {
        // Die Promiscuous-Mitgliedschaft räumt der Kernel beim Schließen des
        // Sockets selbst ab — ein explizites DROP_MEMBERSHIP wäre redundant und
        // im Fehlerfall irreführend.
        // SAFETY: `fd` stammt aus socket() und wird genau einmal geschlossen.
        unsafe { libc::close(self.fd) };
    }
}

// SAFETY: der Typ besitzt nur einen Dateideskriptor und wird immer von genau
// einem Thread verwendet (eine Capture-Task je Interface).
unsafe impl Send for AfPacketSource {}

/// Quelle, die nie ein Paket liefert.
///
/// Für Tests und für den Fall, dass ein konfiguriertes Interface nicht geöffnet
/// werden kann: der Daemon läuft dann degradiert weiter (und meldet das), statt
/// wegen eines Interfaces komplett auszufallen.
pub struct NullSource {
    interface: String,
}

impl NullSource {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
        }
    }
}

impl PacketSource for NullSource {
    fn interface(&self) -> &str {
        &self.interface
    }

    fn recv(&mut self, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn stats(&mut self) -> CaptureStats {
        CaptureStats::default()
    }
}

fn if_nametoindex(name: &str) -> Result<u32> {
    let cname = CString::new(name).map_err(|_| CaptureError::UnknownInterface {
        interface: name.to_string(),
    })?;
    // SAFETY: `cname` ist ein gültiger, nullterminierter C-String.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(CaptureError::UnknownInterface {
            interface: name.to_string(),
        });
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_interfaces_are_reported_as_such() {
        let err = if_nametoindex("definitely-not-an-interface-0").expect_err("should fail");
        assert!(matches!(err, CaptureError::UnknownInterface { .. }));
    }

    #[test]
    fn interface_names_with_nul_bytes_are_rejected() {
        assert!(matches!(
            if_nametoindex("eth0\0extra"),
            Err(CaptureError::UnknownInterface { .. })
        ));
    }

    #[test]
    fn loopback_resolves_to_an_index() {
        // `lo` gibt es auf jedem Linux-System, auch im Container.
        let index = if_nametoindex("lo").expect("loopback must exist");
        assert!(index > 0);
    }

    #[test]
    fn null_source_yields_nothing_and_stays_quiet() {
        let mut source = NullSource::new("eth0");
        let mut buf = [0u8; 128];
        assert_eq!(source.interface(), "eth0");
        assert_eq!(source.recv(&mut buf).expect("recv"), 0);
        assert_eq!(source.stats(), CaptureStats::default());
    }

    /// Ohne `CAP_NET_RAW` muss der Fehler auf die fehlende Capability zeigen —
    /// eine nackte "Permission denied"-Meldung schickt Betreiber sonst auf die
    /// falsche Fährte (Dateirechte statt Capabilities).
    #[test]
    fn opening_without_privileges_names_the_missing_capability() {
        match AfPacketSource::open("lo", false, Duration::from_millis(10)) {
            Err(CaptureError::MissingCapability { needed, .. }) => {
                assert_eq!(needed, "CAP_NET_RAW");
            }
            // Läuft der Test doch mit Rechten, ist das ebenfalls in Ordnung.
            Ok(source) => assert_eq!(source.interface(), "lo"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
