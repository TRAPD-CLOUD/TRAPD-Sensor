//! Paketaufnahme für den TRAPD Network Sensor.
//!
//! Zwei Bausteine: die Erkennung brauchbarer Interfaces und ein `AF_PACKET`-
//! Socket je Interface. Was mit den Bytes passiert, entscheidet
//! `trapd-sensor-passive` — dieses Crate liefert nur rohe Frames und die
//! Kernel-Zähler dazu.
//!
//! Rechte: `CAP_NET_RAW` für den Socket, zusätzlich `CAP_NET_ADMIN` für den
//! Promiscuous-Modus. Beides wird über die systemd-Unit als Ambient Capability
//! vergeben — der Sensor läuft nicht als root.

pub mod error;
pub mod interface;
pub mod source;

pub use error::{CaptureError, Result};
pub use interface::{list_interfaces, select_interfaces, Interface};
pub use source::{AfPacketSource, CaptureStats, NullSource, PacketSource};

/// Empfehlung für `capture.snaplen`: Ethernet-, VLAN-, IP- und Transportheader
/// plus Platz für die Klartextfelder, die der Sensor auswertet (DHCP-Optionen,
/// mDNS/SSDP-Header, DNS-Query-Namen). Alles darüber wäre Payload.
pub const RECOMMENDED_SNAPLEN: usize = 512;
