//! Passive Netzwerkbeobachtung.
//!
//! Alles hier ist Zuhören — kein Modul dieses Crates sendet ein Paket. Die
//! Protokoll-Parser sind reine Funktionen über Byte-Slices, der
//! [`PassiveObserver`] setzt sie zu Beobachtungen zusammen und wendet dabei die
//! Betriebs- und Privacy-Policy an.
//!
//! ## Was der Sensor liest — und was nicht
//!
//! Gelesen werden Header sowie einige klar benannte Klartextfelder: DHCP-
//! Optionen, mDNS/SSDP-Kopfzeilen, DNS-Query-Namen. Das ist der vollständige
//! Umfang. Es gibt keinen generischen Payload-Pfad, keine TLS-Terminierung und
//! keinen Full-Packet-Mitschnitt — nicht als abgeschaltete Option, sondern
//! schlicht nicht vorhanden.
//!
//! Nutzlast landet stattdessen in Zählern: [`flow::FlowAggregator`] verdichtet
//! Verkehr zu Byte- und Paketsummen je 5-Tupel und Zeitfenster.

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod flow;
pub mod frame;
pub mod icmpv6;
pub mod observer;
pub mod ssdp;

pub use arp::{parse_arp, ArpPacket};
pub use dhcp::{parse_dhcp, DhcpMessage, DhcpMessageType};
pub use dns::{parse_dns, DnsMessage, DnsRecord, DnsRecordData};
pub use flow::{classify_direction, well_known_service, FlowAggregator, FlowKey};
pub use frame::{parse_ethernet, parse_ipv4, parse_ipv6, parse_tcp, parse_udp, EthernetFrame};
pub use observer::PassiveObserver;
pub use ssdp::{parse_ssdp, SsdpKind, SsdpMessage};
