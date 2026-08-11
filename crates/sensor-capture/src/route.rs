//! Was der Host über seine eigene Anbindung weiß: Standard-Gateway und
//! On-Link-Netz.
//!
//! Wie bei der Interface-Erkennung über eine Textdatei des Kernels
//! (`/proc/net/route`) statt über `getifaddrs`: keine zusätzliche
//! Abhängigkeit, kein `unsafe`, und gegen eine nachgebaute Datei testbar —
//! was für die Auswahllogik der interessante Teil ist.
//!
//! Das Setup nutzt beides nur als **Vorschlag**. Nichts hier verbindet sich
//! irgendwohin; es ist reines Lesen dessen, was der Kernel ohnehin weiß.

use std::net::Ipv4Addr;
use std::path::Path;

const PROC_NET_ROUTE: &str = "/proc/net/route";

/// Die Anbindung dieses Hosts, soweit aus der Routing-Tabelle ablesbar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkVantagePoint {
    /// Interface der Standard-Route.
    pub interface: Option<String>,
    /// Standard-Gateway (IPv4).
    pub gateway: Option<Ipv4Addr>,
    /// Das direkt angeschlossene Netz dieses Interfaces in CIDR-Notation,
    /// z. B. `192.168.178.0/24`.
    pub lan_cidr: Option<String>,
}

/// Liest die Standard-Route und das dazugehörige On-Link-Netz.
pub fn detect_vantage_point() -> NetworkVantagePoint {
    detect_vantage_point_in(Path::new(PROC_NET_ROUTE))
}

pub(crate) fn detect_vantage_point_in(path: &Path) -> NetworkVantagePoint {
    let Ok(contents) = std::fs::read_to_string(path) else {
        tracing::debug!(path = %path.display(), "cannot read the routing table");
        return NetworkVantagePoint::default();
    };
    let routes = parse_routes(&contents);

    // Die Standard-Route mit der kleinsten Metrik gewinnt — dieselbe Regel,
    // nach der der Kernel auswählt.
    let default = routes
        .iter()
        .filter(|r| r.destination == 0 && r.mask == 0)
        .min_by_key(|r| r.metric);

    let interface = default.map(|r| r.interface.clone());
    let gateway = default
        .map(|r| Ipv4Addr::from(r.gateway))
        .filter(|ip| !ip.is_unspecified());

    // Das On-Link-Netz desselben Interfaces: eine Route ohne Gateway, mit
    // einer Maske und nicht die Default-Route selbst.
    let lan_cidr = interface.as_ref().and_then(|name| {
        routes
            .iter()
            .filter(|r| &r.interface == name && r.gateway == 0 && r.mask != 0)
            .max_by_key(|r| r.mask.count_ones())
            .map(|r| format!("{}/{}", Ipv4Addr::from(r.destination), r.mask.count_ones()))
    });

    NetworkVantagePoint {
        interface,
        gateway,
        lan_cidr,
    }
}

#[derive(Debug)]
struct Route {
    interface: String,
    /// Bereits in Host-Byte-Order.
    destination: u32,
    gateway: u32,
    mask: u32,
    metric: u32,
}

/// `/proc/net/route` hat eine Kopfzeile und danach Tab-getrennte Spalten mit
/// Adressen als Little-Endian-Hex.
fn parse_routes(contents: &str) -> Vec<Route> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 {
                return None;
            }
            Some(Route {
                interface: fields[0].to_string(),
                destination: hex_le(fields[1])?,
                gateway: hex_le(fields[2])?,
                mask: hex_le(fields[7])?,
                metric: fields[6].parse().ok()?,
            })
        })
        .collect()
}

/// Adressen stehen dort in der Byte-Reihenfolge des Hosts (auf allen von
/// TRAPD unterstützten Plattformen Little Endian) — `0100A8C0` ist
/// `192.168.0.1`.
fn hex_le(field: &str) -> Option<u32> {
    u32::from_str_radix(field, 16).ok().map(u32::swap_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t01AAA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t00AAA8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";

    fn write(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(contents.as_bytes()).expect("write");
        file
    }

    #[test]
    fn the_default_route_yields_interface_gateway_and_lan() {
        let file = write(SAMPLE);
        let found = detect_vantage_point_in(file.path());

        assert_eq!(found.interface.as_deref(), Some("eth0"));
        assert_eq!(found.gateway, Some(Ipv4Addr::new(192, 168, 170, 1)));
        assert_eq!(found.lan_cidr.as_deref(), Some("192.168.170.0/24"));
    }

    #[test]
    fn unrelated_interfaces_do_not_leak_into_the_lan_guess() {
        let file = write(SAMPLE);
        let found = detect_vantage_point_in(file.path());
        assert_ne!(
            found.lan_cidr.as_deref(),
            Some("172.17.0.0/16"),
            "docker0 is not the LAN just because it has a route"
        );
    }

    #[test]
    fn the_lowest_metric_default_route_wins() {
        let file = write(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
             wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\n\
             eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n",
        );
        let found = detect_vantage_point_in(file.path());
        assert_eq!(found.interface.as_deref(), Some("eth0"));
        assert_eq!(found.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    /// Ein Sensor an einem Mirror-Port hat oft gar keine Default-Route auf dem
    /// Capture-Interface — das darf kein Fehler sein, nur ein leeres Ergebnis.
    #[test]
    fn a_host_without_a_default_route_reports_nothing_instead_of_guessing() {
        let file = write("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n");
        assert_eq!(detect_vantage_point_in(file.path()), Default::default());
    }

    #[test]
    fn a_missing_routing_table_is_not_an_error() {
        assert_eq!(
            detect_vantage_point_in(Path::new("/definitely/not/here")),
            Default::default()
        );
    }

    #[test]
    fn garbage_lines_are_skipped() {
        let file = write(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
             broken\n\
             eth0\tZZZZ\t0100A8C0\t0003\t0\t0\t100\t00000000\n\
             eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n",
        );
        let found = detect_vantage_point_in(file.path());
        assert_eq!(found.gateway, Some(Ipv4Addr::new(192, 168, 0, 1)));
    }
}
