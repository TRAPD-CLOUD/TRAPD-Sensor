//! Defensive ICMPv6 Neighbor Discovery parsing (RFC 4861).

use std::net::Ipv6Addr;

const MAX_OPTIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeighborDiscovery {
    RouterAdvertisement {
        source_mac: Option<[u8; 6]>,
    },
    NeighborSolicitation {
        target: Ipv6Addr,
        source_mac: Option<[u8; 6]>,
    },
    NeighborAdvertisement {
        target: Ipv6Addr,
        target_mac: Option<[u8; 6]>,
    },
}

/// Parses only the fixed-size NDP messages useful for asset discovery.
/// Unknown ICMPv6 messages, truncated options, zero-length options and excessive
/// option chains are rejected without allocation.
pub fn parse_neighbor_discovery(data: &[u8]) -> Option<NeighborDiscovery> {
    let kind = *data.first()?;
    let code = *data.get(1)?;
    if code != 0 {
        return None;
    }
    match kind {
        134 => Some(NeighborDiscovery::RouterAdvertisement {
            source_mac: link_layer_option(data.get(16..)?, 1)?,
        }),
        135 => Some(NeighborDiscovery::NeighborSolicitation {
            target: address(data.get(8..24)?)?,
            source_mac: link_layer_option(data.get(24..)?, 1)?,
        }),
        136 => Some(NeighborDiscovery::NeighborAdvertisement {
            target: address(data.get(8..24)?)?,
            target_mac: link_layer_option(data.get(24..)?, 2)?,
        }),
        _ => None,
    }
}

fn address(bytes: &[u8]) -> Option<Ipv6Addr> {
    Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?))
}

/// `Some(None)` means a valid option list without the requested option.
fn link_layer_option(mut options: &[u8], wanted: u8) -> Option<Option<[u8; 6]>> {
    for _ in 0..MAX_OPTIONS {
        if options.is_empty() {
            return Some(None);
        }
        let kind = *options.first()?;
        let units = usize::from(*options.get(1)?);
        if units == 0 {
            return None;
        }
        let len = units.checked_mul(8)?;
        let option = options.get(..len)?;
        if kind == wanted {
            return Some(Some(option.get(2..8)?.try_into().ok()?));
        }
        options = options.get(len..)?;
    }
    if options.is_empty() {
        Some(None)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u8, option_kind: u8) -> Vec<u8> {
        let fixed = if kind == 134 { 16 } else { 24 };
        let mut data = vec![0; fixed];
        data[0] = kind;
        if fixed == 24 {
            data[8..24].copy_from_slice(&"2001:db8::42".parse::<Ipv6Addr>().unwrap().octets());
        }
        data.extend_from_slice(&[option_kind, 1, 0, 1, 2, 3, 4, 5]);
        data
    }

    #[test]
    fn parses_ns_na_and_ra() {
        assert!(matches!(
            parse_neighbor_discovery(&message(135, 1)),
            Some(NeighborDiscovery::NeighborSolicitation {
                source_mac: Some([0, 1, 2, 3, 4, 5]),
                ..
            })
        ));
        assert!(matches!(
            parse_neighbor_discovery(&message(136, 2)),
            Some(NeighborDiscovery::NeighborAdvertisement {
                target_mac: Some([0, 1, 2, 3, 4, 5]),
                ..
            })
        ));
        assert!(matches!(
            parse_neighbor_discovery(&message(134, 1)),
            Some(NeighborDiscovery::RouterAdvertisement {
                source_mac: Some(_)
            })
        ));
    }

    #[test]
    fn rejects_malformed_and_bounded_option_chains() {
        assert_eq!(parse_neighbor_discovery(&[135, 0]), None);
        let mut zero = message(135, 1);
        zero[25] = 0;
        assert_eq!(parse_neighbor_discovery(&zero), None);
        let mut many = vec![0; 24];
        many[0] = 135;
        for _ in 0..33 {
            many.extend_from_slice(&[99, 1, 0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(parse_neighbor_discovery(&many), None);
    }
}
