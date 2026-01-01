//! BGP UPDATE message parsing and building.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A parsed BGP route from an UPDATE message
#[derive(Debug, Clone)]
pub struct ParsedRoute {
    pub prefix: String,
    pub next_hop: IpAddr,
    pub as_path: Vec<u32>,
    pub origin: Origin,
}

/// BGP ORIGIN attribute values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Igp,
    Egp,
    Incomplete,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::Igp => write!(f, "IGP"),
            Origin::Egp => write!(f, "EGP"),
            Origin::Incomplete => write!(f, "?"),
        }
    }
}

/// Parse a BGP UPDATE message body and extract routes
pub fn parse_update(data: &[u8]) -> Vec<ParsedRoute> {
    let mut routes = Vec::new();

    if data.len() < 4 {
        return routes;
    }

    // Withdrawn Routes Length
    let withdrawn_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2 + withdrawn_len;

    if pos + 2 > data.len() {
        return routes;
    }

    // Total Path Attribute Length
    let path_attr_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let path_attr_end = pos + path_attr_len;

    // Parse path attributes
    let mut origin = Origin::Incomplete;
    let mut as_path: Vec<u32> = Vec::new();
    let mut next_hop_v4: Option<Ipv4Addr> = None;
    let mut mp_reach_v4: Vec<(String, IpAddr)> = Vec::new(); // (prefix, next_hop)
    let mut mp_reach_v6: Vec<(String, IpAddr)> = Vec::new();

    while pos < path_attr_end && pos < data.len() {
        if pos + 2 > data.len() {
            break;
        }

        let flags = data[pos];
        let attr_type = data[pos + 1];
        pos += 2;

        let extended = (flags & 0x10) != 0;
        let attr_len = if extended {
            if pos + 2 > data.len() {
                break;
            }
            let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            len
        } else {
            if pos >= data.len() {
                break;
            }
            let len = data[pos] as usize;
            pos += 1;
            len
        };

        if pos + attr_len > data.len() {
            break;
        }

        let attr_data = &data[pos..pos + attr_len];

        match attr_type {
            1 => {
                // ORIGIN
                if !attr_data.is_empty() {
                    origin = match attr_data[0] {
                        0 => Origin::Igp,
                        1 => Origin::Egp,
                        _ => Origin::Incomplete,
                    };
                }
            }
            2 => {
                // AS_PATH
                as_path = parse_as_path(attr_data);
            }
            3 => {
                // NEXT_HOP (IPv4)
                if attr_data.len() >= 4 {
                    next_hop_v4 = Some(Ipv4Addr::new(
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ));
                }
            }
            14 => {
                // MP_REACH_NLRI
                if attr_len >= 5 {
                    let afi = u16::from_be_bytes([attr_data[0], attr_data[1]]);
                    let safi = attr_data[2];
                    let nh_len = attr_data[3] as usize;

                    if 4 + nh_len < attr_len && safi == 1 {
                        let nh_data = &attr_data[4..4 + nh_len];
                        let nlri_start = 4 + nh_len + 1; // +1 for reserved byte
                        let nlri_data = &attr_data[nlri_start..];

                        if afi == 1 {
                            // IPv4 unicast
                            // Next-hop can be IPv4 (4 bytes) or IPv6 (16/32 bytes) for link-local sessions
                            let next_hop = parse_next_hop(nh_data);
                            for prefix in parse_ipv4_nlri(nlri_data) {
                                mp_reach_v4.push((prefix, next_hop));
                            }
                        } else if afi == 2 {
                            // IPv6 unicast
                            let next_hop = parse_next_hop(nh_data);
                            for prefix in parse_ipv6_nlri(nlri_data) {
                                mp_reach_v6.push((prefix, next_hop));
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        pos += attr_len;
    }

    // Parse IPv4 NLRI (traditional, after path attributes)
    if path_attr_end < data.len() {
        let nlri_data = &data[path_attr_end..];
        let next_hop: IpAddr = next_hop_v4
            .map(IpAddr::from)
            .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        for prefix in parse_ipv4_nlri(nlri_data) {
            routes.push(ParsedRoute {
                prefix,
                next_hop,
                as_path: as_path.clone(),
                origin,
            });
        }
    }

    // Add MP_REACH routes
    for (prefix, next_hop) in mp_reach_v4 {
        routes.push(ParsedRoute {
            prefix,
            next_hop,
            as_path: as_path.clone(),
            origin,
        });
    }
    for (prefix, next_hop) in mp_reach_v6 {
        routes.push(ParsedRoute {
            prefix,
            next_hop,
            as_path: as_path.clone(),
            origin,
        });
    }

    routes
}

/// Parse next-hop from MP_REACH_NLRI based on length
/// - 4 bytes: IPv4 address
/// - 16 bytes: IPv6 address
/// - 32 bytes: IPv6 global + link-local (use link-local)
fn parse_next_hop(data: &[u8]) -> IpAddr {
    match data.len() {
        4 => {
            // IPv4 next-hop
            IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
        }
        16 => {
            // Single IPv6 next-hop
            let mut octets = [0u8; 16];
            octets.copy_from_slice(data);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        32 => {
            // IPv6 global + link-local, prefer link-local (second address)
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[16..32]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => {
            // Unknown format, try to make sense of it
            if data.len() >= 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[..16]);
                IpAddr::V6(Ipv6Addr::from(octets))
            } else if data.len() >= 4 {
                IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        }
    }
}

/// Parse AS_PATH attribute (supports 4-byte ASNs)
fn parse_as_path(data: &[u8]) -> Vec<u32> {
    let mut asns = Vec::new();
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let seg_type = data[pos];
        let seg_len = data[pos + 1] as usize;
        pos += 2;

        // AS_SEQUENCE (2) or AS_SET (1)
        if seg_type == 1 || seg_type == 2 {
            for _ in 0..seg_len {
                if pos + 4 <= data.len() {
                    // 4-byte ASN
                    let asn = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                    asns.push(asn);
                    pos += 4;
                } else {
                    break;
                }
            }
        }
    }

    asns
}

/// Parse IPv4 NLRI
fn parse_ipv4_nlri(data: &[u8]) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let prefix_len = data[pos] as usize;
        pos += 1;

        let bytes_needed = prefix_len.div_ceil(8);
        if pos + bytes_needed > data.len() {
            break;
        }

        let mut octets = [0u8; 4];
        for (i, byte) in data[pos..pos + bytes_needed].iter().enumerate() {
            octets[i] = *byte;
        }
        pos += bytes_needed;

        let addr = Ipv4Addr::from(octets);
        prefixes.push(format!("{}/{}", addr, prefix_len));
    }

    prefixes
}

/// Parse IPv6 NLRI
fn parse_ipv6_nlri(data: &[u8]) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let prefix_len = data[pos] as usize;
        pos += 1;

        let bytes_needed = prefix_len.div_ceil(8);
        if pos + bytes_needed > data.len() {
            break;
        }

        let mut octets = [0u8; 16];
        for (i, byte) in data[pos..pos + bytes_needed].iter().enumerate() {
            octets[i] = *byte;
        }
        pos += bytes_needed;

        let addr = Ipv6Addr::from(octets);
        prefixes.push(format!("{}/{}", addr, prefix_len));
    }

    prefixes
}

/// Build a BGP UPDATE message body for an IPv4 prefix using MP_REACH_NLRI (RFC 5549).
/// Returns the UPDATE body (not including BGP header).
///
/// The `next_hop` should be the link-local IPv6 address of the interface used for this BGP session.
/// This enables "BGP unnumbered" / RFC 5549 where IPv4 routes are advertised with IPv6 next-hops.
pub fn build_ipv4_update(prefix_str: &str, local_asn: u32, next_hop: Ipv6Addr) -> Option<Vec<u8>> {
    let parts: Vec<&str> = prefix_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    let mut update = Vec::new();

    // Withdrawn Routes Length (0)
    update.extend_from_slice(&0u16.to_be_bytes());

    // Build path attributes
    #[rustfmt::skip]
    let mut path_attrs = vec![
        // ORIGIN (type 1) - IGP
        0x40, // Transitive
        1,    // ORIGIN
        1,    // Length
        0,    // IGP
        // AS_PATH (type 2) - AS_SEQUENCE with our ASN
        0x40, // Transitive
        2,    // AS_PATH
        6,    // Length (1 + 1 + 4)
        2,    // AS_SEQUENCE
        1,    // 1 ASN
    ];
    path_attrs.extend_from_slice(&local_asn.to_be_bytes());

    // MP_REACH_NLRI (type 14) for IPv4 with IPv6 next-hop (RFC 5549)
    let mut mp_reach = Vec::new();
    mp_reach.extend_from_slice(&1u16.to_be_bytes()); // AFI = 1 (IPv4)
    mp_reach.push(1); // SAFI = 1 (unicast)

    // Next hop - 16 bytes for IPv6 (RFC 5549: IPv4 NLRI with IPv6 next-hop)
    mp_reach.push(16); // Next hop length
    mp_reach.extend_from_slice(&next_hop.octets());

    mp_reach.push(0); // Reserved

    // NLRI
    mp_reach.push(prefix_len);
    let bytes_needed = prefix_len.div_ceil(8) as usize;
    mp_reach.extend_from_slice(&addr.octets()[..bytes_needed]);

    // Add MP_REACH_NLRI attribute (optional, transitive, extended length)
    path_attrs.push(0x90); // Optional + Transitive + Extended length
    path_attrs.push(14); // MP_REACH_NLRI
    path_attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    path_attrs.extend(mp_reach);

    // Total Path Attribute Length
    update.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
    update.extend(path_attrs);

    Some(update)
}

/// Build a BGP UPDATE message body for an IPv6 prefix using MP_REACH_NLRI.
/// Returns the UPDATE body (not including BGP header).
///
/// The `next_hop` should be the link-local address of the interface used for this BGP session.
pub fn build_ipv6_update(prefix_str: &str, local_asn: u32, next_hop: Ipv6Addr) -> Option<Vec<u8>> {
    let parts: Vec<&str> = prefix_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: Ipv6Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    let mut update = Vec::new();

    // Withdrawn Routes Length (0)
    update.extend_from_slice(&0u16.to_be_bytes());

    // Build path attributes
    #[rustfmt::skip]
    let mut path_attrs = vec![
        // ORIGIN (type 1) - IGP
        0x40, // Transitive
        1,    // ORIGIN
        1,    // Length
        0,    // IGP
        // AS_PATH (type 2) - AS_SEQUENCE with our ASN
        0x40, // Transitive
        2,    // AS_PATH
        6,    // Length
        2,    // AS_SEQUENCE
        1,    // 1 ASN
    ];
    path_attrs.extend_from_slice(&local_asn.to_be_bytes());

    // MP_REACH_NLRI (type 14) for IPv6
    let mut mp_reach = Vec::new();
    mp_reach.extend_from_slice(&2u16.to_be_bytes()); // AFI = 2 (IPv6)
    mp_reach.push(1); // SAFI = 1 (unicast)

    // Next hop - use the interface's link-local address
    mp_reach.push(16); // Next hop length (16 bytes for single IPv6)
    mp_reach.extend_from_slice(&next_hop.octets());

    mp_reach.push(0); // Reserved

    // NLRI
    mp_reach.push(prefix_len);
    let bytes_needed = prefix_len.div_ceil(8) as usize;
    mp_reach.extend_from_slice(&addr.octets()[..bytes_needed]);

    // Add MP_REACH_NLRI attribute (optional, transitive, extended length)
    path_attrs.push(0x90); // Optional + Transitive + Extended length
    path_attrs.push(14); // MP_REACH_NLRI
    path_attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    path_attrs.extend(mp_reach);

    // Total Path Attribute Length
    update.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
    update.extend(path_attrs);

    Some(update)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_nlri() {
        // 24-bit prefix: 10.100.0.0/24
        let data = [24, 10, 100, 0];
        let prefixes = parse_ipv4_nlri(&data);
        assert_eq!(prefixes, vec!["10.100.0.0/24"]);
    }

    #[test]
    fn test_parse_ipv6_nlri() {
        // 48-bit prefix: 2001:db8:100::/48
        let data = [48, 0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00];
        let prefixes = parse_ipv6_nlri(&data);
        assert_eq!(prefixes, vec!["2001:db8:100::/48"]);
    }

    #[test]
    fn test_parse_as_path() {
        // AS_SEQUENCE with 1 ASN (65002)
        let data = [2, 1, 0, 0, 0xFD, 0xEA]; // type=2, len=1, ASN=65002
        let asns = parse_as_path(&data);
        assert_eq!(asns, vec![65002]);
    }
}
