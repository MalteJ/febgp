//! BGP UPDATE message parsing and building.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::bgp::fsm::NotificationError;

// BGP path attribute type codes (RFC 4271)
const ATTR_ORIGIN: u8 = 1;
const ATTR_AS_PATH: u8 = 2;
const ATTR_NEXT_HOP: u8 = 3;
const ATTR_MULTI_EXIT_DISC: u8 = 4;
const ATTR_LOCAL_PREF: u8 = 5;
const ATTR_MP_REACH_NLRI: u8 = 14;
const ATTR_MP_UNREACH_NLRI: u8 = 15;

/// A parsed BGP route from an UPDATE message
#[derive(Debug, Clone)]
pub struct ParsedRoute {
    pub prefix: String,
    pub next_hop: IpAddr,
    pub as_path: Vec<u32>,
    pub origin: Origin,
    /// LOCAL_PREF attribute (None if not present, typically for eBGP)
    pub local_pref: Option<u32>,
    /// Multi-Exit Discriminator (MED) attribute
    pub med: Option<u32>,
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

/// A parsed route withdrawal from an UPDATE message.
#[derive(Debug, Clone)]
pub struct ParsedWithdrawal {
    pub prefix: String,
}

/// Result of parsing a BGP UPDATE message.
#[derive(Debug, Clone, Default)]
pub struct UpdateResult {
    /// Routes being announced.
    pub routes: Vec<ParsedRoute>,
    /// Prefixes being withdrawn.
    pub withdrawals: Vec<ParsedWithdrawal>,
}

/// Parse a BGP UPDATE message body and extract routes and withdrawals.
pub fn parse_update(data: &Bytes) -> UpdateResult {
    let mut result = UpdateResult::default();
    let mut buf = data.clone();

    if buf.remaining() < 4 {
        return result;
    }

    // Withdrawn Routes Length
    let withdrawn_len = buf.get_u16() as usize;
    if buf.remaining() < withdrawn_len {
        return result;
    }

    // Parse IPv4 withdrawn routes (traditional format)
    if withdrawn_len > 0 {
        let withdrawn_data = buf.copy_to_bytes(withdrawn_len);
        for prefix in parse_ipv4_nlri(&withdrawn_data) {
            result.withdrawals.push(ParsedWithdrawal { prefix });
        }
    }

    if buf.remaining() < 2 {
        return result;
    }

    // Total Path Attribute Length
    let path_attr_len = buf.get_u16() as usize;

    if buf.remaining() < path_attr_len {
        return result;
    }

    // Split the buffer: path attributes and then NLRI
    let mut path_attrs = buf.copy_to_bytes(path_attr_len);
    let mut nlri_data = buf; // Remaining is NLRI

    // Parse path attributes
    let mut origin = Origin::Incomplete;
    let mut as_path: Vec<u32> = Vec::new();
    let mut next_hop_v4: Option<Ipv4Addr> = None;
    let mut local_pref: Option<u32> = None;
    let mut med: Option<u32> = None;
    let mut mp_reach_v4: Vec<(String, IpAddr)> = Vec::new(); // (prefix, next_hop)
    let mut mp_reach_v6: Vec<(String, IpAddr)> = Vec::new();

    while path_attrs.remaining() >= 2 {
        let flags = path_attrs.get_u8();
        let attr_type = path_attrs.get_u8();

        let extended = (flags & 0x10) != 0;
        let attr_len = if extended {
            if path_attrs.remaining() < 2 {
                break;
            }
            path_attrs.get_u16() as usize
        } else {
            if path_attrs.remaining() < 1 {
                break;
            }
            path_attrs.get_u8() as usize
        };

        if path_attrs.remaining() < attr_len {
            break;
        }

        let attr_data = path_attrs.copy_to_bytes(attr_len);

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
                as_path = parse_as_path(&attr_data);
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
            4 => {
                // MULTI_EXIT_DISC (MED)
                if attr_data.len() >= 4 {
                    med = Some(u32::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
            }
            5 => {
                // LOCAL_PREF
                if attr_data.len() >= 4 {
                    local_pref = Some(u32::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
            }
            14 => {
                // MP_REACH_NLRI
                if attr_data.len() >= 5 {
                    let mut mp_buf = attr_data;
                    let afi = mp_buf.get_u16();
                    let safi = mp_buf.get_u8();
                    let nh_len = mp_buf.get_u8() as usize;

                    if mp_buf.remaining() > nh_len && safi == 1 {
                        let nh_data = mp_buf.copy_to_bytes(nh_len);
                        mp_buf.advance(1); // Reserved byte
                        let nlri = mp_buf;

                        if afi == 1 {
                            // IPv4 unicast
                            let next_hop = parse_next_hop(&nh_data);
                            for prefix in parse_ipv4_nlri(&nlri) {
                                mp_reach_v4.push((prefix, next_hop));
                            }
                        } else if afi == 2 {
                            // IPv6 unicast
                            let next_hop = parse_next_hop(&nh_data);
                            for prefix in parse_ipv6_nlri(&nlri) {
                                mp_reach_v6.push((prefix, next_hop));
                            }
                        }
                    }
                }
            }
            15 => {
                // MP_UNREACH_NLRI
                for prefix in parse_mp_unreach_nlri(&attr_data) {
                    result.withdrawals.push(ParsedWithdrawal { prefix });
                }
            }
            _ => {}
        }
    }

    // Parse IPv4 NLRI (traditional, after path attributes)
    if nlri_data.has_remaining() {
        let next_hop: IpAddr = next_hop_v4
            .map(IpAddr::from)
            .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        for prefix in parse_ipv4_nlri(&nlri_data.copy_to_bytes(nlri_data.remaining())) {
            result.routes.push(ParsedRoute {
                prefix,
                next_hop,
                as_path: as_path.clone(),
                origin,
                local_pref,
                med,
            });
        }
    }

    // Add MP_REACH routes
    for (prefix, next_hop) in mp_reach_v4 {
        result.routes.push(ParsedRoute {
            prefix,
            next_hop,
            as_path: as_path.clone(),
            origin,
            local_pref,
            med,
        });
    }
    for (prefix, next_hop) in mp_reach_v6 {
        result.routes.push(ParsedRoute {
            prefix,
            next_hop,
            as_path: as_path.clone(),
            origin,
            local_pref,
            med,
        });
    }

    result
}

/// Validate and parse a BGP UPDATE message body.
///
/// Returns `Ok(UpdateResult)` if the UPDATE is valid, or `Err(NotificationError)` if
/// validation fails. Per RFC 4271 Section 6.3, validation includes:
/// - Well-formed attribute list (correct lengths)
/// - Presence of mandatory well-known attributes (ORIGIN, AS_PATH for routes)
/// - Valid ORIGIN attribute value (0, 1, or 2)
/// - Well-formed AS_PATH attribute
/// - Valid NLRI prefix lengths
///
/// Note: Empty UPDATEs (no routes, only withdrawals or keepalive-equivalent) are valid.
pub fn validate_and_parse_update(data: &Bytes) -> Result<UpdateResult, NotificationError> {
    let mut result = UpdateResult::default();
    let mut buf = data.clone();

    // Minimum UPDATE message body is 4 bytes (withdrawn_len + path_attr_len)
    if buf.remaining() < 4 {
        return Err(NotificationError::malformed_attribute_list());
    }

    // Withdrawn Routes Length
    let withdrawn_len = buf.get_u16() as usize;
    if buf.remaining() < withdrawn_len {
        return Err(NotificationError::malformed_attribute_list());
    }

    // Parse IPv4 withdrawn routes (traditional format)
    if withdrawn_len > 0 {
        let withdrawn_data = buf.copy_to_bytes(withdrawn_len);
        for prefix in parse_ipv4_nlri(&withdrawn_data) {
            result.withdrawals.push(ParsedWithdrawal { prefix });
        }
    }

    if buf.remaining() < 2 {
        return Err(NotificationError::malformed_attribute_list());
    }

    // Total Path Attribute Length
    let path_attr_len = buf.get_u16() as usize;

    if buf.remaining() < path_attr_len {
        return Err(NotificationError::malformed_attribute_list());
    }

    // Split the buffer: path attributes and then NLRI
    let mut path_attrs = buf.copy_to_bytes(path_attr_len);
    let mut nlri_data = buf; // Remaining is NLRI

    // Track which mandatory attributes we've seen
    let mut has_origin = false;
    let mut has_as_path = false;
    let mut has_next_hop = false;
    let mut has_mp_reach = false;

    // Parse and validate path attributes
    let mut origin = Origin::Incomplete;
    let mut as_path: Vec<u32> = Vec::new();
    let mut next_hop_v4: Option<Ipv4Addr> = None;
    let mut local_pref: Option<u32> = None;
    let mut med: Option<u32> = None;
    let mut mp_reach_v4: Vec<(String, IpAddr)> = Vec::new();
    let mut mp_reach_v6: Vec<(String, IpAddr)> = Vec::new();

    while path_attrs.remaining() >= 2 {
        let flags = path_attrs.get_u8();
        let attr_type = path_attrs.get_u8();

        let extended = (flags & 0x10) != 0;
        let attr_len = if extended {
            if path_attrs.remaining() < 2 {
                return Err(NotificationError::malformed_attribute_list());
            }
            path_attrs.get_u16() as usize
        } else {
            if path_attrs.remaining() < 1 {
                return Err(NotificationError::malformed_attribute_list());
            }
            path_attrs.get_u8() as usize
        };

        if path_attrs.remaining() < attr_len {
            return Err(NotificationError::attribute_length_error(&[attr_type]));
        }

        let attr_data = path_attrs.copy_to_bytes(attr_len);

        match attr_type {
            ATTR_ORIGIN => {
                has_origin = true;
                if attr_data.is_empty() {
                    return Err(NotificationError::attribute_length_error(&[ATTR_ORIGIN]));
                }
                origin = match attr_data[0] {
                    0 => Origin::Igp,
                    1 => Origin::Egp,
                    2 => Origin::Incomplete,
                    _ => return Err(NotificationError::invalid_origin()),
                };
            }
            ATTR_AS_PATH => {
                has_as_path = true;
                as_path = validate_and_parse_as_path(&attr_data)?;
            }
            ATTR_NEXT_HOP => {
                has_next_hop = true;
                if attr_data.len() != 4 {
                    return Err(NotificationError::attribute_length_error(&[ATTR_NEXT_HOP]));
                }
                let nh = Ipv4Addr::new(attr_data[0], attr_data[1], attr_data[2], attr_data[3]);
                // RFC 4271: next-hop must not be 0.0.0.0
                if nh.is_unspecified() {
                    return Err(NotificationError::invalid_next_hop(&attr_data));
                }
                next_hop_v4 = Some(nh);
            }
            ATTR_MULTI_EXIT_DISC => {
                // MED - 4 bytes
                if attr_data.len() >= 4 {
                    med = Some(u32::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
            }
            ATTR_LOCAL_PREF => {
                // LOCAL_PREF - 4 bytes
                if attr_data.len() >= 4 {
                    local_pref = Some(u32::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
            }
            ATTR_MP_REACH_NLRI => {
                has_mp_reach = true;
                if attr_data.len() < 5 {
                    return Err(NotificationError::attribute_length_error(&[ATTR_MP_REACH_NLRI]));
                }
                let mut mp_buf = attr_data;
                let afi = mp_buf.get_u16();
                let safi = mp_buf.get_u8();
                let nh_len = mp_buf.get_u8() as usize;

                if mp_buf.remaining() < nh_len + 1 {
                    return Err(NotificationError::attribute_length_error(&[ATTR_MP_REACH_NLRI]));
                }

                if safi == 1 {
                    // Unicast
                    let nh_data = mp_buf.copy_to_bytes(nh_len);
                    mp_buf.advance(1); // Reserved byte
                    let nlri = mp_buf;

                    let next_hop = parse_next_hop(&nh_data);

                    if afi == 1 {
                        // IPv4 unicast
                        for prefix in validate_ipv4_nlri(&nlri)? {
                            mp_reach_v4.push((prefix, next_hop));
                        }
                    } else if afi == 2 {
                        // IPv6 unicast
                        for prefix in validate_ipv6_nlri(&nlri)? {
                            mp_reach_v6.push((prefix, next_hop));
                        }
                    }
                }
            }
            ATTR_MP_UNREACH_NLRI => {
                // MP_UNREACH_NLRI - withdrawn routes
                for prefix in parse_mp_unreach_nlri(&attr_data) {
                    result.withdrawals.push(ParsedWithdrawal { prefix });
                }
            }
            _ => {
                // Unknown attributes are ignored (optional non-transitive)
                // or passed through (optional transitive)
            }
        }
    }

    // Check for mandatory attributes only if we have NLRI
    let has_nlri = nlri_data.has_remaining() || !mp_reach_v4.is_empty() || !mp_reach_v6.is_empty();

    if has_nlri {
        // ORIGIN and AS_PATH are mandatory for any UPDATE with NLRI
        if !has_origin {
            return Err(NotificationError::missing_well_known_attribute(ATTR_ORIGIN));
        }
        if !has_as_path {
            return Err(NotificationError::missing_well_known_attribute(ATTR_AS_PATH));
        }
        // NEXT_HOP is mandatory for traditional IPv4 NLRI (not MP_REACH)
        if nlri_data.has_remaining() && !has_next_hop && !has_mp_reach {
            return Err(NotificationError::missing_well_known_attribute(ATTR_NEXT_HOP));
        }
    }

    // Parse IPv4 NLRI (traditional, after path attributes)
    if nlri_data.has_remaining() {
        let next_hop: IpAddr = next_hop_v4
            .map(IpAddr::from)
            .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        for prefix in validate_ipv4_nlri(&nlri_data.copy_to_bytes(nlri_data.remaining()))? {
            result.routes.push(ParsedRoute {
                prefix,
                next_hop,
                as_path: as_path.clone(),
                origin,
                local_pref,
                med,
            });
        }
    }

    // Add MP_REACH routes
    for (prefix, next_hop) in mp_reach_v4 {
        result.routes.push(ParsedRoute {
            prefix,
            next_hop,
            as_path: as_path.clone(),
            origin,
            local_pref,
            med,
        });
    }
    for (prefix, next_hop) in mp_reach_v6 {
        result.routes.push(ParsedRoute {
            prefix,
            next_hop,
            as_path: as_path.clone(),
            origin,
            local_pref,
            med,
        });
    }

    Ok(result)
}

/// Validate and parse AS_PATH attribute.
fn validate_and_parse_as_path(data: &Bytes) -> Result<Vec<u32>, NotificationError> {
    let mut asns = Vec::new();
    let mut buf = data.clone();

    while buf.remaining() >= 2 {
        let seg_type = buf.get_u8();
        let seg_len = buf.get_u8() as usize;

        // Valid segment types: AS_SET (1), AS_SEQUENCE (2)
        // RFC 5065 adds AS_CONFED_SEQUENCE (3) and AS_CONFED_SET (4)
        if seg_type == 0 || seg_type > 4 {
            return Err(NotificationError::malformed_as_path());
        }

        // Check we have enough bytes for all ASNs (4 bytes each)
        let bytes_needed = seg_len * 4;
        if buf.remaining() < bytes_needed {
            return Err(NotificationError::malformed_as_path());
        }

        // AS_SEQUENCE (2) or AS_SET (1)
        if seg_type == 1 || seg_type == 2 {
            for _ in 0..seg_len {
                asns.push(buf.get_u32());
            }
        } else {
            // Skip confederation segments
            buf.advance(bytes_needed);
        }
    }

    // If there are leftover bytes, the AS_PATH is malformed
    if buf.has_remaining() {
        return Err(NotificationError::malformed_as_path());
    }

    Ok(asns)
}

/// Validate and parse IPv4 NLRI, returning an error for invalid prefix lengths.
fn validate_ipv4_nlri(data: &Bytes) -> Result<Vec<String>, NotificationError> {
    let mut prefixes = Vec::new();
    let mut buf = data.clone();

    while buf.has_remaining() {
        let prefix_len = buf.get_u8();

        // IPv4 prefix length must be 0-32
        if prefix_len > 32 {
            return Err(NotificationError::invalid_network_field());
        }

        let bytes_needed = (prefix_len as usize).div_ceil(8);

        if buf.remaining() < bytes_needed {
            return Err(NotificationError::invalid_network_field());
        }

        let mut octets = [0u8; 4];
        for octet in octets.iter_mut().take(bytes_needed) {
            *octet = buf.get_u8();
        }

        let addr = Ipv4Addr::from(octets);
        prefixes.push(format!("{}/{}", addr, prefix_len));
    }

    Ok(prefixes)
}

/// Validate and parse IPv6 NLRI, returning an error for invalid prefix lengths.
fn validate_ipv6_nlri(data: &Bytes) -> Result<Vec<String>, NotificationError> {
    let mut prefixes = Vec::new();
    let mut buf = data.clone();

    while buf.has_remaining() {
        let prefix_len = buf.get_u8();

        // IPv6 prefix length must be 0-128
        if prefix_len > 128 {
            return Err(NotificationError::invalid_network_field());
        }

        let bytes_needed = (prefix_len as usize).div_ceil(8);

        if buf.remaining() < bytes_needed {
            return Err(NotificationError::invalid_network_field());
        }

        let mut octets = [0u8; 16];
        for octet in octets.iter_mut().take(bytes_needed) {
            *octet = buf.get_u8();
        }

        let addr = Ipv6Addr::from(octets);
        prefixes.push(format!("{}/{}", addr, prefix_len));
    }

    Ok(prefixes)
}

/// Parse next-hop from MP_REACH_NLRI based on length
/// - 4 bytes: IPv4 address
/// - 16 bytes: IPv6 address
/// - 32 bytes: IPv6 global + link-local (use link-local)
fn parse_next_hop(data: &Bytes) -> IpAddr {
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
fn parse_as_path(data: &Bytes) -> Vec<u32> {
    let mut asns = Vec::new();
    let mut buf = data.clone();

    while buf.remaining() >= 2 {
        let seg_type = buf.get_u8();
        let seg_len = buf.get_u8() as usize;

        // AS_SEQUENCE (2) or AS_SET (1)
        if seg_type == 1 || seg_type == 2 {
            for _ in 0..seg_len {
                if buf.remaining() >= 4 {
                    // 4-byte ASN
                    asns.push(buf.get_u32());
                } else {
                    break;
                }
            }
        }
    }

    asns
}

/// Parse IPv4 NLRI
fn parse_ipv4_nlri(data: &Bytes) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut buf = data.clone();

    while buf.has_remaining() {
        let prefix_len = buf.get_u8() as usize;
        let bytes_needed = prefix_len.div_ceil(8);

        if buf.remaining() < bytes_needed {
            break;
        }

        let mut octets = [0u8; 4];
        for octet in octets.iter_mut().take(bytes_needed) {
            *octet = buf.get_u8();
        }

        let addr = Ipv4Addr::from(octets);
        prefixes.push(format!("{}/{}", addr, prefix_len));
    }

    prefixes
}

/// Parse IPv6 NLRI
fn parse_ipv6_nlri(data: &Bytes) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut buf = data.clone();

    while buf.has_remaining() {
        let prefix_len = buf.get_u8() as usize;
        let bytes_needed = prefix_len.div_ceil(8);

        if buf.remaining() < bytes_needed {
            break;
        }

        let mut octets = [0u8; 16];
        for octet in octets.iter_mut().take(bytes_needed) {
            *octet = buf.get_u8();
        }

        let addr = Ipv6Addr::from(octets);
        prefixes.push(format!("{}/{}", addr, prefix_len));
    }

    prefixes
}

/// Parse MP_UNREACH_NLRI attribute for IPv4/IPv6 withdrawals.
///
/// RFC 4760 Section 4:
/// ```text
/// +---------------------------------------------------------+
/// | Address Family Identifier (2 octets)                    |
/// +---------------------------------------------------------+
/// | Subsequent Address Family Identifier (1 octet)          |
/// +---------------------------------------------------------+
/// | Withdrawn Routes (variable)                             |
/// +---------------------------------------------------------+
/// ```
fn parse_mp_unreach_nlri(attr_data: &Bytes) -> Vec<String> {
    if attr_data.len() < 3 {
        return Vec::new();
    }

    let mut buf = attr_data.clone();
    let afi = buf.get_u16();
    let safi = buf.get_u8();

    // Only process unicast (SAFI 1)
    if safi != 1 {
        return Vec::new();
    }

    let nlri = buf; // Remaining bytes are withdrawn NLRI

    match afi {
        1 => parse_ipv4_nlri(&nlri), // IPv4 unicast
        2 => parse_ipv6_nlri(&nlri), // IPv6 unicast
        _ => Vec::new(),
    }
}

/// Build a BGP UPDATE message body for an IPv4 prefix using MP_REACH_NLRI (RFC 5549).
/// Returns the UPDATE body (not including BGP header).
///
/// The `next_hop` should be the link-local IPv6 address of the interface used for this BGP session.
/// This enables "BGP unnumbered" / RFC 5549 where IPv4 routes are advertised with IPv6 next-hops.
pub fn build_ipv4_update(prefix_str: &str, local_asn: u32, next_hop: Ipv6Addr) -> Option<Bytes> {
    let parts: Vec<&str> = prefix_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    let mut update = BytesMut::with_capacity(64);

    // Withdrawn Routes Length (0)
    update.put_u16(0);

    // Build path attributes
    let mut path_attrs = BytesMut::with_capacity(48);
    // ORIGIN (type 1) - IGP
    path_attrs.put_u8(0x40); // Transitive
    path_attrs.put_u8(1);    // ORIGIN
    path_attrs.put_u8(1);    // Length
    path_attrs.put_u8(0);    // IGP
    // AS_PATH (type 2) - AS_SEQUENCE with our ASN
    path_attrs.put_u8(0x40); // Transitive
    path_attrs.put_u8(2);    // AS_PATH
    path_attrs.put_u8(6);    // Length (1 + 1 + 4)
    path_attrs.put_u8(2);    // AS_SEQUENCE
    path_attrs.put_u8(1);    // 1 ASN
    path_attrs.put_u32(local_asn);

    // MP_REACH_NLRI (type 14) for IPv4 with IPv6 next-hop (RFC 5549)
    let mut mp_reach = BytesMut::with_capacity(32);
    mp_reach.put_u16(1); // AFI = 1 (IPv4)
    mp_reach.put_u8(1);  // SAFI = 1 (unicast)

    // Next hop - 16 bytes for IPv6 (RFC 5549: IPv4 NLRI with IPv6 next-hop)
    mp_reach.put_u8(16); // Next hop length
    mp_reach.put_slice(&next_hop.octets());

    mp_reach.put_u8(0); // Reserved

    // NLRI
    mp_reach.put_u8(prefix_len);
    let bytes_needed = prefix_len.div_ceil(8) as usize;
    mp_reach.put_slice(&addr.octets()[..bytes_needed]);

    // Add MP_REACH_NLRI attribute (optional, transitive, extended length)
    path_attrs.put_u8(0x90); // Optional + Transitive + Extended length
    path_attrs.put_u8(14);   // MP_REACH_NLRI
    path_attrs.put_u16(mp_reach.len() as u16);
    path_attrs.put(mp_reach);

    // Total Path Attribute Length
    update.put_u16(path_attrs.len() as u16);
    update.put(path_attrs);

    Some(update.freeze())
}

/// Build a BGP UPDATE message body for an IPv6 prefix using MP_REACH_NLRI.
/// Returns the UPDATE body (not including BGP header).
///
/// The `next_hop` should be the link-local address of the interface used for this BGP session.
pub fn build_ipv6_update(prefix_str: &str, local_asn: u32, next_hop: Ipv6Addr) -> Option<Bytes> {
    let parts: Vec<&str> = prefix_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: Ipv6Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    let mut update = BytesMut::with_capacity(64);

    // Withdrawn Routes Length (0)
    update.put_u16(0);

    // Build path attributes
    let mut path_attrs = BytesMut::with_capacity(48);
    // ORIGIN (type 1) - IGP
    path_attrs.put_u8(0x40); // Transitive
    path_attrs.put_u8(1);    // ORIGIN
    path_attrs.put_u8(1);    // Length
    path_attrs.put_u8(0);    // IGP
    // AS_PATH (type 2) - AS_SEQUENCE with our ASN
    path_attrs.put_u8(0x40); // Transitive
    path_attrs.put_u8(2);    // AS_PATH
    path_attrs.put_u8(6);    // Length
    path_attrs.put_u8(2);    // AS_SEQUENCE
    path_attrs.put_u8(1);    // 1 ASN
    path_attrs.put_u32(local_asn);

    // MP_REACH_NLRI (type 14) for IPv6
    let mut mp_reach = BytesMut::with_capacity(32);
    mp_reach.put_u16(2); // AFI = 2 (IPv6)
    mp_reach.put_u8(1);  // SAFI = 1 (unicast)

    // Next hop - use the interface's link-local address
    mp_reach.put_u8(16); // Next hop length (16 bytes for single IPv6)
    mp_reach.put_slice(&next_hop.octets());

    mp_reach.put_u8(0); // Reserved

    // NLRI
    mp_reach.put_u8(prefix_len);
    let bytes_needed = prefix_len.div_ceil(8) as usize;
    mp_reach.put_slice(&addr.octets()[..bytes_needed]);

    // Add MP_REACH_NLRI attribute (optional, transitive, extended length)
    path_attrs.put_u8(0x90); // Optional + Transitive + Extended length
    path_attrs.put_u8(14);   // MP_REACH_NLRI
    path_attrs.put_u16(mp_reach.len() as u16);
    path_attrs.put(mp_reach);

    // Total Path Attribute Length
    update.put_u16(path_attrs.len() as u16);
    update.put(path_attrs);

    Some(update.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_nlri() {
        // 24-bit prefix: 10.100.0.0/24
        let data = Bytes::from_static(&[24, 10, 100, 0]);
        let prefixes = parse_ipv4_nlri(&data);
        assert_eq!(prefixes, vec!["10.100.0.0/24"]);
    }

    #[test]
    fn test_parse_ipv6_nlri() {
        // 48-bit prefix: 2001:db8:100::/48
        let data = Bytes::from_static(&[48, 0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00]);
        let prefixes = parse_ipv6_nlri(&data);
        assert_eq!(prefixes, vec!["2001:db8:100::/48"]);
    }

    #[test]
    fn test_parse_as_path() {
        // AS_SEQUENCE with 1 ASN (65002)
        let data = Bytes::from_static(&[2, 1, 0, 0, 0xFD, 0xEA]); // type=2, len=1, ASN=65002
        let asns = parse_as_path(&data);
        assert_eq!(asns, vec![65002]);
    }

    // Validation tests

    #[test]
    fn test_validate_as_path_valid() {
        // AS_SEQUENCE with 2 ASNs
        let data = Bytes::from_static(&[2, 2, 0, 0, 0xFD, 0xEA, 0, 0, 0xFD, 0xEB]);
        let result = validate_and_parse_as_path(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![65002, 65003]);
    }

    #[test]
    fn test_validate_as_path_invalid_segment_type() {
        // Invalid segment type (0)
        let data = Bytes::from_static(&[0, 1, 0, 0, 0xFD, 0xEA]);
        let result = validate_and_parse_as_path(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_as_path_truncated() {
        // Segment claims 2 ASNs but only has bytes for 1
        let data = Bytes::from_static(&[2, 2, 0, 0, 0xFD, 0xEA]);
        let result = validate_and_parse_as_path(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ipv4_nlri_valid() {
        let data = Bytes::from_static(&[24, 10, 100, 0]);
        let result = validate_ipv4_nlri(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["10.100.0.0/24"]);
    }

    #[test]
    fn test_validate_ipv4_nlri_invalid_prefix_length() {
        // Prefix length 33 is invalid for IPv4
        let data = Bytes::from_static(&[33, 10, 100, 0, 0, 0]);
        let result = validate_ipv4_nlri(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ipv6_nlri_valid() {
        let data = Bytes::from_static(&[48, 0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00]);
        let result = validate_ipv6_nlri(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["2001:db8:100::/48"]);
    }

    #[test]
    fn test_validate_ipv6_nlri_invalid_prefix_length() {
        // Prefix length 129 is invalid for IPv6
        let data = Bytes::from_static(&[129, 0x20, 0x01]);
        let result = validate_ipv6_nlri(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_update_empty_valid() {
        // Empty UPDATE (no withdrawn, no attrs, no nlri) - valid as keepalive-like
        let data = Bytes::from_static(&[0, 0, 0, 0]);
        let result = validate_and_parse_update(&data);
        assert!(result.is_ok());
        let update = result.unwrap();
        assert!(update.routes.is_empty());
        assert!(update.withdrawals.is_empty());
    }

    #[test]
    fn test_validate_update_too_short() {
        // Too short to be valid
        let data = Bytes::from_static(&[0, 0]);
        let result = validate_and_parse_update(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_update_invalid_origin() {
        // Build UPDATE with invalid ORIGIN value (5)
        let mut update = BytesMut::new();
        update.put_u16(0); // withdrawn len
        // Path attrs: ORIGIN with invalid value
        let mut attrs = BytesMut::new();
        attrs.put_u8(0x40); // flags
        attrs.put_u8(1);    // ORIGIN
        attrs.put_u8(1);    // len
        attrs.put_u8(5);    // invalid value
        update.put_u16(attrs.len() as u16);
        update.put(attrs);
        // Add NLRI to trigger mandatory attr check
        update.put_u8(24);
        update.put_slice(&[10, 0, 0]);

        let result = validate_and_parse_update(&update.freeze());
        assert!(result.is_err());
    }
}
