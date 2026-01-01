//! Netlink interface for installing routes into the Linux routing table.

use std::net::IpAddr;

use futures::TryStreamExt;
use netlink_packet_route::route::RouteProtocol;
use rtnetlink::Handle;

/// Protocol ID for BGP routes (186 = BGP per IANA)
const RTPROT_BGP: RouteProtocol = RouteProtocol::Other(186);

/// Install a route into the Linux routing table.
///
/// Supports:
/// - IPv4 prefix with IPv4 gateway
/// - IPv6 prefix with IPv6 gateway
/// - IPv4 prefix with IPv6 gateway (RFC 5549, BGP unnumbered) - requires interface
pub async fn install_route(prefix: &str, next_hop: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let (dest, prefix_len) = parse_prefix(prefix)?;
    let (gateway, interface) = parse_next_hop_with_interface(next_hop)?;

    match (dest, gateway) {
        (IpAddr::V4(dest), IpAddr::V4(gw)) => {
            install_route_v4(&handle, dest, prefix_len, gw).await?;
        }
        (IpAddr::V6(dest), IpAddr::V6(gw)) => {
            install_route_v6(&handle, dest, prefix_len, gw).await?;
        }
        (IpAddr::V4(dest), IpAddr::V6(gw)) => {
            // IPv4 over IPv6 next-hop (RFC 5549) - requires interface
            if let Some(if_name) = interface {
                install_route_v4_via_v6(&handle, dest, prefix_len, gw, &if_name).await?;
            } else {
                return Err("IPv4 route with IPv6 next-hop requires interface (e.g., fe80::1%eth0)".into());
            }
        }
        (IpAddr::V6(_), IpAddr::V4(_)) => {
            return Err("IPv6 route with IPv4 next-hop is not supported".into());
        }
    }

    Ok(())
}

/// Remove a route from the Linux routing table.
pub async fn remove_route(prefix: &str, next_hop: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let (dest, prefix_len) = parse_prefix(prefix)?;
    let (gateway, interface) = parse_next_hop_with_interface(next_hop)?;

    match (dest, gateway) {
        (IpAddr::V4(dest), IpAddr::V4(gw)) => {
            remove_route_v4(&handle, dest, prefix_len, gw).await?;
        }
        (IpAddr::V6(dest), IpAddr::V6(gw)) => {
            remove_route_v6(&handle, dest, prefix_len, gw).await?;
        }
        (IpAddr::V4(dest), IpAddr::V6(gw)) => {
            // IPv4 via IPv6 removal - need next-hop and interface for ECMP
            if let Some(ref if_name) = interface {
                remove_route_v4_via_v6(&handle, dest, prefix_len, gw, if_name).await?;
            } else {
                // Fallback: remove by prefix only (removes all matching routes)
                remove_route_v4_any(&handle, dest, prefix_len).await?;
            }
        }
        _ => {
            return Err("Address family mismatch not supported for removal".into());
        }
    }

    Ok(())
}

/// Install IPv4 route with IPv4 gateway.
/// Uses `ip route append` to support ECMP (multiple next-hops for same prefix).
async fn install_route_v4(
    _handle: &Handle,
    dest: std::net::Ipv4Addr,
    prefix_len: u8,
    gateway: std::net::Ipv4Addr,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let prefix = format!("{}/{}", dest, prefix_len);
    let gateway_str = gateway.to_string();

    let output = Command::new("ip")
        .args([
            "route", "append",
            &prefix,
            "via", &gateway_str,
            "proto", "bgp",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ip route append failed: {}", stderr).into());
    }

    Ok(())
}

/// Install IPv6 route with IPv6 gateway.
/// Uses `ip route append` to support ECMP (multiple next-hops for same prefix).
async fn install_route_v6(
    _handle: &Handle,
    dest: std::net::Ipv6Addr,
    prefix_len: u8,
    gateway: std::net::Ipv6Addr,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let prefix = format!("{}/{}", dest, prefix_len);
    let gateway_str = gateway.to_string();

    let output = Command::new("ip")
        .args([
            "-6", "route", "append",
            &prefix,
            "via", &gateway_str,
            "proto", "bgp",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ip route append failed: {}", stderr).into());
    }

    Ok(())
}

async fn remove_route_v4(
    handle: &Handle,
    dest: std::net::Ipv4Addr,
    prefix_len: u8,
    _gateway: std::net::Ipv4Addr,
) -> Result<(), Box<dyn std::error::Error>> {
    // Find and delete matching routes
    let mut routes = handle.route().get(rtnetlink::IpVersion::V4).execute();

    while let Some(route) = routes.try_next().await? {
        // Check if this route matches our prefix
        if let Some((route_dest, route_prefix_len)) = get_route_v4_dest(&route) {
            if route_dest == dest && route_prefix_len == prefix_len {
                // Check if it's a BGP route (protocol 186)
                if route.header.protocol == RTPROT_BGP {
                    handle.route().del(route).execute().await?;
                }
            }
        }
    }

    Ok(())
}

async fn remove_route_v6(
    handle: &Handle,
    dest: std::net::Ipv6Addr,
    prefix_len: u8,
    _gateway: std::net::Ipv6Addr,
) -> Result<(), Box<dyn std::error::Error>> {
    // Find and delete matching routes
    let mut routes = handle.route().get(rtnetlink::IpVersion::V6).execute();

    while let Some(route) = routes.try_next().await? {
        // Check if this route matches our prefix
        if let Some((route_dest, route_prefix_len)) = get_route_v6_dest(&route) {
            if route_dest == dest && route_prefix_len == prefix_len {
                // Check if it's a BGP route (protocol 186)
                if route.header.protocol == RTPROT_BGP {
                    handle.route().del(route).execute().await?;
                }
            }
        }
    }

    Ok(())
}

fn get_route_v4_dest(
    route: &netlink_packet_route::route::RouteMessage,
) -> Option<(std::net::Ipv4Addr, u8)> {
    use netlink_packet_route::route::{RouteAddress, RouteAttribute};

    let prefix_len = route.header.destination_prefix_length;

    for attr in &route.attributes {
        if let RouteAttribute::Destination(RouteAddress::Inet(addr)) = attr {
            return Some((*addr, prefix_len));
        }
    }

    None
}

fn get_route_v6_dest(
    route: &netlink_packet_route::route::RouteMessage,
) -> Option<(std::net::Ipv6Addr, u8)> {
    use netlink_packet_route::route::{RouteAddress, RouteAttribute};

    let prefix_len = route.header.destination_prefix_length;

    for attr in &route.attributes {
        if let RouteAttribute::Destination(RouteAddress::Inet6(addr)) = attr {
            return Some((*addr, prefix_len));
        }
    }

    None
}

fn parse_prefix(prefix: &str) -> Result<(IpAddr, u8), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = prefix.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid prefix format: {}", prefix).into());
    }

    let addr: IpAddr = parts[0].parse()?;
    let prefix_len: u8 = parts[1].parse()?;

    Ok((addr, prefix_len))
}

/// Parse next-hop address and optional interface (e.g., "fe80::1%eth0" -> (fe80::1, Some("eth0")))
fn parse_next_hop_with_interface(next_hop: &str) -> Result<(IpAddr, Option<String>), Box<dyn std::error::Error>> {
    if let Some(pos) = next_hop.find('%') {
        let addr_str = &next_hop[..pos];
        let interface = &next_hop[pos + 1..];
        Ok((addr_str.parse()?, Some(interface.to_string())))
    } else {
        Ok((next_hop.parse()?, None))
    }
}

/// Install IPv4 route with IPv6 gateway (RFC 5549 / BGP unnumbered).
/// This uses the `ip` command because rtnetlink doesn't easily support RTA_VIA.
/// Uses `ip route append` to support ECMP (multiple next-hops for same prefix).
async fn install_route_v4_via_v6(
    _handle: &Handle,
    dest: std::net::Ipv4Addr,
    prefix_len: u8,
    gateway: std::net::Ipv6Addr,
    interface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    // Use `ip route append` with `via inet6` for IPv4 over IPv6 next-hop
    // `append` allows multiple next-hops for ECMP instead of failing with "File exists"
    // Example: ip route append 10.0.0.0/24 via inet6 fe80::1 dev eth0 proto bgp
    let prefix = format!("{}/{}", dest, prefix_len);
    let gateway_str = gateway.to_string();

    let output = Command::new("ip")
        .args([
            "route", "append",
            &prefix,
            "via", "inet6", &gateway_str,
            "dev", interface,
            "proto", "bgp",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ip route append failed: {}", stderr).into());
    }

    Ok(())
}

/// Remove IPv4 route with IPv6 gateway (specific next-hop for ECMP).
async fn remove_route_v4_via_v6(
    _handle: &Handle,
    dest: std::net::Ipv4Addr,
    prefix_len: u8,
    gateway: std::net::Ipv6Addr,
    interface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let prefix = format!("{}/{}", dest, prefix_len);
    let gateway_str = gateway.to_string();

    // Delete specific route with next-hop and interface
    let output = Command::new("ip")
        .args([
            "route", "del",
            &prefix,
            "via", "inet6", &gateway_str,
            "dev", interface,
            "proto", "bgp",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "No such process" error (route doesn't exist)
        if !stderr.contains("No such process") && !stderr.contains("RTNETLINK answers: No such process") {
            return Err(format!("ip route del failed: {}", stderr).into());
        }
    }

    Ok(())
}

/// Remove IPv4 route by prefix only (fallback when next-hop is unknown).
async fn remove_route_v4_any(
    _handle: &Handle,
    dest: std::net::Ipv4Addr,
    prefix_len: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let prefix = format!("{}/{}", dest, prefix_len);

    // Delete all BGP routes for this prefix
    let output = Command::new("ip")
        .args(["route", "del", &prefix, "proto", "bgp"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "No such process" error (route doesn't exist)
        if !stderr.contains("No such process") && !stderr.contains("RTNETLINK answers: No such process") {
            return Err(format!("ip route del failed: {}", stderr).into());
        }
    }

    Ok(())
}
