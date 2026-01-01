//! Netlink interface for installing routes into the Linux routing table.
//!
//! # Implementation Notes
//!
//! Route **removal** uses native rtnetlink where possible:
//! - IPv4 routes with IPv4 gateways: rtnetlink
//! - IPv6 routes with IPv6 gateways: rtnetlink
//! - IPv4 routes with IPv6 gateways (RFC 5549): shell (`ip route del`)
//!   - rtnetlink doesn't reliably expose RTA_VIA attributes when enumerating routes
//!
//! Route **installation** uses the `ip` command for ECMP support:
//! - rtnetlink's `RouteAddRequest` doesn't expose `NLM_F_APPEND` flag
//! - Without append semantics, adding a second route to the same prefix fails
//! - The `ip route append` command handles ECMP correctly
//!
//! For IPv4-via-IPv6 routes (RFC 5549), both install and remove use `ip` command:
//! - Requires `via inet6` syntax which maps to the RTA_VIA netlink attribute
//! - rtnetlink's high-level API doesn't provide reliable RTA_VIA support

use std::net::IpAddr;

use futures::TryStreamExt;
use netlink_packet_route::route::{RouteMessage, RouteProtocol};
use netlink_packet_route::AddressFamily;
use rtnetlink::Handle;

/// Protocol ID for BGP routes (186 = BGP per IANA)
const RTPROT_BGP: RouteProtocol = RouteProtocol::Other(186);

/// A reusable netlink connection handle for route operations.
///
/// This struct maintains a persistent connection to the netlink socket,
/// allowing multiple route operations to be performed without the overhead
/// of creating a new connection for each operation.
pub struct NetlinkHandle {
    handle: Handle,
}

impl NetlinkHandle {
    /// Create a new netlink handle.
    ///
    /// This establishes a connection to the netlink socket and spawns
    /// the connection task in the background.
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    /// Install a route into the Linux routing table.
    ///
    /// Supports:
    /// - IPv4 prefix with IPv4 gateway
    /// - IPv6 prefix with IPv6 gateway
    /// - IPv4 prefix with IPv6 gateway (RFC 5549, BGP unnumbered) - requires interface
    pub async fn install_route(&self, prefix: &str, next_hop: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (dest, prefix_len) = parse_prefix(prefix)?;
        let (gateway, interface) = parse_next_hop_with_interface(next_hop)?;

        match (dest, gateway) {
            (IpAddr::V4(dest), IpAddr::V4(gw)) => {
                install_route_v4(&self.handle, dest, prefix_len, gw).await?;
            }
            (IpAddr::V6(dest), IpAddr::V6(gw)) => {
                install_route_v6(&self.handle, dest, prefix_len, gw, interface.as_deref()).await?;
            }
            (IpAddr::V4(dest), IpAddr::V6(gw)) => {
                // IPv4 over IPv6 next-hop (RFC 5549) - requires interface
                if let Some(if_name) = interface {
                    install_route_v4_via_v6(&self.handle, dest, prefix_len, gw, &if_name).await?;
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
    pub async fn remove_route(&self, prefix: &str, next_hop: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (dest, prefix_len) = parse_prefix(prefix)?;
        let (gateway, interface) = parse_next_hop_with_interface(next_hop)?;

        match (dest, gateway) {
            (IpAddr::V4(dest), IpAddr::V4(gw)) => {
                remove_route_v4(&self.handle, dest, prefix_len, gw).await?;
            }
            (IpAddr::V6(dest), IpAddr::V6(gw)) => {
                remove_route_v6(&self.handle, dest, prefix_len, gw, interface.as_deref()).await?;
            }
            (IpAddr::V4(dest), IpAddr::V6(gw)) => {
                // IPv4 via IPv6 removal - need next-hop and interface for ECMP
                if let Some(ref if_name) = interface {
                    remove_route_v4_via_v6(&self.handle, dest, prefix_len, gw, if_name).await?;
                } else {
                    // Fallback: remove by prefix only (removes all matching routes)
                    remove_route_v4_any(&self.handle, dest, prefix_len).await?;
                }
            }
            _ => {
                return Err("Address family mismatch not supported for removal".into());
            }
        }

        Ok(())
    }
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
/// Interface is required for link-local next-hops (fe80::).
async fn install_route_v6(
    _handle: &Handle,
    dest: std::net::Ipv6Addr,
    prefix_len: u8,
    gateway: std::net::Ipv6Addr,
    interface: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let prefix = format!("{}/{}", dest, prefix_len);
    let gateway_str = gateway.to_string();

    // Build arguments - include "dev <interface>" if provided (required for link-local next-hops)
    let mut args = vec![
        "-6", "route", "append",
        &prefix,
        "via", &gateway_str,
    ];

    let interface_owned: String;
    if let Some(if_name) = interface {
        interface_owned = if_name.to_string();
        args.push("dev");
        args.push(&interface_owned);
    }

    args.push("proto");
    args.push("bgp");

    let output = Command::new("ip")
        .args(&args)
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
    let mut filter = RouteMessage::default();
    filter.header.address_family = AddressFamily::Inet;
    let mut routes = handle.route().get(filter).execute();

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
    _interface: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Find and delete matching routes
    // Note: rtnetlink can delete routes without specifying the interface,
    // even for routes with link-local next-hops
    let mut filter = RouteMessage::default();
    filter.header.address_family = AddressFamily::Inet6;
    let mut routes = handle.route().get(filter).execute();

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
///
/// Uses shell command because rtnetlink's route enumeration doesn't reliably
/// expose the RTA_VIA attribute for IPv4-via-IPv6 routes in a way we can match.
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
/// Removes all BGP routes matching the destination prefix.
async fn remove_route_v4_any(
    handle: &Handle,
    dest: std::net::Ipv4Addr,
    prefix_len: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    // Find and delete all matching BGP routes
    let mut filter = RouteMessage::default();
    filter.header.address_family = AddressFamily::Inet;
    let mut routes = handle.route().get(filter).execute();

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
