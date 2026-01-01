//! Netlink interface for installing routes into the Linux routing table.
//!
//! # Implementation Notes
//!
//! Uses multipath routes with `replace` semantics:
//! - A single route entry per prefix with multiple nexthops (ECMP)
//! - Idempotent: calling with the same nexthops is a no-op
//! - Atomic: the route is replaced in a single operation

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use netlink_packet_route::route::{RouteMessage, RouteProtocol};
use netlink_packet_route::AddressFamily;
use rtnetlink::{Handle, RouteMessageBuilder, RouteNextHopBuilder};
use libc;

/// Protocol ID for BGP routes (186 = BGP per IANA)
const RTPROT_BGP: RouteProtocol = RouteProtocol::Other(186);

/// Parsed next-hop with interface information.
#[derive(Debug, Clone)]
pub struct NextHop {
    pub gateway: IpAddr,
    pub interface: Option<String>,
}

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

    /// Set the nexthops for a prefix (create or replace).
    ///
    /// This is the main route management function. It:
    /// - Creates the route if it doesn't exist
    /// - Replaces it if it does (with all provided nexthops)
    /// - Uses multipath for ECMP when multiple nexthops are provided
    ///
    /// If `nexthops` is empty, this is a no-op. Use `remove_prefix` to delete.
    pub async fn set_route(
        &self,
        prefix: &str,
        nexthops: &[String],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if nexthops.is_empty() {
            return Ok(());
        }

        let (dest, prefix_len) = parse_prefix(prefix)?;

        // Parse all nexthops
        let parsed_nexthops: Vec<NextHop> = nexthops
            .iter()
            .map(|nh| parse_next_hop_with_interface(nh))
            .collect::<Result<Vec<_>, _>>()?;

        match dest {
            IpAddr::V4(dest) => {
                self.set_route_v4(dest, prefix_len, &parsed_nexthops).await?;
            }
            IpAddr::V6(dest) => {
                self.set_route_v6(dest, prefix_len, &parsed_nexthops).await?;
            }
        }

        Ok(())
    }

    /// Remove a prefix from the routing table.
    ///
    /// Removes all routes for the given prefix with RTPROT_BGP protocol.
    pub async fn remove_prefix(&self, prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (dest, prefix_len) = parse_prefix(prefix)?;

        match dest {
            IpAddr::V4(dest) => {
                self.remove_prefix_v4(dest, prefix_len).await?;
            }
            IpAddr::V6(dest) => {
                self.remove_prefix_v6(dest, prefix_len).await?;
            }
        }

        Ok(())
    }

    /// Set IPv4 route with multipath support.
    async fn set_route_v4(
        &self,
        dest: Ipv4Addr,
        prefix_len: u8,
        nexthops: &[NextHop],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if nexthops.is_empty() {
            return Ok(());
        }

        // Build nexthop entries
        let mut nh_entries = Vec::new();
        for nh in nexthops {
            let if_name = nh.interface.as_deref().ok_or_else(|| {
                format!("Interface required for nexthop {:?}", nh.gateway)
            })?;
            let if_index = nix::net::if_::if_nametoindex(if_name)
                .map_err(|e| format!("Failed to get interface index for {}: {}", if_name, e))?;

            let entry = match nh.gateway {
                IpAddr::V4(gw) => {
                    RouteNextHopBuilder::new_ipv4()
                        .interface(if_index)
                        .via(IpAddr::V4(gw))
                        .map_err(|e| format!("Failed to build nexthop: {:?}", e))?
                        .build()
                }
                IpAddr::V6(gw) => {
                    // IPv4 route with IPv6 gateway (RFC 5549)
                    RouteNextHopBuilder::new_ipv4()
                        .interface(if_index)
                        .via(IpAddr::V6(gw))
                        .map_err(|e| format!("Failed to build nexthop: {:?}", e))?
                        .build()
                }
            };
            nh_entries.push(entry);
        }

        let message = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(dest, prefix_len)
            .protocol(RTPROT_BGP)
            .multipath(nh_entries)
            .build();

        self.handle
            .route()
            .add(message)
            .replace()
            .execute()
            .await
            .map_err(|e| format!("Failed to set IPv4 route: {}", e))?;

        Ok(())
    }

    /// Set IPv6 route with multipath support.
    async fn set_route_v6(
        &self,
        dest: Ipv6Addr,
        prefix_len: u8,
        nexthops: &[NextHop],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if nexthops.is_empty() {
            return Ok(());
        }

        // Build nexthop entries
        let mut nh_entries = Vec::new();
        for nh in nexthops {
            let gw = match nh.gateway {
                IpAddr::V6(gw) => gw,
                IpAddr::V4(_) => {
                    return Err("IPv6 route cannot have IPv4 gateway".into());
                }
            };

            let mut builder = RouteNextHopBuilder::new_ipv6()
                .via(IpAddr::V6(gw))
                .map_err(|e| format!("Failed to build nexthop: {:?}", e))?;

            // Add interface if provided (required for link-local)
            if let Some(ref if_name) = nh.interface {
                let if_index = nix::net::if_::if_nametoindex(if_name.as_str())
                    .map_err(|e| format!("Failed to get interface index for {}: {}", if_name, e))?;
                builder = builder.interface(if_index);
            }

            nh_entries.push(builder.build());
        }

        let message = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(dest, prefix_len)
            .protocol(RTPROT_BGP)
            .multipath(nh_entries)
            .build();

        self.handle
            .route()
            .add(message)
            .replace()
            .execute()
            .await
            .map_err(|e| format!("Failed to set IPv6 route: {}", e))?;

        Ok(())
    }

    /// Remove all BGP routes for an IPv4 prefix.
    async fn remove_prefix_v4(
        &self,
        dest: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Build a delete message for the specific prefix
        let message = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(dest, prefix_len)
            .protocol(RTPROT_BGP)
            .build();

        // Try to delete - ignore error if route doesn't exist
        match self.handle.route().del(message).execute().await {
            Ok(_) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ESRCH => {
                // Route not found - that's fine
                Ok(())
            }
            Err(e) => Err(format!("Failed to remove IPv4 prefix: {}", e).into()),
        }
    }

    /// Remove all BGP routes for an IPv6 prefix.
    async fn remove_prefix_v6(
        &self,
        dest: Ipv6Addr,
        prefix_len: u8,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Build a delete message for the specific prefix
        let message = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(dest, prefix_len)
            .protocol(RTPROT_BGP)
            .build();

        // Try to delete - ignore error if route doesn't exist
        match self.handle.route().del(message).execute().await {
            Ok(_) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ESRCH => {
                // Route not found - that's fine
                Ok(())
            }
            Err(e) => Err(format!("Failed to remove IPv6 prefix: {}", e).into()),
        }
    }

    /// Remove all BGP routes from the kernel routing table.
    ///
    /// This queries the kernel directly for all routes with RTPROT_BGP protocol
    /// and removes them. Used for cleanup on daemon shutdown.
    pub async fn remove_all_bgp_routes(&self) -> usize {
        let mut removed = 0;

        // Remove IPv4 BGP routes
        removed += remove_all_bgp_routes_v4(&self.handle).await;

        // Remove IPv6 BGP routes
        removed += remove_all_bgp_routes_v6(&self.handle).await;

        removed
    }

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
fn parse_next_hop_with_interface(next_hop: &str) -> Result<NextHop, Box<dyn std::error::Error>> {
    if let Some(pos) = next_hop.find('%') {
        let addr_str = &next_hop[..pos];
        let interface = &next_hop[pos + 1..];
        Ok(NextHop {
            gateway: addr_str.parse()?,
            interface: Some(interface.to_string()),
        })
    } else {
        Ok(NextHop {
            gateway: next_hop.parse()?,
            interface: None,
        })
    }
}

/// Remove all IPv4 BGP routes from the kernel.
async fn remove_all_bgp_routes_v4(handle: &Handle) -> usize {
    let mut filter = RouteMessage::default();
    filter.header.address_family = AddressFamily::Inet;

    let routes: Vec<RouteMessage> = match handle.route().get(filter).execute().try_collect().await {
        Ok(routes) => routes,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to enumerate IPv4 routes for cleanup");
            return 0;
        }
    };

    let mut removed = 0;
    for route in routes {
        if route.header.protocol == RTPROT_BGP {
            if let Err(e) = handle.route().del(route).execute().await {
                tracing::warn!(error = %e, "Failed to remove IPv4 BGP route during shutdown");
            } else {
                removed += 1;
            }
        }
    }

    removed
}

/// Remove all IPv6 BGP routes from the kernel.
async fn remove_all_bgp_routes_v6(handle: &Handle) -> usize {
    let mut filter = RouteMessage::default();
    filter.header.address_family = AddressFamily::Inet6;

    let routes: Vec<RouteMessage> = match handle.route().get(filter).execute().try_collect().await {
        Ok(routes) => routes,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to enumerate IPv6 routes for cleanup");
            return 0;
        }
    };

    let mut removed = 0;
    for route in routes {
        if route.header.protocol == RTPROT_BGP {
            if let Err(e) = handle.route().del(route).execute().await {
                tracing::warn!(error = %e, "Failed to remove IPv6 BGP route during shutdown");
            } else {
                removed += 1;
            }
        }
    }

    removed
}
