//! Routing Information Base (RIB) for BGP routes.
//!
//! This module manages the BGP routing table including:
//! - Route storage and lookup
//! - Best path selection (shortest AS path, ECMP for equal paths)
//! - Kernel route installation via netlink

use tokio::sync::{mpsc, oneshot};

use crate::bgp::ParsedRoute;
use crate::netlink::NetlinkHandle;

/// A route entry in the RIB.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub prefix: String,
    pub next_hop: String,
    pub as_path: String,
    pub as_path_len: usize,
    pub origin: String,
    pub peer_idx: usize,
    pub best: bool,
}

/// Commands sent to the RibActor.
pub enum RibCommand {
    /// Add a single route from a peer session.
    AddRoute {
        peer_idx: usize,
        route: ParsedRoute,
        interface: String,
    },
    /// Add multiple routes in a batch (from a single UPDATE message).
    AddRoutes {
        peer_idx: usize,
        routes: Vec<ParsedRoute>,
        interface: String,
    },
    /// Remove all routes from a peer (session went down).
    RemovePeerRoutes {
        peer_idx: usize,
        response: oneshot::Sender<usize>,
    },
    /// Get all routes (for gRPC get_routes).
    GetRoutes {
        response: oneshot::Sender<Vec<RouteEntry>>,
    },
    /// Get route count from a specific peer.
    GetPeerStats {
        peer_idx: usize,
        response: oneshot::Sender<usize>,
    },
}

/// The Routing Information Base.
pub struct Rib {
    routes: Vec<RouteEntry>,
    /// Reusable netlink handle for route installation (None if route installation disabled)
    netlink: Option<NetlinkHandle>,
}

impl Default for Rib {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Rib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rib")
            .field("routes", &self.routes)
            .field("netlink", &self.netlink.is_some())
            .finish()
    }
}

impl Rib {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            netlink: None,
        }
    }

    /// Create a new RIB with route installation enabled.
    ///
    /// This establishes a persistent netlink connection that will be reused
    /// for all route install/remove operations.
    pub fn with_netlink() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            routes: Vec::new(),
            netlink: Some(NetlinkHandle::new()?),
        })
    }

    /// Get all routes.
    pub fn routes(&self) -> &[RouteEntry] {
        &self.routes
    }

    /// Get mutable access to routes (for API compatibility during migration).
    pub fn routes_mut(&mut self) -> &mut Vec<RouteEntry> {
        &mut self.routes
    }

    /// Count routes from a specific peer.
    pub fn count_routes_from_peer(&self, peer_idx: usize) -> usize {
        self.routes.iter().filter(|r| r.peer_idx == peer_idx).count()
    }

    /// Add or update a route from a peer.
    ///
    /// If the RIB was created with `with_netlink()`, routes will be automatically
    /// installed/removed from the kernel.
    ///
    /// Returns the routes that need to be installed/removed from the kernel:
    /// - `to_install`: Routes that are now best but weren't before
    /// - `to_remove`: Routes that were best but aren't anymore
    pub async fn add_route(
        &mut self,
        peer_idx: usize,
        route: ParsedRoute,
        interface: &str,
    ) -> (Vec<(String, String)>, Vec<(String, String)>) {
        let as_path_str = route
            .as_path
            .iter()
            .map(|asn| asn.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        let as_path_len = route.as_path.len();
        let prefix = route.prefix.clone();

        // Format next-hop with interface suffix for link-local addresses
        let next_hop_str = format_next_hop(&route.next_hop.to_string(), interface);

        // Check if we already have a route from this peer for this prefix
        let existing = self
            .routes
            .iter_mut()
            .find(|r| r.prefix == prefix && r.peer_idx == peer_idx);

        if let Some(existing_route) = existing {
            existing_route.next_hop = next_hop_str;
            existing_route.as_path = as_path_str;
            existing_route.as_path_len = as_path_len;
            existing_route.origin = route.origin.to_string();
        } else {
            self.routes.push(RouteEntry {
                prefix: prefix.clone(),
                next_hop: next_hop_str,
                as_path: as_path_str,
                as_path_len,
                origin: route.origin.to_string(),
                peer_idx,
                best: false,
            });
        }

        // Collect routes that were previously best
        let previously_best: Vec<(String, String)> = self
            .routes
            .iter()
            .filter(|r| r.prefix == prefix && r.best)
            .map(|r| (r.prefix.clone(), r.next_hop.clone()))
            .collect();

        // Recalculate best paths
        recalculate_best_paths(&mut self.routes, &prefix);

        // Get currently best routes
        let currently_best: Vec<(String, String)> = self
            .routes
            .iter()
            .filter(|r| r.prefix == prefix && r.best)
            .map(|r| (r.prefix.clone(), r.next_hop.clone()))
            .collect();

        // Calculate diff
        let to_install: Vec<(String, String)> = currently_best
            .iter()
            .filter(|(p, nh)| !previously_best.iter().any(|(pp, pnh)| pp == p && pnh == nh))
            .cloned()
            .collect();

        let to_remove: Vec<(String, String)> = previously_best
            .iter()
            .filter(|(p, nh)| !currently_best.iter().any(|(cp, cnh)| cp == p && cnh == nh))
            .cloned()
            .collect();

        // Apply kernel route changes using the reusable netlink handle
        if let Some(ref netlink) = self.netlink {
            for (prefix, next_hop) in &to_install {
                if let Err(e) = netlink.install_route(prefix, next_hop).await {
                    tracing::warn!(prefix = %prefix, error = %e, "Failed to install route");
                }
            }

            for (prefix, next_hop) in &to_remove {
                if let Err(e) = netlink.remove_route(prefix, next_hop).await {
                    tracing::warn!(prefix = %prefix, error = %e, "Failed to remove route");
                }
            }
        }

        (to_install, to_remove)
    }

    /// Remove all routes from a peer (called when session goes down).
    ///
    /// If the RIB was created with `with_netlink()`, routes will be automatically
    /// removed from the kernel and failover routes will be installed.
    ///
    /// Returns the number of routes removed.
    pub async fn remove_peer_routes(&mut self, peer_idx: usize) -> usize {
        // Collect routes to remove and affected prefixes
        let routes_to_remove: Vec<(String, String, bool)> = self
            .routes
            .iter()
            .filter(|r| r.peer_idx == peer_idx)
            .map(|r| (r.prefix.clone(), r.next_hop.clone(), r.best))
            .collect();

        let affected_prefixes: Vec<String> = routes_to_remove
            .iter()
            .map(|(p, _, _)| p.clone())
            .collect();

        // Get remaining best routes (from OTHER peers) BEFORE removal
        let mut remaining_best_before: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for prefix in &affected_prefixes {
            let best_routes: Vec<String> = self
                .routes
                .iter()
                .filter(|r| r.prefix == *prefix && r.best && r.peer_idx != peer_idx)
                .map(|r| r.next_hop.clone())
                .collect();
            remaining_best_before.insert(prefix.clone(), best_routes);
        }

        // Remove routes
        let removed_count = routes_to_remove.len();
        self.routes.retain(|r| r.peer_idx != peer_idx);

        // Recalculate best paths and update kernel
        for prefix in &affected_prefixes {
            recalculate_best_paths(&mut self.routes, prefix);

            if let Some(ref netlink) = self.netlink {
                // Remove routes from this peer that were best
                for (p, nh, was_best) in &routes_to_remove {
                    if p == prefix && *was_best {
                        if let Err(e) = netlink.remove_route(p, nh).await {
                            tracing::warn!(prefix = %p, error = %e, "Failed to remove route");
                        }
                    }
                }

                // Install newly best routes (failover)
                let currently_best: Vec<String> = self
                    .routes
                    .iter()
                    .filter(|r| r.prefix == *prefix && r.best)
                    .map(|r| r.next_hop.clone())
                    .collect();

                let previously_best = remaining_best_before.get(prefix).cloned().unwrap_or_default();
                for next_hop in &currently_best {
                    if !previously_best.contains(next_hop) {
                        if let Err(e) = netlink.install_route(prefix, next_hop).await {
                            tracing::warn!(prefix = %prefix, error = %e, "Failed to install failover route");
                        }
                    }
                }
            }
        }

        removed_count
    }
}

/// Format next-hop with interface suffix for link-local IPv6 addresses.
fn format_next_hop(next_hop: &str, interface: &str) -> String {
    if next_hop.starts_with("fe80:") || next_hop.starts_with("FE80:") {
        format!("{}%{}", next_hop, interface)
    } else {
        next_hop.to_string()
    }
}

/// Recalculate best paths for a given prefix.
/// Shorter AS path wins. Equal AS path length = ECMP (all marked as best).
fn recalculate_best_paths(routes: &mut [RouteEntry], prefix: &str) {
    let min_as_path_len = routes
        .iter()
        .filter(|r| r.prefix == prefix)
        .map(|r| r.as_path_len)
        .min();

    if let Some(min_len) = min_as_path_len {
        for route in routes.iter_mut() {
            if route.prefix == prefix {
                route.best = route.as_path_len == min_len;
            }
        }
    }
}

/// Actor that owns and manages the RIB.
///
/// The RibActor runs in its own Tokio task and processes commands
/// sent via an mpsc channel. This eliminates lock contention between
/// peer sessions and gRPC handlers.
pub struct RibActor {
    rib: Rib,
    command_rx: mpsc::Receiver<RibCommand>,
}

impl RibActor {
    /// Create a new RibActor.
    ///
    /// If `install_routes` is true, routes will be installed into the
    /// Linux kernel via netlink.
    pub fn new(
        command_rx: mpsc::Receiver<RibCommand>,
        install_routes: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let rib = if install_routes {
            Rib::with_netlink()?
        } else {
            Rib::new()
        };

        Ok(Self { rib, command_rx })
    }

    /// Run the actor event loop.
    ///
    /// This method consumes the actor and runs until the command channel
    /// is closed (all senders dropped).
    pub async fn run(mut self) {
        while let Some(cmd) = self.command_rx.recv().await {
            match cmd {
                RibCommand::AddRoute {
                    peer_idx,
                    route,
                    interface,
                } => {
                    self.rib.add_route(peer_idx, route, &interface).await;
                }
                RibCommand::AddRoutes {
                    peer_idx,
                    routes,
                    interface,
                } => {
                    for route in routes {
                        self.rib.add_route(peer_idx, route, &interface).await;
                    }
                }
                RibCommand::RemovePeerRoutes { peer_idx, response } => {
                    let count = self.rib.remove_peer_routes(peer_idx).await;
                    let _ = response.send(count);
                }
                RibCommand::GetRoutes { response } => {
                    let routes = self.rib.routes().to_vec();
                    let _ = response.send(routes);
                }
                RibCommand::GetPeerStats { peer_idx, response } => {
                    let count = self.rib.count_routes_from_peer(peer_idx);
                    let _ = response.send(count);
                }
            }
        }
    }
}

/// Handle for sending commands to the RibActor.
///
/// This is a lightweight, cloneable handle that can be shared across
/// multiple peer sessions and the gRPC service.
#[derive(Clone)]
pub struct RibHandle {
    sender: mpsc::Sender<RibCommand>,
}

impl RibHandle {
    /// Create a new RibHandle from an mpsc sender.
    pub fn new(sender: mpsc::Sender<RibCommand>) -> Self {
        Self { sender }
    }

    /// Add a single route (fire-and-forget).
    pub async fn add_route(&self, peer_idx: usize, route: ParsedRoute, interface: String) {
        let _ = self
            .sender
            .send(RibCommand::AddRoute {
                peer_idx,
                route,
                interface,
            })
            .await;
    }

    /// Add multiple routes in a batch (fire-and-forget).
    pub async fn add_routes(&self, peer_idx: usize, routes: Vec<ParsedRoute>, interface: String) {
        let _ = self
            .sender
            .send(RibCommand::AddRoutes {
                peer_idx,
                routes,
                interface,
            })
            .await;
    }

    /// Remove all routes from a peer, returns count.
    pub async fn remove_peer_routes(&self, peer_idx: usize) -> usize {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(RibCommand::RemovePeerRoutes {
                peer_idx,
                response: tx,
            })
            .await
            .is_ok()
        {
            rx.await.unwrap_or(0)
        } else {
            0
        }
    }

    /// Get all routes (cloned).
    pub async fn get_routes(&self) -> Vec<RouteEntry> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(RibCommand::GetRoutes { response: tx })
            .await
            .is_ok()
        {
            rx.await.unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Get route count for a specific peer.
    pub async fn get_peer_stats(&self, peer_idx: usize) -> usize {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(RibCommand::GetPeerStats {
                peer_idx,
                response: tx,
            })
            .await
            .is_ok()
        {
            rx.await.unwrap_or(0)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recalculate_best_paths_single_route() {
        let mut routes = vec![RouteEntry {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            as_path: "65001".to_string(),
            as_path_len: 1,
            origin: "IGP".to_string(),
            peer_idx: 0,
            best: false,
        }];

        recalculate_best_paths(&mut routes, "10.0.0.0/24");
        assert!(routes[0].best);
    }

    #[test]
    fn test_recalculate_best_paths_shorter_wins() {
        let mut routes = vec![
            RouteEntry {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                as_path: "65001 65002".to_string(),
                as_path_len: 2,
                origin: "IGP".to_string(),
                peer_idx: 0,
                best: false,
            },
            RouteEntry {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.2".to_string(),
                as_path: "65003".to_string(),
                as_path_len: 1,
                origin: "IGP".to_string(),
                peer_idx: 1,
                best: false,
            },
        ];

        recalculate_best_paths(&mut routes, "10.0.0.0/24");
        assert!(!routes[0].best); // Longer path
        assert!(routes[1].best); // Shorter path
    }

    #[test]
    fn test_recalculate_best_paths_ecmp() {
        let mut routes = vec![
            RouteEntry {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                as_path: "65001".to_string(),
                as_path_len: 1,
                origin: "IGP".to_string(),
                peer_idx: 0,
                best: false,
            },
            RouteEntry {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.2".to_string(),
                as_path: "65002".to_string(),
                as_path_len: 1,
                origin: "IGP".to_string(),
                peer_idx: 1,
                best: false,
            },
        ];

        recalculate_best_paths(&mut routes, "10.0.0.0/24");
        assert!(routes[0].best); // ECMP - both best
        assert!(routes[1].best);
    }

    #[test]
    fn test_format_next_hop_link_local() {
        assert_eq!(
            format_next_hop("fe80::1", "eth0"),
            "fe80::1%eth0"
        );
        assert_eq!(
            format_next_hop("FE80::1", "eth0"),
            "FE80::1%eth0"
        );
    }

    #[test]
    fn test_format_next_hop_global() {
        assert_eq!(
            format_next_hop("2001:db8::1", "eth0"),
            "2001:db8::1"
        );
        assert_eq!(
            format_next_hop("192.168.1.1", "eth0"),
            "192.168.1.1"
        );
    }

    // Helper for creating test routes
    fn test_route(prefix: &str, next_hop: &str, as_path: Vec<u32>) -> ParsedRoute {
        use crate::bgp::update::Origin;
        use std::net::IpAddr;
        ParsedRoute {
            prefix: prefix.to_string(),
            next_hop: next_hop.parse::<IpAddr>().unwrap(),
            as_path,
            origin: Origin::Igp,
        }
    }

    #[tokio::test]
    async fn test_rib_add_route_single() {
        let mut rib = Rib::new();
        let route = test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);

        let (to_install, to_remove) = rib.add_route(0, route, "eth0").await;

        assert_eq!(rib.routes().len(), 1);
        assert!(rib.routes()[0].best);
        assert_eq!(rib.routes()[0].prefix, "10.0.0.0/24");
        assert_eq!(to_install.len(), 1);
        assert_eq!(to_install[0].0, "10.0.0.0/24");
        assert!(to_remove.is_empty());
    }

    #[tokio::test]
    async fn test_rib_add_route_shorter_path_wins() {
        let mut rib = Rib::new();

        // Add route with longer AS path first
        let route1 = test_route("10.0.0.0/24", "192.168.1.1", vec![65001, 65002]);
        rib.add_route(0, route1, "eth0").await;
        assert!(rib.routes()[0].best);

        // Add route with shorter AS path from different peer
        let route2 = test_route("10.0.0.0/24", "192.168.1.2", vec![65003]);
        let (to_install, to_remove) = rib.add_route(1, route2, "eth0").await;

        assert_eq!(rib.routes().len(), 2);
        // First route should no longer be best
        let route_peer0 = rib.routes().iter().find(|r| r.peer_idx == 0).unwrap();
        assert!(!route_peer0.best);
        // Second route should be best
        let route_peer1 = rib.routes().iter().find(|r| r.peer_idx == 1).unwrap();
        assert!(route_peer1.best);
        // Should install new best, remove old best
        assert_eq!(to_install.len(), 1);
        assert_eq!(to_remove.len(), 1);
    }

    #[tokio::test]
    async fn test_rib_add_route_ecmp() {
        let mut rib = Rib::new();

        // Add two routes with equal AS path length
        let route1 = test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);
        rib.add_route(0, route1, "eth0").await;

        let route2 = test_route("10.0.0.0/24", "192.168.1.2", vec![65002]);
        let (to_install, _) = rib.add_route(1, route2, "eth0").await;

        assert_eq!(rib.routes().len(), 2);
        // Both routes should be best (ECMP)
        assert!(rib.routes().iter().all(|r| r.best));
        // Second route should be installed (first was already installed)
        assert_eq!(to_install.len(), 1);
    }

    #[tokio::test]
    async fn test_rib_add_route_updates_existing() {
        let mut rib = Rib::new();

        // Add route from peer 0
        let route1 = test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);
        rib.add_route(0, route1, "eth0").await;

        // Update route from same peer with different next-hop
        let route2 = test_route("10.0.0.0/24", "192.168.1.99", vec![65001, 65002]);
        rib.add_route(0, route2, "eth0").await;

        // Should still have only one route, not two
        assert_eq!(rib.routes().len(), 1);
        assert_eq!(rib.routes()[0].next_hop, "192.168.1.99");
        assert_eq!(rib.routes()[0].as_path, "65001 65002");
    }

    #[tokio::test]
    async fn test_rib_remove_peer_routes_basic() {
        let mut rib = Rib::new();

        // Add routes from two peers
        let route1 = test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);
        rib.add_route(0, route1, "eth0").await;
        let route2 = test_route("10.1.0.0/24", "192.168.1.2", vec![65002]);
        rib.add_route(1, route2, "eth0").await;

        assert_eq!(rib.routes().len(), 2);

        // Remove peer 0's routes
        let removed = rib.remove_peer_routes(0).await;

        assert_eq!(removed, 1);
        assert_eq!(rib.routes().len(), 1);
        assert_eq!(rib.routes()[0].peer_idx, 1);
    }

    #[tokio::test]
    async fn test_rib_remove_peer_routes_recalculates_best() {
        let mut rib = Rib::new();

        // Add short AS path from peer 0 (will be best)
        let route1 = test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);
        rib.add_route(0, route1, "eth0").await;

        // Add longer AS path from peer 1 (not best)
        let route2 = test_route("10.0.0.0/24", "192.168.1.2", vec![65002, 65003, 65004]);
        rib.add_route(1, route2, "eth0").await;

        // Verify peer 0 is best, peer 1 is not
        let peer0_route = rib.routes().iter().find(|r| r.peer_idx == 0).unwrap();
        let peer1_route = rib.routes().iter().find(|r| r.peer_idx == 1).unwrap();
        assert!(peer0_route.best);
        assert!(!peer1_route.best);

        // Remove peer 0's routes
        rib.remove_peer_routes(0).await;

        // Peer 1's route should now be best
        assert_eq!(rib.routes().len(), 1);
        assert!(rib.routes()[0].best);
        assert_eq!(rib.routes()[0].peer_idx, 1);
    }
}
