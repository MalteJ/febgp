//! Routing Information Base (RIB) for BGP routes.
//!
//! This module manages the BGP routing table including:
//! - Route storage and lookup
//! - Best path selection (shortest AS path, ECMP for equal paths)
//! - Kernel route installation via netlink

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::bgp::ParsedRoute;
use crate::error::RibError;
use crate::netlink::NetlinkHandle;

/// Special peer index for locally originated routes (via API).
pub const LOCAL_PEER_IDX: usize = usize::MAX;

/// Events emitted when routes change in the RIB.
/// Subscribers receive these via the broadcast channel.
#[derive(Debug, Clone)]
pub enum RouteEvent {
    /// A new route was added to the RIB.
    Added(RouteEntry),
    /// A route was withdrawn from the RIB.
    Withdrawn {
        prefix: String,
        next_hop: String,
        peer_idx: usize,
    },
    /// Best path changed for a prefix (includes the new best route).
    BestChanged(RouteEntry),
}

/// A locally originated route added via API.
#[derive(Debug, Clone)]
pub struct ApiRoute {
    pub prefix: String,
    pub next_hop: Option<String>,
    pub as_path: Vec<u32>,
}

/// Events for API route changes that need to be advertised to peers.
#[derive(Debug, Clone)]
pub enum ApiRouteAdvertisement {
    /// Announce a new route to all peers.
    Announce(ApiRoute),
    /// Withdraw a route from all peers.
    Withdraw { prefix: String },
}

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
    /// Remove all routes from kernel (for shutdown cleanup).
    RemoveAllRoutes {
        response: oneshot::Sender<usize>,
    },
    /// Add a locally originated route (via API).
    AddApiRoute {
        route: ApiRoute,
        response: oneshot::Sender<Result<(), RibError>>,
    },
    /// Withdraw a locally originated route (via API).
    WithdrawApiRoute {
        prefix: String,
        response: oneshot::Sender<Result<(), RibError>>,
    },
    /// Get all locally originated routes (for advertising to new peers).
    GetApiRoutes {
        response: oneshot::Sender<Vec<ApiRoute>>,
    },
}

/// The Routing Information Base.
pub struct Rib {
    routes: Vec<RouteEntry>,
    /// Locally originated routes (added via API).
    api_routes: Vec<ApiRoute>,
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
            api_routes: Vec::new(),
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
            api_routes: Vec::new(),
            netlink: Some(NetlinkHandle::new()?),
        })
    }

    /// Get all API routes.
    pub fn api_routes(&self) -> &[ApiRoute] {
        &self.api_routes
    }

    /// Add a locally originated route.
    pub fn add_api_route(&mut self, route: ApiRoute) -> Result<(), RibError> {
        // Check if route already exists
        if self.api_routes.iter().any(|r| r.prefix == route.prefix) {
            return Err(RibError::DuplicateRoute(route.prefix));
        }

        // Validate prefix format
        if !is_valid_prefix(&route.prefix) {
            return Err(RibError::InvalidPrefix(route.prefix));
        }

        self.api_routes.push(route);
        Ok(())
    }

    /// Withdraw a locally originated route.
    pub fn withdraw_api_route(&mut self, prefix: &str) -> Result<ApiRoute, RibError> {
        let idx = self.api_routes.iter().position(|r| r.prefix == prefix);
        match idx {
            Some(i) => Ok(self.api_routes.remove(i)),
            None => Err(RibError::RouteNotFound(prefix.to_string())),
        }
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

        // Calculate diff for return value
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

        // Update kernel route with all current nexthops (multipath/replace)
        if let Some(ref netlink) = self.netlink {
            let nexthops: Vec<String> = currently_best
                .iter()
                .map(|(_, nh)| nh.clone())
                .collect();

            if nexthops.is_empty() {
                if let Err(e) = netlink.remove_prefix(&prefix).await {
                    tracing::warn!(prefix = %prefix, error = %e, "Failed to remove prefix");
                }
            } else if let Err(e) = netlink.set_route(&prefix, &nexthops).await {
                tracing::warn!(prefix = %prefix, error = %e, "Failed to set route");
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

        // Remove routes from RIB
        let removed_count = routes_to_remove.len();
        self.routes.retain(|r| r.peer_idx != peer_idx);

        // Recalculate best paths and update kernel for each affected prefix
        for prefix in &affected_prefixes {
            recalculate_best_paths(&mut self.routes, prefix);

            if let Some(ref netlink) = self.netlink {
                // Get all currently best nexthops for this prefix
                let nexthops: Vec<String> = self
                    .routes
                    .iter()
                    .filter(|r| r.prefix == *prefix && r.best)
                    .map(|r| r.next_hop.clone())
                    .collect();

                if nexthops.is_empty() {
                    // No more routes for this prefix - remove from kernel
                    if let Err(e) = netlink.remove_prefix(prefix).await {
                        tracing::warn!(prefix = %prefix, error = %e, "Failed to remove prefix");
                    }
                } else if let Err(e) = netlink.set_route(prefix, &nexthops).await {
                    // Update with remaining nexthops (multipath/replace)
                    tracing::warn!(prefix = %prefix, error = %e, "Failed to set failover route");
                }
            }
        }

        removed_count
    }

    /// Remove all installed BGP routes from the kernel.
    ///
    /// This is called during daemon shutdown to clean up routes.
    /// Queries the kernel directly for all routes with RTPROT_BGP protocol
    /// and removes them - more robust than iterating through the RIB.
    /// Returns the number of routes removed.
    pub async fn remove_all_routes(&mut self) -> usize {
        if let Some(ref netlink) = self.netlink {
            let removed = netlink.remove_all_bgp_routes().await;
            if removed > 0 {
                tracing::info!(routes_removed = removed, "Removed {} BGP route(s) from kernel during shutdown", removed);
            }
            removed
        } else {
            0
        }
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

/// Validate prefix format (basic CIDR validation).
fn is_valid_prefix(prefix: &str) -> bool {
    let parts: Vec<&str> = prefix.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    // Check if it's a valid IP address
    let ip_valid = parts[0].parse::<std::net::IpAddr>().is_ok();

    // Check if prefix length is valid
    let prefix_len_valid = parts[1].parse::<u8>().is_ok();

    ip_valid && prefix_len_valid
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
    /// Broadcast sender for route change events.
    event_tx: broadcast::Sender<RouteEvent>,
}

impl RibActor {
    /// Create a new RibActor.
    ///
    /// If `install_routes` is true, routes will be installed into the
    /// Linux kernel via netlink.
    ///
    /// Returns the actor and a broadcast sender that can be cloned for subscribers.
    pub fn new(
        command_rx: mpsc::Receiver<RibCommand>,
        install_routes: bool,
    ) -> Result<(Self, broadcast::Sender<RouteEvent>), Box<dyn std::error::Error + Send + Sync>> {
        let rib = if install_routes {
            Rib::with_netlink()?
        } else {
            Rib::new()
        };

        // Create broadcast channel with reasonable capacity for route events.
        // Subscribers that fall behind will miss events (lagged).
        let (event_tx, _) = broadcast::channel(1024);
        let event_tx_clone = event_tx.clone();

        Ok((Self { rib, command_rx, event_tx }, event_tx_clone))
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
                    let prefix = route.prefix.clone();
                    self.rib.add_route(peer_idx, route, &interface).await;
                    // Emit event for the added/updated route
                    if let Some(entry) = self.rib.routes().iter().find(|r| r.prefix == prefix && r.peer_idx == peer_idx) {
                        let _ = self.event_tx.send(RouteEvent::Added(entry.clone()));
                    }
                }
                RibCommand::AddRoutes {
                    peer_idx,
                    routes,
                    interface,
                } => {
                    for route in routes {
                        let prefix = route.prefix.clone();
                        self.rib.add_route(peer_idx, route, &interface).await;
                        // Emit event for each added/updated route
                        if let Some(entry) = self.rib.routes().iter().find(|r| r.prefix == prefix && r.peer_idx == peer_idx) {
                            let _ = self.event_tx.send(RouteEvent::Added(entry.clone()));
                        }
                    }
                }
                RibCommand::RemovePeerRoutes { peer_idx, response } => {
                    // Collect routes to be removed before removal
                    let withdrawn: Vec<_> = self.rib.routes()
                        .iter()
                        .filter(|r| r.peer_idx == peer_idx)
                        .map(|r| (r.prefix.clone(), r.next_hop.clone()))
                        .collect();

                    let count = self.rib.remove_peer_routes(peer_idx).await;

                    // Emit withdrawn events
                    for (prefix, next_hop) in withdrawn {
                        let _ = self.event_tx.send(RouteEvent::Withdrawn {
                            prefix,
                            next_hop,
                            peer_idx,
                        });
                    }

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
                RibCommand::RemoveAllRoutes { response } => {
                    // Collect all routes before removal for withdrawal events
                    let withdrawn: Vec<_> = self.rib.routes()
                        .iter()
                        .map(|r| (r.prefix.clone(), r.next_hop.clone(), r.peer_idx))
                        .collect();

                    let count = self.rib.remove_all_routes().await;

                    // Emit withdrawn events for all routes
                    for (prefix, next_hop, peer_idx) in withdrawn {
                        let _ = self.event_tx.send(RouteEvent::Withdrawn {
                            prefix,
                            next_hop,
                            peer_idx,
                        });
                    }

                    let _ = response.send(count);
                }
                RibCommand::AddApiRoute { route, response } => {
                    let prefix = route.prefix.clone();
                    let result = self.rib.add_api_route(route.clone());
                    if result.is_ok() {
                        // Create a RouteEntry for the API route (for event emission)
                        let entry = RouteEntry {
                            prefix: prefix.clone(),
                            next_hop: route.next_hop.clone().unwrap_or_default(),
                            as_path: route.as_path.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(" "),
                            as_path_len: route.as_path.len(),
                            origin: "IGP".to_string(),
                            peer_idx: LOCAL_PEER_IDX,
                            best: true,
                        };
                        let _ = self.event_tx.send(RouteEvent::Added(entry));
                        tracing::info!(prefix = %prefix, "Added API route");
                    }
                    let _ = response.send(result);
                }
                RibCommand::WithdrawApiRoute { prefix, response } => {
                    let result = self.rib.withdraw_api_route(&prefix);
                    if let Ok(route) = &result {
                        let _ = self.event_tx.send(RouteEvent::Withdrawn {
                            prefix: route.prefix.clone(),
                            next_hop: route.next_hop.clone().unwrap_or_default(),
                            peer_idx: LOCAL_PEER_IDX,
                        });
                        tracing::info!(prefix = %route.prefix, "Withdrawn API route");
                    }
                    let _ = response.send(result.map(|_| ()));
                }
                RibCommand::GetApiRoutes { response } => {
                    let routes = self.rib.api_routes().to_vec();
                    let _ = response.send(routes);
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
    /// Broadcast sender for subscribing to route events.
    event_tx: broadcast::Sender<RouteEvent>,
}

impl RibHandle {
    /// Create a new RibHandle from an mpsc sender and broadcast sender.
    pub fn new(sender: mpsc::Sender<RibCommand>, event_tx: broadcast::Sender<RouteEvent>) -> Self {
        Self { sender, event_tx }
    }

    /// Subscribe to route update events.
    ///
    /// Returns a receiver that will receive RouteEvent notifications
    /// whenever routes are added, withdrawn, or best path changes.
    pub fn subscribe_updates(&self) -> broadcast::Receiver<RouteEvent> {
        self.event_tx.subscribe()
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

    /// Remove all routes from kernel (for shutdown cleanup).
    pub async fn remove_all_routes(&self) -> usize {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(RibCommand::RemoveAllRoutes { response: tx })
            .await
            .is_ok()
        {
            rx.await.unwrap_or(0)
        } else {
            0
        }
    }

    /// Add a locally originated route (via API).
    pub async fn add_api_route(&self, route: ApiRoute) -> Result<(), RibError> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(RibCommand::AddApiRoute { route, response: tx })
            .await
            .is_ok()
        {
            rx.await
                .unwrap_or_else(|_| Err(RibError::ChannelError("channel closed".to_string())))
        } else {
            Err(RibError::ChannelError("failed to send command".to_string()))
        }
    }

    /// Withdraw a locally originated route (via API).
    pub async fn withdraw_api_route(&self, prefix: String) -> Result<(), RibError> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(RibCommand::WithdrawApiRoute { prefix, response: tx })
            .await
            .is_ok()
        {
            rx.await
                .unwrap_or_else(|_| Err(RibError::ChannelError("channel closed".to_string())))
        } else {
            Err(RibError::ChannelError("failed to send command".to_string()))
        }
    }

    /// Get all locally originated routes.
    pub async fn get_api_routes(&self) -> Vec<ApiRoute> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(RibCommand::GetApiRoutes { response: tx })
            .await
            .is_ok()
        {
            rx.await.unwrap_or_default()
        } else {
            Vec::new()
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

    // Tests for new API route functionality

    #[test]
    fn test_is_valid_prefix_ipv4() {
        assert!(is_valid_prefix("10.0.0.0/24"));
        assert!(is_valid_prefix("192.168.1.0/32"));
        assert!(is_valid_prefix("0.0.0.0/0"));
    }

    #[test]
    fn test_is_valid_prefix_ipv6() {
        assert!(is_valid_prefix("2001:db8::/32"));
        assert!(is_valid_prefix("fe80::1/128"));
        assert!(is_valid_prefix("::/0"));
    }

    #[test]
    fn test_is_valid_prefix_invalid() {
        assert!(!is_valid_prefix("10.0.0.0")); // Missing prefix length
        assert!(!is_valid_prefix("invalid/24")); // Invalid IP
        assert!(!is_valid_prefix("10.0.0.0/abc")); // Invalid prefix length
        assert!(!is_valid_prefix("")); // Empty string
    }

    #[test]
    fn test_api_route_add() {
        let mut rib = Rib::new();

        let route = ApiRoute {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: Some("192.168.1.1".to_string()),
            as_path: vec![65001],
        };

        let result = rib.add_api_route(route);
        assert!(result.is_ok());
        assert_eq!(rib.api_routes().len(), 1);
        assert_eq!(rib.api_routes()[0].prefix, "10.0.0.0/24");
    }

    #[test]
    fn test_api_route_add_duplicate() {
        let mut rib = Rib::new();

        let route1 = ApiRoute {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: None,
            as_path: vec![],
        };

        let route2 = ApiRoute {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: Some("192.168.1.1".to_string()),
            as_path: vec![65001],
        };

        assert!(rib.add_api_route(route1).is_ok());
        let result = rib.add_api_route(route2);
        assert!(matches!(result, Err(RibError::DuplicateRoute(_))));
    }

    #[test]
    fn test_api_route_add_invalid_prefix() {
        let mut rib = Rib::new();

        let route = ApiRoute {
            prefix: "invalid".to_string(),
            next_hop: None,
            as_path: vec![],
        };

        let result = rib.add_api_route(route);
        assert!(matches!(result, Err(RibError::InvalidPrefix(_))));
    }

    #[test]
    fn test_api_route_withdraw() {
        let mut rib = Rib::new();

        let route = ApiRoute {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: None,
            as_path: vec![],
        };

        rib.add_api_route(route).unwrap();
        assert_eq!(rib.api_routes().len(), 1);

        let result = rib.withdraw_api_route("10.0.0.0/24");
        assert!(result.is_ok());
        assert_eq!(rib.api_routes().len(), 0);
    }

    #[test]
    fn test_api_route_withdraw_not_found() {
        let mut rib = Rib::new();

        let result = rib.withdraw_api_route("10.0.0.0/24");
        assert!(matches!(result, Err(RibError::RouteNotFound(_))));
    }

    #[tokio::test]
    async fn test_rib_actor_route_events() {
        use tokio::sync::mpsc;

        let (tx, rx) = mpsc::channel::<RibCommand>(32);
        let (actor, event_tx) = RibActor::new(rx, false).unwrap();

        // Subscribe to events before spawning actor
        let mut event_rx = event_tx.subscribe();

        // Spawn the actor
        tokio::spawn(actor.run());

        // Create handle
        let handle = RibHandle::new(tx, event_tx);

        // Add a route
        let route = test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);
        handle.add_route(0, route, "eth0".to_string()).await;

        // Wait for and verify the event
        let event = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            event_rx.recv()
        ).await;

        assert!(event.is_ok());
        let event = event.unwrap().unwrap();
        match event {
            RouteEvent::Added(entry) => {
                assert_eq!(entry.prefix, "10.0.0.0/24");
                assert_eq!(entry.peer_idx, 0);
            }
            _ => panic!("Expected RouteEvent::Added"),
        }
    }

    #[tokio::test]
    async fn test_rib_actor_api_route_add() {
        use tokio::sync::mpsc;

        let (tx, rx) = mpsc::channel::<RibCommand>(32);
        let (actor, event_tx) = RibActor::new(rx, false).unwrap();

        // Subscribe to events
        let mut event_rx = event_tx.subscribe();

        // Spawn the actor
        tokio::spawn(actor.run());

        // Create handle
        let handle = RibHandle::new(tx, event_tx);

        // Add an API route
        let route = ApiRoute {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: Some("192.168.1.1".to_string()),
            as_path: vec![65001],
        };

        let result = handle.add_api_route(route).await;
        assert!(result.is_ok());

        // Verify event was emitted
        let event = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            event_rx.recv()
        ).await;

        assert!(event.is_ok());
        let event = event.unwrap().unwrap();
        match event {
            RouteEvent::Added(entry) => {
                assert_eq!(entry.prefix, "10.0.0.0/24");
                assert_eq!(entry.peer_idx, LOCAL_PEER_IDX);
            }
            _ => panic!("Expected RouteEvent::Added"),
        }
    }

    #[tokio::test]
    async fn test_rib_actor_api_route_withdraw() {
        use tokio::sync::mpsc;

        let (tx, rx) = mpsc::channel::<RibCommand>(32);
        let (actor, event_tx) = RibActor::new(rx, false).unwrap();

        // Subscribe to events
        let mut event_rx = event_tx.subscribe();

        // Spawn the actor
        tokio::spawn(actor.run());

        // Create handle
        let handle = RibHandle::new(tx, event_tx);

        // Add an API route first
        let route = ApiRoute {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: None,
            as_path: vec![],
        };
        handle.add_api_route(route).await.unwrap();

        // Consume the add event
        let _ = event_rx.recv().await;

        // Withdraw the route
        let result = handle.withdraw_api_route("10.0.0.0/24".to_string()).await;
        assert!(result.is_ok());

        // Verify withdrawal event
        let event = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            event_rx.recv()
        ).await;

        assert!(event.is_ok());
        let event = event.unwrap().unwrap();
        match event {
            RouteEvent::Withdrawn { prefix, peer_idx, .. } => {
                assert_eq!(prefix, "10.0.0.0/24");
                assert_eq!(peer_idx, LOCAL_PEER_IDX);
            }
            _ => panic!("Expected RouteEvent::Withdrawn"),
        }
    }

    #[tokio::test]
    async fn test_rib_handle_get_api_routes() {
        use tokio::sync::mpsc;

        let (tx, rx) = mpsc::channel::<RibCommand>(32);
        let (actor, event_tx) = RibActor::new(rx, false).unwrap();

        tokio::spawn(actor.run());
        let handle = RibHandle::new(tx, event_tx);

        // Add some API routes
        handle.add_api_route(ApiRoute {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: None,
            as_path: vec![],
        }).await.unwrap();

        handle.add_api_route(ApiRoute {
            prefix: "192.168.0.0/16".to_string(),
            next_hop: Some("10.0.0.1".to_string()),
            as_path: vec![65001, 65002],
        }).await.unwrap();

        // Get API routes
        let routes = handle.get_api_routes().await;
        assert_eq!(routes.len(), 2);

        let prefixes: Vec<_> = routes.iter().map(|r| r.prefix.as_str()).collect();
        assert!(prefixes.contains(&"10.0.0.0/24"));
        assert!(prefixes.contains(&"192.168.0.0/16"));
    }

    #[tokio::test]
    async fn test_rib_handle_subscribe_updates() {
        use tokio::sync::mpsc;

        let (tx, rx) = mpsc::channel::<RibCommand>(32);
        let (actor, event_tx) = RibActor::new(rx, false).unwrap();

        tokio::spawn(actor.run());
        let handle = RibHandle::new(tx, event_tx);

        // Subscribe to updates
        let mut rx1 = handle.subscribe_updates();
        let mut rx2 = handle.subscribe_updates();

        // Add a route
        let route = test_route("10.0.0.0/24", "192.168.1.1", vec![65001]);
        handle.add_route(0, route, "eth0".to_string()).await;

        // Both subscribers should receive the event
        let event1 = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            rx1.recv()
        ).await;
        let event2 = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            rx2.recv()
        ).await;

        assert!(event1.is_ok());
        assert!(event2.is_ok());
    }
}
