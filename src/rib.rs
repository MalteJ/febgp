//! Routing Information Base (RIB) for BGP routes.
//!
//! This module manages the BGP routing table including:
//! - Route storage and lookup
//! - Best path selection (shortest AS path, ECMP for equal paths)
//! - Kernel route installation via netlink

use crate::bgp::ParsedRoute;
use crate::netlink;

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

/// The Routing Information Base.
#[derive(Debug, Default)]
pub struct Rib {
    routes: Vec<RouteEntry>,
}

impl Rib {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
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
    /// Returns the routes that need to be installed/removed from the kernel:
    /// - `to_install`: Routes that are now best but weren't before
    /// - `to_remove`: Routes that were best but aren't anymore
    pub async fn add_route(
        &mut self,
        peer_idx: usize,
        route: ParsedRoute,
        interface: &str,
        install_routes: bool,
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

        // Apply kernel route changes
        if install_routes {
            for (prefix, next_hop) in &to_install {
                if let Err(e) = netlink::install_route(prefix, next_hop).await {
                    eprintln!("Failed to install route {}: {}", prefix, e);
                }
            }

            for (prefix, next_hop) in &to_remove {
                if let Err(e) = netlink::remove_route(prefix, next_hop).await {
                    eprintln!("Failed to remove route {}: {}", prefix, e);
                }
            }
        }

        (to_install, to_remove)
    }

    /// Remove all routes from a peer (called when session goes down).
    ///
    /// Returns the number of routes removed.
    pub async fn remove_peer_routes(&mut self, peer_idx: usize, install_routes: bool) -> usize {
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

            if install_routes {
                // Remove routes from this peer that were best
                for (p, nh, was_best) in &routes_to_remove {
                    if p == prefix && *was_best {
                        if let Err(e) = netlink::remove_route(p, nh).await {
                            eprintln!("Failed to remove route {}: {}", p, e);
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
                        if let Err(e) = netlink::install_route(prefix, next_hop).await {
                            eprintln!("Failed to install failover route {}: {}", prefix, e);
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
}
