//! Daemon peer session management.
//!
//! Handles running individual BGP peer sessions and managing their state.

pub mod startup;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{mpsc, watch, RwLock};
use tracing::{debug, error, info, warn};

use crate::api::server::DaemonState;
use crate::bgp::{
    build_ipv4_update, build_ipv6_update, parse_update, FsmConfig, FsmState, SessionActor,
    SessionCommand, SessionEvent, TcpTransport,
};
use crate::config::{Config, parse_peer_address, PeerConfig, SessionMode};
use crate::neighbor_discovery::get_interface_link_local;
use crate::peer_manager::PeerManagerHandle;
use crate::rib::{RibHandle, RouteEvent, LOCAL_PEER_IDX};

/// Context for running a peer session.
pub struct PeerSessionContext {
    pub peer_idx: usize,
    pub peer: PeerConfig,
    pub local_asn: u32,
    pub router_id: Ipv4Addr,
    pub state: Arc<RwLock<DaemonState>>,
    pub prefixes: Vec<String>,
    pub rib_handle: RibHandle,
    pub hold_time: u16,
    pub connect_retry_time: u64,
    pub ipv4_unicast: bool,
    pub ipv6_unicast: bool,
    pub shutdown_rx: watch::Receiver<bool>,
}

/// Shared daemon context bundling handles for task spawning.
///
/// This struct bundles all the shared handles needed by various daemon tasks,
/// eliminating the need to clone many individual Arc values when spawning tasks.
#[derive(Clone)]
pub struct DaemonContext {
    pub state: Arc<RwLock<DaemonState>>,
    pub rib_handle: RibHandle,
    pub session_senders: Arc<RwLock<Vec<mpsc::Sender<SessionCommand>>>>,
    pub peer_addr_to_sender: Arc<RwLock<HashMap<String, mpsc::Sender<SessionCommand>>>>,
    pub peer_manager_handle: PeerManagerHandle,
    pub config: Arc<Config>,
    pub shutdown_rx: watch::Receiver<bool>,
}

impl DaemonContext {
    /// Create a new peer session context from this daemon context.
    pub fn peer_session_context(&self, peer_idx: usize, peer: PeerConfig) -> PeerSessionContext {
        PeerSessionContext {
            peer_idx,
            peer,
            local_asn: self.config.asn,
            router_id: self.config.router_id,
            state: Arc::clone(&self.state),
            prefixes: self.config.prefixes.clone(),
            rib_handle: self.rib_handle.clone(),
            hold_time: self.config.hold_time,
            connect_retry_time: self.config.connect_retry_time,
            ipv4_unicast: self.config.ipv4_unicast,
            ipv6_unicast: self.config.ipv6_unicast,
            shutdown_rx: self.shutdown_rx.clone(),
        }
    }
}

/// Run a BGP session for a single peer.
///
/// Takes externally created channels to allow the caller to keep a reference
/// to the command sender for graceful shutdown.
///
/// The `peer_addr` parameter is optional - if None, it will be parsed from the
/// peer configuration. This allows sessions to be started either from explicit
/// config or from neighbor discovery.
pub async fn run_peer_session(
    ctx: PeerSessionContext,
    cmd_tx: mpsc::Sender<SessionCommand>,
    cmd_rx: mpsc::Receiver<SessionCommand>,
    peer_addr: Option<SocketAddr>,
) {
    let PeerSessionContext {
        peer_idx,
        peer,
        local_asn,
        router_id,
        state,
        prefixes,
        rib_handle,
        hold_time,
        connect_retry_time,
        ipv4_unicast,
        ipv6_unicast,
        shutdown_rx,
    } = ctx;

    let session_mode = peer.session_mode;

    // Get peer address - either passed in or parsed from config
    // For passive-only mode, address is optional (we accept incoming connections)
    let peer_addr = match peer_addr {
        Some(addr) => Some(addr),
        None => match parse_peer_address(&peer) {
            Ok(Some(addr)) => Some(addr),
            Ok(None) => {
                if session_mode == SessionMode::Passive {
                    // Passive mode doesn't require an address - we'll accept incoming
                    None
                } else {
                    error!(
                        interface = peer.interface,
                        "No peer address available for {}", peer.interface
                    );
                    return;
                }
            }
            Err(e) => {
                error!(
                    interface = peer.interface,
                    error = %e,
                    "Failed to parse peer address for {}: {}", peer.interface, e
                );
                return;
            }
        },
    };

    // Create display string for logging (used throughout the function)
    let peer_addr_display = peer_addr
        .as_ref()
        .map(|a| a.to_string())
        .unwrap_or_else(|| format!("passive:{}", peer.interface));

    match (session_mode, &peer_addr) {
        (SessionMode::Active | SessionMode::Both, Some(addr)) => {
            info!(
                peer = %addr,
                interface = peer.interface,
                mode = ?session_mode,
                "Starting BGP session to {} via {}", addr, peer.interface
            );
        }
        (SessionMode::Passive, _) => {
            info!(
                interface = peer.interface,
                mode = ?session_mode,
                "Waiting for incoming BGP connections on {}", peer.interface
            );
        }
        (_, None) => {
            // This shouldn't happen due to earlier check, but handle gracefully
            error!(
                interface = peer.interface,
                "No peer address for active session on {}", peer.interface
            );
            return;
        }
    }

    // Create FSM configuration
    let fsm_config = FsmConfig {
        local_asn,
        router_id,
        hold_time,
        peer_asn: peer.remote_asn.unwrap_or(0), // 0 = accept any (BGP unnumbered)
        connect_retry_time: std::time::Duration::from_secs(connect_retry_time),
        ipv4_unicast,
        ipv6_unicast,
    };

    // Create transport - use a placeholder address for passive-only mode
    let transport_addr = peer_addr.unwrap_or_else(|| {
        // Placeholder for passive mode - won't be used for outbound
        use std::net::{Ipv6Addr, SocketAddrV6};
        std::net::SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 179, 0, 0))
    });
    let transport = TcpTransport::new(transport_addr);

    // Create event channel
    let (event_tx, mut event_rx) = mpsc::channel::<SessionEvent>(16);

    // Create and spawn the session actor
    let actor = SessionActor::new(fsm_config, transport, cmd_rx, event_tx);
    tokio::spawn(actor.run());

    // Send start command only for active/both modes
    if session_mode != SessionMode::Passive {
        if let Err(e) = cmd_tx.send(SessionCommand::Start).await {
            error!(
                interface = peer.interface,
                error = %e,
                "Failed to start session for {}: {}", peer.interface, e
            );
            return;
        }
    }

    let mut established_at: Option<Instant> = None;
    let mut is_established = false;

    // Subscribe to route events for API route advertisements
    let mut route_events_rx = rib_handle.subscribe_updates();

    // Helper to announce a prefix to this peer
    let announce_prefix =
        |prefix: &str, local_asn: u32, local_link_local: std::net::Ipv6Addr| -> Option<bytes::Bytes> {
            if prefix.contains(':') {
                build_ipv6_update(prefix, local_asn, local_link_local)
            } else {
                build_ipv4_update(prefix, local_asn, local_link_local)
            }
        };

    // Process events from the session actor and route events
    loop {
        tokio::select! {
            // Handle session events
            event = event_rx.recv() => {
                let Some(event) = event else { break };

                match event {
                    SessionEvent::StateChange { to, .. } => {
                        update_peer_state(&state, peer_idx, to.into()).await;

                        if to == FsmState::Established {
                            established_at = Some(Instant::now());
                            is_established = true;
                            info!(peer = %peer_addr_display, "Session established with {}", peer_addr_display);
                        } else if to == FsmState::Idle {
                            established_at = None;
                            is_established = false;
                        }
                    }
                    SessionEvent::Established { peer_asn, peer_router_id, .. } => {
                        // Update with learned ASN
                        update_peer_asn(&state, peer_idx, peer_asn).await;
                        info!(
                            peer = %peer_addr_display,
                            asn = peer_asn,
                            router_id = %peer_router_id,
                            "Peer {} (AS{}) router-id: {}",
                            peer_addr_display, peer_asn, peer_router_id
                        );

                        // Get our link-local address for the interface to use as next-hop
                        let local_link_local = match get_interface_link_local(&peer.interface) {
                            Ok(addr) => addr,
                            Err(e) => {
                                error!(
                                    interface = peer.interface,
                                    error = %e,
                                    "Failed to get link-local address for {}: {}",
                                    peer.interface, e
                                );
                                continue;
                            }
                        };

                        // Announce configured prefixes
                        for prefix in &prefixes {
                            if let Some(body) = announce_prefix(prefix, local_asn, local_link_local) {
                                if let Err(e) = cmd_tx.send(SessionCommand::SendUpdate(body)).await {
                                    error!(
                                        prefix = prefix,
                                        peer = %peer_addr_display,
                                        error = %e,
                                        "Failed to send UPDATE for {}: {}", prefix, e
                                    );
                                } else {
                                    debug!(
                                        prefix = prefix,
                                        peer = %peer_addr_display,
                                        "Announced prefix {} to {}", prefix, peer_addr_display
                                    );
                                }
                            } else {
                                error!(prefix = prefix, "Failed to build UPDATE for prefix: {}", prefix);
                            }
                        }

                        // Also announce any existing API routes
                        let api_routes = rib_handle.get_api_routes().await;
                        for route in api_routes {
                            if let Some(body) = announce_prefix(&route.prefix, local_asn, local_link_local) {
                                if let Err(e) = cmd_tx.send(SessionCommand::SendUpdate(body)).await {
                                    error!(
                                        prefix = %route.prefix,
                                        peer = %peer_addr_display,
                                        error = %e,
                                        "Failed to send API route UPDATE: {}", e
                                    );
                                } else {
                                    debug!(
                                        prefix = %route.prefix,
                                        peer = %peer_addr_display,
                                        "Announced API route {} to {}", route.prefix, peer_addr_display
                                    );
                                }
                            }
                        }
                    }
                    SessionEvent::SessionDown { reason } => {
                        warn!(
                            peer = %peer_addr_display,
                            reason = reason,
                            "Session to {} went down: {}", peer_addr_display, reason
                        );
                        update_peer_state(&state, peer_idx, crate::bgp::SessionState::Idle).await;
                        is_established = false;

                        // Remove all routes from this peer via RibActor (no write lock needed for RIB)
                        let removed = rib_handle.remove_peer_routes(peer_idx).await;

                        // Update neighbor state
                        {
                            let mut s = state.write().await;
                            if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
                                neighbor.prefixes_received = 0;
                            }
                        }

                        if removed > 0 {
                            info!(
                                peer_idx = peer_idx,
                                routes_removed = removed,
                                "Removed {} route(s) from peer {}", removed, peer_idx
                            );
                        }
                        established_at = None;

                        // Automatic reconnection after a short delay (unless shutting down)
                        // Only reconnect if we have an address (active/both mode)
                        if session_mode != SessionMode::Passive {
                            let cmd_tx_clone = cmd_tx.clone();
                            let shutdown_rx_clone = shutdown_rx.clone();
                            let peer_addr_for_log = peer_addr_display.clone();
                            tokio::spawn(async move {
                                // Wait before attempting reconnection (avoids tight reconnect loop)
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                                // Skip reconnection if shutdown is in progress
                                if *shutdown_rx_clone.borrow() {
                                    debug!(peer = %peer_addr_for_log, "Skipping reconnect due to shutdown");
                                    return;
                                }

                                debug!(peer = %peer_addr_for_log, "Attempting to reconnect to peer...");
                                match cmd_tx_clone.send(SessionCommand::Start).await {
                                    Ok(()) => debug!(peer = %peer_addr_for_log, "Reconnect command sent"),
                                    Err(e) => error!(
                                        peer = %peer_addr_for_log,
                                        error = %e,
                                        "Failed to send reconnect command: {}", e
                                    ),
                                }
                            });
                        }
                    }
                    SessionEvent::UpdateReceived(data) => {
                        // Parse UPDATE and add routes to RIB
                        let routes = parse_update(&data);

                        // Log received routes
                        for route in &routes {
                            debug!(
                                peer_idx = peer_idx,
                                prefix = %route.prefix,
                                next_hop = %route.next_hop,
                                as_path = ?route.as_path,
                                "Route received: {} via {} AS_PATH {:?}",
                                route.prefix, route.next_hop, route.as_path
                            );
                        }

                        // Get the interface for this peer
                        let interface = {
                            let s = state.read().await;
                            s.neighbors
                                .get(peer_idx)
                                .map(|n| n.interface.clone())
                                .unwrap_or_default()
                        };

                        // Send routes to RibActor (no write lock needed)
                        rib_handle.add_routes(peer_idx, routes, interface).await;

                        // Update prefix count from RibActor
                        let count = rib_handle.get_peer_stats(peer_idx).await;
                        {
                            let mut s = state.write().await;
                            if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
                                neighbor.prefixes_received = count as u64;
                            }
                        }
                    }
                }

                // Update uptime
                if let Some(started) = established_at {
                    update_uptime(&state, peer_idx, started.elapsed().as_secs()).await;
                }
            }

            // Handle API route events (only process if established)
            route_event = route_events_rx.recv() => {
                // Only advertise if we're in Established state
                if !is_established {
                    continue;
                }

                let Ok(event) = route_event else {
                    // Channel lagged or closed, continue
                    continue;
                };

                // Only process events for API routes (LOCAL_PEER_IDX)
                match &event {
                    RouteEvent::Added(entry) if entry.peer_idx == LOCAL_PEER_IDX => {
                        // Get our link-local address for the interface
                        let local_link_local = match get_interface_link_local(&peer.interface) {
                            Ok(addr) => addr,
                            Err(e) => {
                                error!(
                                    interface = peer.interface,
                                    error = %e,
                                    "Failed to get link-local for API route advertisement"
                                );
                                continue;
                            }
                        };

                        if let Some(body) = announce_prefix(&entry.prefix.to_string(), local_asn, local_link_local) {
                            if let Err(e) = cmd_tx.send(SessionCommand::SendUpdate(body)).await {
                                error!(
                                    prefix = %entry.prefix,
                                    peer = %peer_addr_display,
                                    error = %e,
                                    "Failed to advertise API route"
                                );
                            } else {
                                debug!(
                                    prefix = %entry.prefix,
                                    peer = %peer_addr_display,
                                    "Advertised API route to peer"
                                );
                            }
                        }
                    }
                    RouteEvent::Withdrawn { prefix, peer_idx: withdrawn_peer_idx, .. } if *withdrawn_peer_idx == LOCAL_PEER_IDX => {
                        // TODO: Build and send withdrawal UPDATE
                        debug!(
                            prefix = %prefix,
                            peer = %peer_addr_display,
                            "API route withdrawal - withdrawal UPDATEs not yet implemented"
                        );
                    }
                    _ => {
                        // Not an API route event, ignore
                    }
                }
            }
        }
    }
}

/// Update peer state in shared daemon state.
pub async fn update_peer_state(
    state: &Arc<RwLock<DaemonState>>,
    peer_idx: usize,
    new_state: crate::bgp::SessionState,
) {
    let mut s = state.write().await;
    if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
        neighbor.state = new_state;
    }
}

/// Update peer ASN in shared daemon state.
pub async fn update_peer_asn(state: &Arc<RwLock<DaemonState>>, peer_idx: usize, asn: u32) {
    let mut s = state.write().await;
    if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
        neighbor.remote_asn = Some(asn);
    }
}

/// Update peer uptime in shared daemon state.
pub async fn update_uptime(state: &Arc<RwLock<DaemonState>>, peer_idx: usize, uptime_secs: u64) {
    let mut s = state.write().await;
    if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
        neighbor.uptime_secs = uptime_secs;
    }
}

/// Extract the IP address from a SocketAddr as a string (without port).
/// For IPv6 link-local addresses, includes the scope ID.
pub fn extract_ip_addr(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => v4.ip().to_string(),
        SocketAddr::V6(v6) => {
            let ip = v6.ip();
            if v6.scope_id() != 0 {
                // Link-local address with scope ID
                format!("{}%{}", ip, v6.scope_id())
            } else {
                ip.to_string()
            }
        }
    }
}
