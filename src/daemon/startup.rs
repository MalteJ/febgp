//! Daemon startup and initialization logic.
//!
//! Contains helper functions for initializing daemon components and spawning tasks.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, RwLock};
use tracing::{debug, error, info, warn};

use crate::api::server::{DaemonState, NeighborState};
use crate::bgp::{self, SessionCommand};
use crate::config::{parse_peer_address, Config, PeerConfig};
use crate::neighbor_discovery::{NeighborDiscovery, NeighborEvent};
use crate::peer_manager::{PeerManager, PeerManagerConfig, PeerManagerHandle};
use crate::rib::{RibActor, RibCommand, RibHandle};
use crate::PeerManagerCommand;

use super::{extract_ip_addr, run_peer_session, DaemonContext};

/// Components initialized during daemon startup.
pub struct DaemonComponents {
    pub ctx: DaemonContext,
    pub shutdown_tx: watch::Sender<bool>,
    pub neighbor_rx: mpsc::Receiver<NeighborEvent>,
    pub discovery_peers: HashMap<String, (usize, PeerConfig)>,
}

/// Initialize core daemon components.
///
/// Creates the RIB actor, shared state, channels, and PeerManager.
pub async fn init_daemon_components(
    config: Config,
    install_routes: bool,
) -> Result<DaemonComponents, Box<dyn std::error::Error>> {
    // Log configuration
    info!("FeBGP starting...");
    info!(asn = config.asn, "ASN: {}", config.asn);
    info!(router_id = %config.router_id, "Router ID: {}", config.router_id);
    info!(prefixes = ?config.prefixes, "Prefixes: {:?}", config.prefixes);
    info!(peers = config.peers.len(), "Peers: {}", config.peers.len());
    info!(
        hold_time = config.hold_time,
        keepalive = config.hold_time / 3,
        connect_retry = config.connect_retry_time,
        "Timers: hold={} keepalive={} connect_retry={}",
        config.hold_time, config.hold_time / 3, config.connect_retry_time
    );
    if install_routes {
        info!("Route installation: enabled");
    }

    // Create RibActor with command channel
    let (rib_tx, rib_rx) = mpsc::channel::<RibCommand>(256);
    let (rib_actor, route_event_tx) = RibActor::new(rib_rx, install_routes)
        .map_err(|e| format!("Failed to create RibActor: {}", e))?;
    let rib_handle = RibHandle::new(rib_tx, route_event_tx);

    tokio::spawn(async move {
        rib_actor.run().await;
    });

    // Create shared state
    let state = Arc::new(RwLock::new(DaemonState::new(
        config.asn,
        config.router_id.to_string(),
        rib_handle.clone(),
    )));

    // Initialize neighbor states
    {
        let mut s = state.write().await;
        for peer in &config.peers {
            s.neighbors.push(NeighborState {
                address: peer.address.clone().unwrap_or_default(),
                interface: peer.interface.clone(),
                remote_asn: peer.remote_asn,
                state: bgp::SessionState::Idle,
                uptime_secs: 0,
                prefixes_received: 0,
            });
        }
    }

    // Track command senders for graceful shutdown and incoming connection routing
    let session_senders: Arc<RwLock<Vec<mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(Vec::new()));
    let peer_addr_to_sender: Arc<RwLock<HashMap<String, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Channel for neighbor discovery events
    let (neighbor_tx, neighbor_rx) = mpsc::channel::<NeighborEvent>(32);

    // Shutdown signal - broadcast to all peer sessions
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Create PeerManager for dynamic peer management
    let (pm_tx, pm_rx) = mpsc::channel::<PeerManagerCommand>(32);
    let peer_manager_handle = PeerManagerHandle::new(pm_tx);
    let peer_manager = PeerManager::new(
        pm_rx,
        PeerManagerConfig {
            state: Arc::clone(&state),
            rib_handle: rib_handle.clone(),
            shutdown_rx: shutdown_rx.clone(),
            local_asn: config.asn,
            router_id: config.router_id,
            prefixes: config.prefixes.clone(),
            hold_time: config.hold_time,
            connect_retry_time: config.connect_retry_time,
            ipv4_unicast: config.ipv4_unicast,
            ipv6_unicast: config.ipv6_unicast,
            initial_peer_count: config.peers.len(),
        },
    );

    // Set PeerManager handle on DaemonState
    {
        let mut s = state.write().await;
        s.set_peer_manager(peer_manager_handle.clone());
    }

    // Spawn PeerManager task
    tokio::spawn(async move {
        peer_manager.run().await;
    });

    // Store peer configs for interfaces awaiting neighbor discovery
    let mut discovery_peers: HashMap<String, (usize, PeerConfig)> = HashMap::new();

    // Wrap config in Arc for sharing
    let config = Arc::new(config);

    // Spawn BGP sessions for peers with explicit addresses,
    // start neighbor discovery for peers without addresses
    for (peer_idx, peer) in config.peers.iter().enumerate() {
        match parse_peer_address(peer) {
            Ok(Some(peer_addr)) => {
                // Explicit address - start session immediately
                let ctx = super::PeerSessionContext {
                    peer_idx,
                    peer: peer.clone(),
                    local_asn: config.asn,
                    router_id: config.router_id,
                    state: Arc::clone(&state),
                    prefixes: config.prefixes.clone(),
                    rib_handle: rib_handle.clone(),
                    hold_time: config.hold_time,
                    connect_retry_time: config.connect_retry_time,
                    ipv4_unicast: config.ipv4_unicast,
                    ipv6_unicast: config.ipv6_unicast,
                    shutdown_rx: shutdown_rx.clone(),
                };

                // Create command channel and keep sender for shutdown
                let (cmd_tx, cmd_rx) = mpsc::channel::<SessionCommand>(16);
                session_senders.write().await.push(cmd_tx.clone());

                // Register this peer's address for incoming connection routing
                let addr_key = extract_ip_addr(&peer_addr);
                peer_addr_to_sender
                    .write()
                    .await
                    .insert(addr_key, cmd_tx.clone());

                // Register with PeerManager
                peer_manager_handle
                    .register_startup_peer(peer_idx, peer.clone(), cmd_tx.clone())
                    .await;

                tokio::spawn(async move {
                    run_peer_session(ctx, cmd_tx, cmd_rx, Some(peer_addr)).await;
                });
            }
            Ok(None) => {
                // No address - use neighbor discovery
                info!(
                    interface = peer.interface,
                    "Starting neighbor discovery on {}",
                    peer.interface
                );

                // Store peer config for when neighbor is discovered
                discovery_peers.insert(peer.interface.clone(), (peer_idx, peer.clone()));

                // Start neighbor discovery for this interface
                match NeighborDiscovery::new(&peer.interface, neighbor_tx.clone()) {
                    Ok(nd) => {
                        tokio::spawn(nd.run());
                    }
                    Err(e) => {
                        error!(
                            interface = peer.interface,
                            error = %e,
                            "Failed to start neighbor discovery on {}: {}",
                            peer.interface,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    interface = peer.interface,
                    error = %e,
                    "Invalid peer configuration for {}: {}",
                    peer.interface,
                    e
                );
            }
        }
    }

    let ctx = DaemonContext {
        state,
        rib_handle,
        session_senders,
        peer_addr_to_sender,
        peer_manager_handle,
        config,
        shutdown_rx,
    };

    Ok(DaemonComponents {
        ctx,
        shutdown_tx,
        neighbor_rx,
        discovery_peers,
    })
}

/// Spawn the neighbor discovery event handler task.
pub fn spawn_neighbor_handler(
    ctx: DaemonContext,
    mut neighbor_rx: mpsc::Receiver<NeighborEvent>,
    discovery_peers: HashMap<String, (usize, PeerConfig)>,
) {
    tokio::spawn(async move {
        while let Some(event) = neighbor_rx.recv().await {
            match event {
                NeighborEvent::Discovered {
                    interface,
                    interface_index,
                    address,
                } => {
                    info!(
                        interface = interface,
                        neighbor = %address,
                        "Neighbor discovered: {} on {}",
                        address,
                        interface
                    );

                    // Find the peer config for this interface
                    if let Some((peer_idx, peer)) = discovery_peers.get(&interface) {
                        let peer_idx = *peer_idx;
                        let peer = peer.clone();
                        let peer_for_pm = peer.clone();

                        // Create peer address with scope ID
                        let peer_addr = SocketAddr::V6(std::net::SocketAddrV6::new(
                            address,
                            179, // BGP port
                            0,
                            interface_index,
                        ));

                        // Update neighbor state with discovered address
                        {
                            let mut s = ctx.state.write().await;
                            if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
                                neighbor.address = format!("{}%{}", address, interface);
                            }
                        }

                        let session_ctx = ctx.peer_session_context(peer_idx, peer);

                        // Create command channel
                        let (cmd_tx, cmd_rx) = mpsc::channel::<SessionCommand>(16);
                        ctx.session_senders.write().await.push(cmd_tx.clone());

                        // Register for incoming connection routing
                        let addr_key = extract_ip_addr(&peer_addr);
                        ctx.peer_addr_to_sender
                            .write()
                            .await
                            .insert(addr_key, cmd_tx.clone());

                        // Register with PeerManager
                        ctx.peer_manager_handle
                            .register_startup_peer(peer_idx, peer_for_pm, cmd_tx.clone())
                            .await;

                        // Spawn the BGP session
                        tokio::spawn(async move {
                            run_peer_session(session_ctx, cmd_tx, cmd_rx, Some(peer_addr)).await;
                        });
                    }
                }
            }
        }
    });
}

/// Spawn the incoming BGP connection listener.
pub async fn spawn_bgp_listener(ctx: DaemonContext) {
    // Start TCP listener for incoming BGP connections (non-fatal if it fails)
    let bgp_listener = TcpListener::bind("[::]:179").await.ok();

    if let Some(listener) = bgp_listener {
        let peer_map = Arc::clone(&ctx.peer_addr_to_sender);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let addr_key = extract_ip_addr(&peer_addr);
                        debug!(peer = %peer_addr, "Incoming BGP connection from {}", peer_addr);

                        let map = peer_map.read().await;
                        if let Some(sender) = map.get(&addr_key) {
                            if let Err(e) =
                                sender.send(SessionCommand::IncomingConnection(stream)).await
                            {
                                error!(
                                    peer = %peer_addr,
                                    error = %e,
                                    "Failed to route incoming connection: {}", e
                                );
                            }
                        } else {
                            warn!(
                                peer = %peer_addr,
                                "Dropping connection from unknown peer: {}", peer_addr
                            );
                            // stream is dropped, closing the connection
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Error accepting connection: {}", e);
                    }
                }
            }
        });
    }
}

/// Spawn the shutdown handler task.
pub fn spawn_shutdown_handler(
    ctx: DaemonContext,
    shutdown_tx: watch::Sender<bool>,
    install_routes: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        info!("Received shutdown signal, stopping BGP sessions...");

        // Signal shutdown to all peer sessions (prevents reconnection attempts)
        let _ = shutdown_tx.send(true);

        // Send Stop command to all sessions
        let senders = ctx.session_senders.read().await;
        for (idx, sender) in senders.iter().enumerate() {
            if let Err(e) = sender.send(SessionCommand::Stop).await {
                error!(
                    session = idx,
                    error = %e,
                    "Failed to send stop to session {}: {}", idx, e
                );
            }
        }

        // Give sessions time to send NOTIFICATION and close cleanly
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Remove installed routes from kernel (if route installation was enabled)
        if install_routes {
            let removed = ctx.rib_handle.remove_all_routes().await;
            if removed > 0 {
                info!(
                    routes_removed = removed,
                    "Cleaned up {} kernel route(s)", removed
                );
            }
        }

        info!("Shutdown complete");
    })
}

/// Wait for shutdown signal (SIGTERM or SIGINT/Ctrl+C).
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {},
    }
}
