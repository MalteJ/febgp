use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use tracing::{debug, error, info, warn};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{mpsc, watch, RwLock};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use febgp::api;
use febgp::api::server::{DaemonState, FebgpServiceImpl, NeighborState};
use febgp::{FebgpServiceServer, DEFAULT_CONFIG_PATH, DEFAULT_SOCKET_PATH};
use febgp::bgp::{self, build_ipv4_update, build_ipv6_update, parse_update, FsmConfig, FsmState, SessionActor, SessionCommand, SessionEvent, TcpTransport};
use febgp::config::{parse_peer_address, Config, PeerConfig};
use febgp::neighbor_discovery::{get_interface_link_local, NeighborDiscovery, NeighborEvent};
use febgp::peer_manager::{PeerManager, PeerManagerConfig, PeerManagerHandle, PeerManagerCommand};
use febgp::rib::{RibActor, RibCommand, RibHandle, RouteEvent, LOCAL_PEER_IDX};

/// Context for running a peer session.
struct PeerSessionContext {
    peer_idx: usize,
    peer: PeerConfig,
    local_asn: u32,
    router_id: Ipv4Addr,
    state: Arc<RwLock<DaemonState>>,
    prefixes: Vec<String>,
    rib_handle: RibHandle,
    hold_time: u16,
    connect_retry_time: u64,
    ipv4_unicast: bool,
    ipv6_unicast: bool,
    shutdown_rx: watch::Receiver<bool>,
}

#[derive(Parser)]
#[command(name = "febgp")]
#[command(version)]
#[command(about = "FeBGP - A BGP daemon in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the BGP daemon
    Daemon {
        /// Path to config file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: String,

        /// gRPC socket path
        #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
        socket: String,

        /// Install routes into Linux routing table via netlink
        #[arg(long)]
        install_routes: bool,
    },
    /// Show neighbor status
    Status {
        /// gRPC socket path
        #[arg(short, long, default_value = DEFAULT_SOCKET_PATH)]
        socket: String,
    },
    /// Show BGP routes
    Routes {
        /// gRPC socket path
        #[arg(short, long, default_value = DEFAULT_SOCKET_PATH)]
        socket: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { config, socket, install_routes } => {
            run_daemon(&config, &socket, install_routes)
        }
        Commands::Status { socket } => show_status(&socket),
        Commands::Routes { socket } => show_routes(&socket),
    }
}

#[tokio::main]
async fn run_daemon_async(
    config: Config,
    socket_path: &str,
    install_routes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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
    // Map from peer address (without port) to session command sender
    let peer_addr_to_sender: Arc<RwLock<HashMap<String, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Channel for neighbor discovery events
    let (neighbor_tx, mut neighbor_rx) = mpsc::channel::<NeighborEvent>(32);

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
    // Maps interface name to (peer_idx, peer_config)
    let mut discovery_peers: HashMap<String, (usize, PeerConfig)> = HashMap::new();

    // Spawn BGP sessions for peers with explicit addresses,
    // start neighbor discovery for peers without addresses
    for (peer_idx, peer) in config.peers.iter().enumerate() {
        match parse_peer_address(peer) {
            Ok(Some(peer_addr)) => {
                // Explicit address - start session immediately
                let ctx = PeerSessionContext {
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
                peer_addr_to_sender.write().await.insert(addr_key, cmd_tx.clone());

                // Register with PeerManager
                peer_manager_handle.register_startup_peer(peer_idx, peer.clone(), cmd_tx.clone()).await;

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

    // Clone values needed for the neighbor handler task
    let neighbor_state = Arc::clone(&state);
    let neighbor_rib_handle = rib_handle.clone();
    let neighbor_session_senders = Arc::clone(&session_senders);
    let neighbor_peer_addr_to_sender = Arc::clone(&peer_addr_to_sender);
    let neighbor_peer_manager_handle = peer_manager_handle.clone();
    let neighbor_config_asn = config.asn;
    let neighbor_config_router_id = config.router_id;
    let neighbor_config_prefixes = config.prefixes.clone();
    let neighbor_config_hold_time = config.hold_time;
    let neighbor_config_connect_retry_time = config.connect_retry_time;
    let neighbor_config_ipv4_unicast = config.ipv4_unicast;
    let neighbor_config_ipv6_unicast = config.ipv6_unicast;
    let neighbor_shutdown_rx = shutdown_rx.clone();

    // Spawn task to handle discovered neighbors
    tokio::spawn(async move {
        while let Some(event) = neighbor_rx.recv().await {
            match event {
                NeighborEvent::Discovered { interface, interface_index, address } => {
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
                            let mut s = neighbor_state.write().await;
                            if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
                                neighbor.address = format!("{}%{}", address, interface);
                            }
                        }

                        let ctx = PeerSessionContext {
                            peer_idx,
                            peer,
                            local_asn: neighbor_config_asn,
                            router_id: neighbor_config_router_id,
                            state: Arc::clone(&neighbor_state),
                            prefixes: neighbor_config_prefixes.clone(),
                            rib_handle: neighbor_rib_handle.clone(),
                            hold_time: neighbor_config_hold_time,
                            connect_retry_time: neighbor_config_connect_retry_time,
                            ipv4_unicast: neighbor_config_ipv4_unicast,
                            ipv6_unicast: neighbor_config_ipv6_unicast,
                            shutdown_rx: neighbor_shutdown_rx.clone(),
                        };

                        // Create command channel
                        let (cmd_tx, cmd_rx) = mpsc::channel::<SessionCommand>(16);
                        neighbor_session_senders.write().await.push(cmd_tx.clone());

                        // Register for incoming connection routing
                        let addr_key = extract_ip_addr(&peer_addr);
                        neighbor_peer_addr_to_sender.write().await.insert(addr_key, cmd_tx.clone());

                        // Register with PeerManager
                        neighbor_peer_manager_handle.register_startup_peer(peer_idx, peer_for_pm, cmd_tx.clone()).await;

                        // Spawn the BGP session
                        tokio::spawn(async move {
                            run_peer_session(ctx, cmd_tx, cmd_rx, Some(peer_addr)).await;
                        });
                    }
                }
            }
        }
    });

    // Start TCP listener for incoming BGP connections (non-fatal if it fails)
    let bgp_listener = TcpListener::bind("[::]:179").await.ok();

    // Spawn incoming connection handler
    if let Some(listener) = bgp_listener {
        let peer_map = Arc::clone(&peer_addr_to_sender);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let addr_key = extract_ip_addr(&peer_addr);
                        debug!(peer = %peer_addr, "Incoming BGP connection from {}", peer_addr);

                        let map = peer_map.read().await;
                        if let Some(sender) = map.get(&addr_key) {
                            if let Err(e) = sender.send(SessionCommand::IncomingConnection(stream)).await {
                                error!(peer = %peer_addr, error = %e, "Failed to route incoming connection: {}", e);
                            }
                        } else {
                            warn!(peer = %peer_addr, "Dropping connection from unknown peer: {}", peer_addr);
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

    // Ensure parent directory exists
    if let Some(parent) = Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove old socket if it exists
    let _ = std::fs::remove_file(socket_path);

    // Create Unix socket listener
    let uds = UnixListener::bind(socket_path)?;
    let uds_stream = UnixListenerStream::new(uds);

    let service = FebgpServiceImpl::new(state);

    info!(socket = socket_path, "gRPC server listening on {}", socket_path);

    // Set up signal handlers for graceful shutdown
    let shutdown_senders = Arc::clone(&session_senders);
    let shutdown_rib_handle = rib_handle.clone();
    let shutdown_handle = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        info!("Received shutdown signal, stopping BGP sessions...");

        // Signal shutdown to all peer sessions (prevents reconnection attempts)
        let _ = shutdown_tx.send(true);

        // Send Stop command to all sessions
        let senders = shutdown_senders.read().await;
        for (idx, sender) in senders.iter().enumerate() {
            if let Err(e) = sender.send(SessionCommand::Stop).await {
                error!(session = idx, error = %e, "Failed to send stop to session {}: {}", idx, e);
            }
        }

        // Give sessions time to send NOTIFICATION and close cleanly
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Remove installed routes from kernel (if route installation was enabled)
        if install_routes {
            let removed = shutdown_rib_handle.remove_all_routes().await;
            if removed > 0 {
                info!(routes_removed = removed, "Cleaned up {} kernel route(s)", removed);
            }
        }

        info!("Shutdown complete");
    });

    // Run gRPC server with graceful shutdown
    Server::builder()
        .add_service(FebgpServiceServer::new(service))
        .serve_with_incoming_shutdown(uds_stream, async {
            shutdown_handle.await.ok();
        })
        .await?;

    Ok(())
}

fn run_daemon(config_path: &str, socket_path: &str, install_routes: bool) -> ExitCode {
    // Initialize tracing with RUST_LOG env filter (defaults to info if not set)
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    let config = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // CLI flag overrides config value (either one enables route installation)
    let install_routes = install_routes || config.install_routes;

    if let Err(e) = run_daemon_async(config, socket_path, install_routes) {
        error!("Daemon error: {}", e);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[tokio::main]
async fn show_status_async(socket_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = api::client::get_status(socket_path).await?;

    println!("FeBGP Status");
    println!("  ASN: {}", status.asn);
    println!("  Router ID: {}", status.router_id);
    println!();

    if status.neighbors.is_empty() {
        println!("No neighbors configured");
    } else {
        println!(
            "{:<40} {:>8} {:>12} {:>10} {:>10}",
            "Neighbor", "AS", "Interface", "State", "Prefixes"
        );
        println!("{}", "-".repeat(84));

        for n in &status.neighbors {
            let asn_str = if n.remote_asn == 0 {
                "?".to_string() // Not yet learned
            } else {
                n.remote_asn.to_string()
            };
            println!(
                "{:<40} {:>8} {:>12} {:>10} {:>10}",
                n.address, asn_str, n.interface, n.state, n.prefixes_received
            );
        }
    }

    Ok(())
}

fn show_status(socket_path: &str) -> ExitCode {
    if let Err(e) = show_status_async(socket_path) {
        eprintln!("Failed to get status: {}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[tokio::main]
async fn show_routes_async(socket_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let routes = api::client::get_routes(socket_path).await?;

    if routes.routes.is_empty() {
        println!("No routes in RIB");
    } else {
        println!(
            "{:<3} {:<40} {:<40} {:<20} {:<6}",
            "", "Prefix", "Next Hop", "AS Path", "Origin"
        );
        println!("{}", "-".repeat(112));

        // Sort routes by prefix for cleaner display
        let mut sorted_routes = routes.routes.clone();
        sorted_routes.sort_by(|a, b| a.prefix.cmp(&b.prefix));

        let mut last_prefix = String::new();
        for r in &sorted_routes {
            let best = if r.best { "*" } else { " " };
            // Show prefix only for first route, empty for ECMP paths
            let display_prefix = if r.prefix != last_prefix {
                last_prefix = r.prefix.clone();
                r.prefix.as_str()
            } else {
                "" // ECMP path - don't repeat prefix
            };
            println!(
                "{:<3} {:<40} {:<40} {:<20} {:<6}",
                best, display_prefix, r.next_hop, r.as_path, r.origin
            );
        }
    }

    Ok(())
}

fn show_routes(socket_path: &str) -> ExitCode {
    if let Err(e) = show_routes_async(socket_path) {
        eprintln!("Failed to get routes: {}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
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

/// Run a BGP session for a single peer.
///
/// Takes externally created channels to allow the caller to keep a reference
/// to the command sender for graceful shutdown.
///
/// The `peer_addr` parameter is optional - if None, it will be parsed from the
/// peer configuration. This allows sessions to be started either from explicit
/// config or from neighbor discovery.
async fn run_peer_session(
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

    // Get peer address - either passed in or parsed from config
    let peer_addr = match peer_addr {
        Some(addr) => addr,
        None => match parse_peer_address(&peer) {
            Ok(Some(addr)) => addr,
            Ok(None) => {
                error!(interface = peer.interface, "No peer address available for {}", peer.interface);
                return;
            }
            Err(e) => {
                error!(interface = peer.interface, error = %e, "Failed to parse peer address for {}: {}", peer.interface, e);
                return;
            }
        },
    };

    info!(peer = %peer_addr, interface = peer.interface, "Starting BGP session to {} via {}", peer_addr, peer.interface);

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

    // Create transport
    let transport = TcpTransport::new(peer_addr);

    // Create event channel
    let (event_tx, mut event_rx) = mpsc::channel::<SessionEvent>(16);

    // Create and spawn the session actor
    let actor = SessionActor::new(fsm_config, transport, cmd_rx, event_tx);
    tokio::spawn(actor.run());

    // Send start command
    if let Err(e) = cmd_tx.send(SessionCommand::Start).await {
        error!(interface = peer.interface, error = %e, "Failed to start session for {}: {}", peer.interface, e);
        return;
    }

    let mut established_at: Option<Instant> = None;
    let mut is_established = false;

    // Subscribe to route events for API route advertisements
    let mut route_events_rx = rib_handle.subscribe_updates();

    // Helper to announce a prefix to this peer
    let announce_prefix = |prefix: &str, local_asn: u32, local_link_local: std::net::Ipv6Addr| -> Option<Vec<u8>> {
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
                            info!(peer = %peer_addr, "Session established with {}", peer_addr);
                        } else if to == FsmState::Idle {
                            established_at = None;
                            is_established = false;
                        }
                    }
                    SessionEvent::Established { peer_asn, peer_router_id, .. } => {
                        // Update with learned ASN
                        update_peer_asn(&state, peer_idx, peer_asn).await;
                        info!(
                            peer = %peer_addr,
                            asn = peer_asn,
                            router_id = %peer_router_id,
                            "Peer {} (AS{}) router-id: {}",
                            peer_addr, peer_asn, peer_router_id
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
                                    error!(prefix = prefix, peer = %peer_addr, error = %e, "Failed to send UPDATE for {}: {}", prefix, e);
                                } else {
                                    debug!(prefix = prefix, peer = %peer_addr, "Announced prefix {} to {}", prefix, peer_addr);
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
                                    error!(prefix = %route.prefix, peer = %peer_addr, error = %e, "Failed to send API route UPDATE: {}", e);
                                } else {
                                    debug!(prefix = %route.prefix, peer = %peer_addr, "Announced API route {} to {}", route.prefix, peer_addr);
                                }
                            }
                        }
                    }
                    SessionEvent::SessionDown { reason } => {
                        warn!(peer = %peer_addr, reason = reason, "Session to {} went down: {}", peer_addr, reason);
                        update_peer_state(&state, peer_idx, bgp::SessionState::Idle).await;
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
                            info!(peer_idx = peer_idx, routes_removed = removed, "Removed {} route(s) from peer {}", removed, peer_idx);
                        }
                        established_at = None;

                        // Automatic reconnection after a short delay (unless shutting down)
                        let cmd_tx_clone = cmd_tx.clone();
                        let shutdown_rx_clone = shutdown_rx.clone();
                        tokio::spawn(async move {
                            // Wait before attempting reconnection (avoids tight reconnect loop)
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                            // Skip reconnection if shutdown is in progress
                            if *shutdown_rx_clone.borrow() {
                                debug!(peer = %peer_addr, "Skipping reconnect due to shutdown");
                                return;
                            }

                            debug!(peer = %peer_addr, "Attempting to reconnect to peer...");
                            match cmd_tx_clone.send(SessionCommand::Start).await {
                                Ok(()) => debug!(peer = %peer_addr, "Reconnect command sent to {}", peer_addr),
                                Err(e) => error!(peer = %peer_addr, error = %e, "Failed to send reconnect command: {}", e),
                            }
                        });
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
                                error!(interface = peer.interface, error = %e, "Failed to get link-local for API route advertisement");
                                continue;
                            }
                        };

                        if let Some(body) = announce_prefix(&entry.prefix, local_asn, local_link_local) {
                            if let Err(e) = cmd_tx.send(SessionCommand::SendUpdate(body)).await {
                                error!(prefix = %entry.prefix, peer = %peer_addr, error = %e, "Failed to advertise API route");
                            } else {
                                debug!(prefix = %entry.prefix, peer = %peer_addr, "Advertised API route to peer");
                            }
                        }
                    }
                    RouteEvent::Withdrawn { prefix, peer_idx: withdrawn_peer_idx, .. } if *withdrawn_peer_idx == LOCAL_PEER_IDX => {
                        // TODO: Build and send withdrawal UPDATE
                        debug!(prefix = %prefix, peer = %peer_addr, "API route withdrawal - withdrawal UPDATEs not yet implemented");
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
async fn update_peer_state(
    state: &Arc<RwLock<DaemonState>>,
    peer_idx: usize,
    new_state: bgp::SessionState,
) {
    let mut s = state.write().await;
    if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
        neighbor.state = new_state;
    }
}

/// Update peer ASN in shared daemon state.
async fn update_peer_asn(state: &Arc<RwLock<DaemonState>>, peer_idx: usize, asn: u32) {
    let mut s = state.write().await;
    if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
        neighbor.remote_asn = Some(asn);
    }
}

/// Update peer uptime in shared daemon state.
async fn update_uptime(state: &Arc<RwLock<DaemonState>>, peer_idx: usize, uptime_secs: u64) {
    let mut s = state.write().await;
    if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
        neighbor.uptime_secs = uptime_secs;
    }
}

/// Extract the IP address from a SocketAddr as a string (without port).
/// For IPv6 link-local addresses, includes the scope ID.
fn extract_ip_addr(addr: &SocketAddr) -> String {
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
