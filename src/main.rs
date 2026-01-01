use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use febgp::api;
use febgp::api::server::{DaemonState, FebgpServiceImpl, NeighborState};
use febgp::{FebgpServiceServer, DEFAULT_CONFIG_PATH, DEFAULT_SOCKET_PATH};
use febgp::bgp::{self, build_ipv4_update, build_ipv6_update, parse_update, FsmConfig, FsmState, SessionActor, SessionCommand, SessionEvent, TcpTransport};
use febgp::config::{parse_peer_address, Config, PeerConfig};
use febgp::rib::{RibActor, RibCommand, RibHandle};

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
}

#[derive(Parser)]
#[command(name = "febgp")]
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
    println!("FeBGP starting...");
    println!("  ASN: {}", config.asn);
    println!("  Router ID: {}", config.router_id);
    println!("  Prefixes: {:?}", config.prefixes);
    println!("  Peers: {}", config.peers.len());
    println!("  Timers: hold={} keepalive={} connect_retry={}",
             config.hold_time, config.hold_time / 3, config.connect_retry_time);
    if install_routes {
        println!("  Route installation: enabled");
    }

    // Create RibActor with command channel
    let (rib_tx, rib_rx) = mpsc::channel::<RibCommand>(256);
    let rib_handle = RibHandle::new(rib_tx);

    let rib_actor = RibActor::new(rib_rx, install_routes)
        .map_err(|e| format!("Failed to create RibActor: {}", e))?;

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
    let mut session_senders: Vec<mpsc::Sender<SessionCommand>> = Vec::new();
    // Map from peer address (without port) to session command sender
    let peer_addr_to_sender: Arc<RwLock<HashMap<String, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Spawn BGP sessions for each peer
    for (peer_idx, peer) in config.peers.iter().enumerate() {
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
        };

        // Create command channel and keep sender for shutdown
        let (cmd_tx, cmd_rx) = mpsc::channel::<SessionCommand>(16);
        session_senders.push(cmd_tx.clone());

        // Register this peer's address for incoming connection routing
        if let Ok(peer_addr) = parse_peer_address(peer) {
            let addr_key = extract_ip_addr(&peer_addr);
            let mut map = peer_addr_to_sender.write().await;
            map.insert(addr_key, cmd_tx.clone());
        }

        tokio::spawn(async move {
            run_peer_session(ctx, cmd_tx, cmd_rx).await;
        });
    }

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
                        println!("Incoming BGP connection from {}", peer_addr);

                        let map = peer_map.read().await;
                        if let Some(sender) = map.get(&addr_key) {
                            if let Err(e) = sender.send(SessionCommand::IncomingConnection(stream)).await {
                                eprintln!("Failed to route incoming connection: {}", e);
                            }
                        } else {
                            println!("Dropping connection from unknown peer: {}", peer_addr);
                            // stream is dropped, closing the connection
                        }
                    }
                    Err(e) => {
                        eprintln!("Error accepting connection: {}", e);
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

    println!("  gRPC server listening on {}", socket_path);

    // Set up signal handlers for graceful shutdown
    let shutdown_senders = session_senders.clone();
    let shutdown_handle = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        println!("\nReceived shutdown signal, stopping BGP sessions...");

        // Send Stop command to all sessions
        for (idx, sender) in shutdown_senders.iter().enumerate() {
            if let Err(e) = sender.send(SessionCommand::Stop).await {
                eprintln!("Failed to send stop to session {}: {}", idx, e);
            }
        }

        // Give sessions time to send NOTIFICATION and close cleanly
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        println!("Shutdown complete");
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
    let config = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = run_daemon_async(config, socket_path, install_routes) {
        eprintln!("Daemon error: {}", e);
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
async fn run_peer_session(
    ctx: PeerSessionContext,
    cmd_tx: mpsc::Sender<SessionCommand>,
    cmd_rx: mpsc::Receiver<SessionCommand>,
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
    } = ctx;

    // Parse peer address
    let peer_addr = match parse_peer_address(&peer) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Failed to parse peer address for {}: {}", peer.interface, e);
            return;
        }
    };

    println!("Starting BGP session to {} via {}", peer_addr, peer.interface);

    // Create FSM configuration
    let fsm_config = FsmConfig {
        local_asn,
        router_id,
        hold_time,
        peer_asn: peer.remote_asn.unwrap_or(0), // 0 = accept any (BGP unnumbered)
        connect_retry_time: std::time::Duration::from_secs(connect_retry_time),
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
        eprintln!("Failed to start session for {}: {}", peer.interface, e);
        return;
    }

    let mut established_at: Option<Instant> = None;

    // Process events from the session actor
    while let Some(event) = event_rx.recv().await {
        match event {
            SessionEvent::StateChange { to, .. } => {
                update_peer_state(&state, peer_idx, to.into()).await;

                if to == FsmState::Established {
                    established_at = Some(Instant::now());
                    println!("Session established with {}", peer_addr);
                } else if to == FsmState::Idle {
                    established_at = None;
                }
            }
            SessionEvent::Established { peer_asn, peer_router_id, .. } => {
                // Update with learned ASN
                update_peer_asn(&state, peer_idx, peer_asn).await;
                println!(
                    "Peer {} (AS{}) router-id: {}",
                    peer_addr, peer_asn, peer_router_id
                );

                // Announce configured prefixes
                for prefix in &prefixes {
                    let update_body = if prefix.contains(':') {
                        // IPv6 prefix
                        build_ipv6_update(prefix, local_asn)
                    } else {
                        // IPv4 prefix
                        build_ipv4_update(prefix, local_asn)
                    };

                    if let Some(body) = update_body {
                        if let Err(e) = cmd_tx.send(SessionCommand::SendUpdate(body)).await {
                            eprintln!("Failed to send UPDATE for {}: {}", prefix, e);
                        } else {
                            println!("Announced prefix {} to {}", prefix, peer_addr);
                        }
                    } else {
                        eprintln!("Failed to build UPDATE for prefix: {}", prefix);
                    }
                }
            }
            SessionEvent::SessionDown { reason } => {
                println!("Session to {} went down: {}", peer_addr, reason);
                update_peer_state(&state, peer_idx, bgp::SessionState::Idle).await;

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
                    println!("Removed {} route(s) from peer {}", removed, peer_idx);
                }
                established_at = None;

                // Automatic reconnection after a short delay
                let cmd_tx_clone = cmd_tx.clone();
                tokio::spawn(async move {
                    // Wait before attempting reconnection (avoids tight reconnect loop)
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    println!("Attempting to reconnect to peer...");
                    match cmd_tx_clone.send(SessionCommand::Start).await {
                        Ok(()) => println!("Reconnect command sent to {}", peer_addr),
                        Err(e) => eprintln!("Failed to send reconnect command: {}", e),
                    }
                });
            }
            SessionEvent::UpdateReceived(data) => {
                // Parse UPDATE and add routes to RIB
                let routes = parse_update(&data);
                let route_count = routes.len();

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

                if route_count > 0 {
                    println!("Received {} route(s) from peer {}", route_count, peer_idx);
                }
            }
        }

        // Update uptime
        if let Some(started) = established_at {
            update_uptime(&state, peer_idx, started.elapsed().as_secs()).await;
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
