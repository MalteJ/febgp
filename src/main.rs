use std::net::{Ipv6Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

mod api;
mod bgp;
mod config;

use api::server::{DaemonState, FebgpServiceImpl, NeighborState};
use api::{FebgpServiceServer, DEFAULT_CONFIG_PATH, DEFAULT_SOCKET_PATH};
use bgp::{FsmConfig, FsmState, SessionActor, SessionCommand, SessionEvent, TcpTransport};
use config::{Config, PeerConfig};

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
        Commands::Daemon { config, socket } => run_daemon(&config, &socket),
        Commands::Status { socket } => show_status(&socket),
        Commands::Routes { socket } => show_routes(&socket),
    }
}

#[tokio::main]
async fn run_daemon_async(
    config: Config,
    socket_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("FeBGP starting...");
    println!("  ASN: {}", config.asn);
    println!("  Router ID: {}", config.router_id);
    println!("  Prefixes: {:?}", config.prefixes);
    println!("  Peers: {}", config.peers.len());

    // Create shared state
    let state = Arc::new(RwLock::new(DaemonState::new(
        config.asn,
        config.router_id.to_string(),
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

    // Spawn BGP sessions for each peer
    for (peer_idx, peer) in config.peers.iter().enumerate() {
        let state_clone = Arc::clone(&state);
        let local_asn = config.asn;
        let router_id = config.router_id;
        let peer_config = peer.clone();

        tokio::spawn(async move {
            run_peer_session(peer_idx, peer_config, local_asn, router_id, state_clone).await;
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

    Server::builder()
        .add_service(FebgpServiceServer::new(service))
        .serve_with_incoming(uds_stream)
        .await?;

    Ok(())
}

fn run_daemon(config_path: &str, socket_path: &str) -> ExitCode {
    let config = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = run_daemon_async(config, socket_path) {
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

        for r in &routes.routes {
            let best = if r.best { "*" } else { "" };
            println!(
                "{:<3} {:<40} {:<40} {:<20} {:<6}",
                best, r.prefix, r.next_hop, r.as_path, r.origin
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

/// Run a BGP session for a single peer.
async fn run_peer_session(
    peer_idx: usize,
    peer: PeerConfig,
    local_asn: u32,
    router_id: std::net::Ipv4Addr,
    state: Arc<RwLock<DaemonState>>,
) {
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
        hold_time: 90,
        peer_asn: peer.remote_asn.unwrap_or(0), // 0 = accept any (BGP unnumbered)
        connect_retry_time: std::time::Duration::from_secs(30),
    };

    // Create transport
    let transport = TcpTransport::new(peer_addr);

    // Create channels for commands and events
    let (cmd_tx, cmd_rx) = mpsc::channel::<SessionCommand>(16);
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
            }
            SessionEvent::SessionDown { reason } => {
                println!("Session to {} went down: {}", peer_addr, reason);
                update_peer_state(&state, peer_idx, bgp::SessionState::Idle).await;
                established_at = None;
            }
            SessionEvent::UpdateReceived { .. } => {
                // TODO: Process UPDATE messages and update RIB
                increment_prefixes_received(&state, peer_idx).await;
            }
        }

        // Update uptime
        if let Some(started) = established_at {
            update_uptime(&state, peer_idx, started.elapsed().as_secs()).await;
        }
    }
}

/// Parse peer address from configuration.
fn parse_peer_address(peer: &PeerConfig) -> Result<SocketAddr, String> {
    const BGP_PORT: u16 = 179;

    if let Some(addr_str) = &peer.address {
        // Explicit address provided
        if let Ok(addr) = addr_str.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(addr, BGP_PORT));
        }

        // Try parsing as IPv6 with scope ID (fe80::1%eth0 format)
        if let Some((ip_part, scope_part)) = addr_str.split_once('%') {
            let ip: Ipv6Addr = ip_part
                .parse()
                .map_err(|e| format!("Invalid IPv6 address: {}", e))?;
            let scope_id = get_interface_index(scope_part)
                .ok_or_else(|| format!("Unknown interface: {}", scope_part))?;
            return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip, BGP_PORT, 0, scope_id,
            )));
        }

        return Err(format!("Invalid address format: {}", addr_str));
    }

    // No address specified - for now, require explicit address
    // TODO: Implement neighbor discovery for link-local peering
    Err("No peer address specified and neighbor discovery not yet implemented".to_string())
}

/// Get interface index by name.
fn get_interface_index(name: &str) -> Option<u32> {
    nix::net::if_::if_nametoindex(name).ok()
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

/// Increment prefixes received counter.
async fn increment_prefixes_received(state: &Arc<RwLock<DaemonState>>, peer_idx: usize) {
    let mut s = state.write().await;
    if let Some(neighbor) = s.neighbors.get_mut(peer_idx) {
        neighbor.prefixes_received += 1;
    }
}
