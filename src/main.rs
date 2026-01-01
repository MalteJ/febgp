use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::sync::RwLock;
use tonic::transport::Server;

mod api;
mod bgp;
mod config;

use api::server::{DaemonState, FebgpServiceImpl};
use api::{default_grpc_addr, FebgpServiceServer, DEFAULT_GRPC_PORT};
use config::Config;

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
        #[arg(short, long)]
        config: String,

        /// gRPC listen port
        #[arg(long, default_value_t = DEFAULT_GRPC_PORT)]
        grpc_port: u16,
    },
    /// Show neighbor status
    Status {
        /// gRPC server address
        #[arg(short, long, default_value_t = default_grpc_addr())]
        address: String,
    },
    /// Show BGP routes
    Routes {
        /// gRPC server address
        #[arg(short, long, default_value_t = default_grpc_addr())]
        address: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { config, grpc_port } => run_daemon(&config, grpc_port),
        Commands::Status { address } => show_status(&address),
        Commands::Routes { address } => show_routes(&address),
    }
}

#[tokio::main]
async fn run_daemon_async(config: Config, grpc_port: u16) -> Result<(), Box<dyn std::error::Error>> {
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

    // TODO: Start BGP sessions for each peer
    // For now, just populate some state for testing
    {
        let mut s = state.write().await;
        for peer in &config.peers {
            s.neighbors.push(api::server::NeighborState {
                address: peer.address.clone().unwrap_or_default(),
                interface: peer.interface.clone(),
                remote_asn: peer.remote_asn,
                state: bgp::SessionState::Idle,
                uptime_secs: 0,
                prefixes_received: 0,
            });
        }
    }

    // Start gRPC server
    let addr = format!("0.0.0.0:{}", grpc_port).parse()?;
    let service = FebgpServiceImpl::new(state);

    println!("  gRPC server listening on {}", addr);

    Server::builder()
        .add_service(FebgpServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

fn run_daemon(config_path: &str, grpc_port: u16) -> ExitCode {
    let config = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = run_daemon_async(config, grpc_port) {
        eprintln!("Daemon error: {}", e);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[tokio::main]
async fn show_status_async(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = api::client::get_status(address).await?;

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

fn show_status(address: &str) -> ExitCode {
    if let Err(e) = show_status_async(address) {
        eprintln!("Failed to get status: {}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[tokio::main]
async fn show_routes_async(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let routes = api::client::get_routes(address).await?;

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

fn show_routes(address: &str) -> ExitCode {
    if let Err(e) = show_routes_async(address) {
        eprintln!("Failed to get routes: {}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
