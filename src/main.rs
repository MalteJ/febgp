use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::{error, info};

use febgp::api;
use febgp::api::server::FebgpServiceImpl;
use febgp::config::Config;
use febgp::daemon::startup::{
    init_daemon_components, spawn_bgp_listener, spawn_neighbor_handler, spawn_shutdown_handler,
};
use febgp::{FebgpServiceServer, DEFAULT_CONFIG_PATH, DEFAULT_SOCKET_PATH};

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
    // Initialize all daemon components
    let components = init_daemon_components(config, install_routes).await?;

    // Spawn neighbor discovery handler
    spawn_neighbor_handler(
        components.ctx.clone(),
        components.neighbor_rx,
        components.discovery_peers,
    );

    // Spawn incoming BGP connection listener
    spawn_bgp_listener(components.ctx.clone()).await;

    // Ensure parent directory exists
    if let Some(parent) = Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove old socket if it exists
    let _ = std::fs::remove_file(socket_path);

    // Create Unix socket listener
    let uds = UnixListener::bind(socket_path)?;
    let uds_stream = UnixListenerStream::new(uds);

    let service = FebgpServiceImpl::new(components.ctx.state.clone());

    info!(socket = socket_path, "gRPC server listening on {}", socket_path);

    // Spawn shutdown handler
    let shutdown_handle =
        spawn_shutdown_handler(components.ctx, components.shutdown_tx, install_routes);

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
            let as_path_str = r
                .as_path
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "{:<3} {:<40} {:<40} {:<20} {:<6}",
                best, display_prefix, r.next_hop, as_path_str, r.origin
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

