//! Integration test binary for connecting to a BGP peer.

use std::env;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::process::ExitCode;
use std::time::Duration;

use tokio::sync::mpsc;

use febgp::{FsmConfig, FsmState, SessionActor, SessionCommand, SessionEvent, TcpTransport};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() != 7 {
        eprintln!(
            "Usage: {} <local_asn> <router_id> <remote_asn> <peer_addr> <scope_id> <port>",
            args[0]
        );
        return ExitCode::FAILURE;
    }

    let local_asn: u32 = match args[1].parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid local_asn: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let router_id: Ipv4Addr = match args[2].parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid router_id: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let remote_asn: u32 = match args[3].parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid remote_asn: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let peer_addr: Ipv6Addr = match args[4].parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid peer_addr: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let scope_id: u32 = match args[5].parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid scope_id: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let port: u16 = match args[6].parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid port: {}", e);
            return ExitCode::FAILURE;
        }
    };

    println!(
        "Connecting to [{}%{}]:{} as AS{} (router-id: {})",
        peer_addr, scope_id, port, local_asn, router_id
    );

    // Create FSM configuration
    let fsm_config = FsmConfig {
        local_asn,
        router_id,
        hold_time: 90,
        peer_asn: remote_asn,
        connect_retry_time: Duration::from_secs(30),
    };

    // Create transport with link-local address
    let socket_addr = SocketAddrV6::new(peer_addr, port, 0, scope_id);
    let transport = TcpTransport::new(SocketAddr::V6(socket_addr));

    // Create channels
    let (cmd_tx, cmd_rx) = mpsc::channel::<SessionCommand>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<SessionEvent>(16);

    // Create and spawn the session actor
    let actor = SessionActor::new(fsm_config, transport, cmd_rx, event_tx);
    tokio::spawn(actor.run());

    // Send start command
    if let Err(e) = cmd_tx.send(SessionCommand::Start).await {
        eprintln!("Failed to start session: {}", e);
        return ExitCode::FAILURE;
    }

    // Wait for events with timeout
    let timeout = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(event) = event_rx.recv().await {
            match event {
                SessionEvent::StateChange { to, .. } => {
                    println!("State: {:?}", to);
                    if to == FsmState::Idle {
                        // Session failed and reset to Idle
                        return false;
                    }
                }
                SessionEvent::Established { peer_asn, peer_router_id, .. } => {
                    println!("ESTABLISHED with AS{} (router-id: {})", peer_asn, peer_router_id);
                    return true;
                }
                SessionEvent::SessionDown { reason } => {
                    eprintln!("Session down: {}", reason);
                    return false;
                }
                _ => {}
            }
        }
        false
    });

    match timeout.await {
        Ok(true) => {
            println!("Session established, holding for 3 seconds...");
            tokio::time::sleep(Duration::from_secs(3)).await;
            println!("Session held for 3 seconds, exiting");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("Session failed to establish");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("Timeout waiting for session establishment");
            ExitCode::FAILURE
        }
    }
}
