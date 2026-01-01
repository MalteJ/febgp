use std::env;
use std::net::Ipv4Addr;
use std::process::ExitCode;

use febgp::Session;

fn main() -> ExitCode {
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

    let peer_addr: std::net::Ipv6Addr = match args[4].parse() {
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

    let mut session = Session::new(local_asn, router_id, remote_asn);

    match session.connect_link_local(peer_addr, scope_id, port) {
        Ok(()) => {
            println!("Session state: {:?}", session.state);
            if session.is_established() {
                println!("ESTABLISHED");
                // Keep session alive for a few seconds so GoBGP can verify
                std::thread::sleep(std::time::Duration::from_secs(3));
                println!("Session held for 3 seconds, exiting");
                ExitCode::SUCCESS
            } else {
                println!("NOT ESTABLISHED");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("Connection failed: {}", e);
            ExitCode::FAILURE
        }
    }
}
