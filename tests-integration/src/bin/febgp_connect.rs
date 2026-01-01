//! Integration test binary for connecting to a BGP peer.
//!
//! Usage: febgp-connect <local_asn> <router_id> <remote_asn> <peer_addr> <scope_id> <port> [options]
//!
//! Options:
//!   --announce-v4 <prefix>   Announce an IPv4 prefix (e.g., "10.0.0.0/24")
//!   --announce-v6 <prefix>   Announce an IPv6 prefix (e.g., "2001:db8::/32")
//!   --wait <seconds>         Wait time after establishment (default: 3)

use std::env;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::process::ExitCode;
use std::time::Duration;

use tokio::sync::mpsc;

use febgp::{FsmConfig, FsmState, SessionActor, SessionCommand, SessionEvent, TcpTransport};

/// Parsed command line arguments
struct Args {
    local_asn: u32,
    router_id: Ipv4Addr,
    remote_asn: u32,
    peer_addr: Ipv6Addr,
    scope_id: u32,
    port: u16,
    announce_v4: Vec<String>,
    announce_v6: Vec<String>,
    wait_seconds: u64,
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 7 {
        return Err(format!(
            "Usage: {} <local_asn> <router_id> <remote_asn> <peer_addr> <scope_id> <port> [options]",
            args[0]
        ));
    }

    let local_asn: u32 = args[1].parse().map_err(|e| format!("Invalid local_asn: {}", e))?;
    let router_id: Ipv4Addr = args[2].parse().map_err(|e| format!("Invalid router_id: {}", e))?;
    let remote_asn: u32 = args[3].parse().map_err(|e| format!("Invalid remote_asn: {}", e))?;
    let peer_addr: Ipv6Addr = args[4].parse().map_err(|e| format!("Invalid peer_addr: {}", e))?;
    let scope_id: u32 = args[5].parse().map_err(|e| format!("Invalid scope_id: {}", e))?;
    let port: u16 = args[6].parse().map_err(|e| format!("Invalid port: {}", e))?;

    let mut announce_v4 = Vec::new();
    let mut announce_v6 = Vec::new();
    let mut wait_seconds = 3u64;

    let mut i = 7;
    while i < args.len() {
        match args[i].as_str() {
            "--announce-v4" => {
                i += 1;
                if i >= args.len() {
                    return Err("--announce-v4 requires a prefix".to_string());
                }
                announce_v4.push(args[i].clone());
            }
            "--announce-v6" => {
                i += 1;
                if i >= args.len() {
                    return Err("--announce-v6 requires a prefix".to_string());
                }
                announce_v6.push(args[i].clone());
            }
            "--wait" => {
                i += 1;
                if i >= args.len() {
                    return Err("--wait requires a number".to_string());
                }
                wait_seconds = args[i].parse().map_err(|e| format!("Invalid wait time: {}", e))?;
            }
            other => {
                return Err(format!("Unknown option: {}", other));
            }
        }
        i += 1;
    }

    Ok(Args {
        local_asn,
        router_id,
        remote_asn,
        peer_addr,
        scope_id,
        port,
        announce_v4,
        announce_v6,
        wait_seconds,
    })
}

/// Parse an IPv4 prefix from a BGP UPDATE NLRI section
fn parse_ipv4_nlri(data: &[u8]) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let prefix_len = data[pos] as usize;
        pos += 1;

        let bytes_needed = prefix_len.div_ceil(8);
        if pos + bytes_needed > data.len() {
            break;
        }

        let mut octets = [0u8; 4];
        for (i, byte) in data[pos..pos + bytes_needed].iter().enumerate() {
            octets[i] = *byte;
        }
        pos += bytes_needed;

        let addr = Ipv4Addr::from(octets);
        prefixes.push(format!("{}/{}", addr, prefix_len));
    }

    prefixes
}

/// Parse an IPv6 prefix from MP_REACH_NLRI
fn parse_ipv6_nlri(data: &[u8]) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        if pos >= data.len() {
            break;
        }
        let prefix_len = data[pos] as usize;
        pos += 1;

        let bytes_needed = prefix_len.div_ceil(8);
        if pos + bytes_needed > data.len() {
            break;
        }

        let mut octets = [0u8; 16];
        for (i, byte) in data[pos..pos + bytes_needed].iter().enumerate() {
            octets[i] = *byte;
        }
        pos += bytes_needed;

        let addr = Ipv6Addr::from(octets);
        prefixes.push(format!("{}/{}", addr, prefix_len));
    }

    prefixes
}

/// Parse a BGP UPDATE message and extract announced prefixes
fn parse_update(data: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut ipv4_prefixes = Vec::new();
    let mut ipv6_prefixes = Vec::new();

    if data.len() < 4 {
        return (ipv4_prefixes, ipv6_prefixes);
    }

    // Withdrawn Routes Length
    let withdrawn_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2 + withdrawn_len;

    if pos + 2 > data.len() {
        return (ipv4_prefixes, ipv6_prefixes);
    }

    // Total Path Attribute Length
    let path_attr_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let path_attr_end = pos + path_attr_len;

    // Parse path attributes for MP_REACH_NLRI (type 14)
    while pos < path_attr_end && pos < data.len() {
        if pos + 2 > data.len() {
            break;
        }

        let flags = data[pos];
        let attr_type = data[pos + 1];
        pos += 2;

        let extended = (flags & 0x10) != 0;
        let attr_len = if extended {
            if pos + 2 > data.len() {
                break;
            }
            let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            len
        } else {
            if pos >= data.len() {
                break;
            }
            let len = data[pos] as usize;
            pos += 1;
            len
        };

        if pos + attr_len > data.len() {
            break;
        }

        // MP_REACH_NLRI (type 14)
        if attr_type == 14 && attr_len >= 5 {
            let attr_data = &data[pos..pos + attr_len];
            let afi = u16::from_be_bytes([attr_data[0], attr_data[1]]);
            let safi = attr_data[2];
            let next_hop_len = attr_data[3] as usize;

            if 4 + next_hop_len < attr_len {
                // Skip next hop and reserved byte
                let nlri_start = 4 + next_hop_len + 1;
                let nlri_data = &attr_data[nlri_start..];

                if afi == 1 && safi == 1 {
                    // IPv4 unicast via MP_REACH_NLRI
                    ipv4_prefixes.extend(parse_ipv4_nlri(nlri_data));
                } else if afi == 2 && safi == 1 {
                    // IPv6 unicast
                    ipv6_prefixes.extend(parse_ipv6_nlri(nlri_data));
                }
            }
        }

        pos += attr_len;
    }

    // Parse IPv4 NLRI (remaining bytes after path attributes)
    if path_attr_end < data.len() {
        let nlri_data = &data[path_attr_end..];
        ipv4_prefixes.extend(parse_ipv4_nlri(nlri_data));
    }

    (ipv4_prefixes, ipv6_prefixes)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::FAILURE;
        }
    };

    println!(
        "Connecting to [{}%{}]:{} as AS{} (router-id: {})",
        args.peer_addr, args.scope_id, args.port, args.local_asn, args.router_id
    );

    if !args.announce_v4.is_empty() {
        println!("Will announce IPv4: {:?}", args.announce_v4);
    }
    if !args.announce_v6.is_empty() {
        println!("Will announce IPv6: {:?}", args.announce_v6);
    }

    // Create FSM configuration
    let fsm_config = FsmConfig {
        local_asn: args.local_asn,
        router_id: args.router_id,
        hold_time: 90,
        peer_asn: args.remote_asn,
        connect_retry_time: Duration::from_secs(30),
        ipv4_unicast: true,
        ipv6_unicast: true,
    };

    // Create transport with link-local address
    let socket_addr = SocketAddrV6::new(args.peer_addr, args.port, 0, args.scope_id);
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

    // Track received prefixes
    let mut received_v4: Vec<String> = Vec::new();
    let mut received_v6: Vec<String> = Vec::new();

    // Wait for establishment with timeout
    let establish_timeout = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(event) = event_rx.recv().await {
            match event {
                SessionEvent::StateChange { to, .. } => {
                    println!("State: {:?}", to);
                    if to == FsmState::Idle {
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

    let established = match establish_timeout.await {
        Ok(true) => true,
        Ok(false) => {
            eprintln!("Session failed to establish");
            return ExitCode::FAILURE;
        }
        Err(_) => {
            eprintln!("Timeout waiting for session establishment");
            return ExitCode::FAILURE;
        }
    };

    if !established {
        return ExitCode::FAILURE;
    }

    // Send UPDATE messages if we have routes to announce
    if !args.announce_v4.is_empty() || !args.announce_v6.is_empty() {
        for prefix in &args.announce_v4 {
            if let Some(update) = build_ipv4_update(prefix, args.local_asn) {
                if let Err(e) = cmd_tx.send(SessionCommand::SendUpdate(update)).await {
                    eprintln!("Failed to send IPv4 UPDATE: {}", e);
                }
                println!("SENT_UPDATE_V4: {}", prefix);
            }
        }
        for prefix in &args.announce_v6 {
            if let Some(update) = build_ipv6_update(prefix, args.local_asn, args.router_id) {
                if let Err(e) = cmd_tx.send(SessionCommand::SendUpdate(update)).await {
                    eprintln!("Failed to send IPv6 UPDATE: {}", e);
                }
                println!("SENT_UPDATE_V6: {}", prefix);
            }
        }
    }

    // Wait for updates and hold session
    println!("Session established, waiting for {} seconds...", args.wait_seconds);
    let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(args.wait_seconds);

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(wait_deadline) => {
                break;
            }
            Some(event) = event_rx.recv() => {
                match event {
                    SessionEvent::UpdateReceived(data) => {
                        let (v4, v6) = parse_update(&data);
                        for prefix in v4 {
                            println!("RECEIVED_V4: {}", prefix);
                            received_v4.push(prefix);
                        }
                        for prefix in v6 {
                            println!("RECEIVED_V6: {}", prefix);
                            received_v6.push(prefix);
                        }
                    }
                    SessionEvent::SessionDown { reason } => {
                        eprintln!("Session down during wait: {}", reason);
                        return ExitCode::FAILURE;
                    }
                    _ => {}
                }
            }
        }
    }

    println!("Session held for {} seconds, exiting", args.wait_seconds);
    println!("Total received - IPv4: {}, IPv6: {}", received_v4.len(), received_v6.len());

    ExitCode::SUCCESS
}

/// Build a BGP UPDATE message for an IPv4 prefix using MP_REACH_NLRI
/// (This is more compatible when the session uses link-local addresses)
fn build_ipv4_update(prefix_str: &str, local_asn: u32) -> Option<Vec<u8>> {
    let parts: Vec<&str> = prefix_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    let mut update = Vec::new();

    // Withdrawn Routes Length (0)
    update.extend_from_slice(&0u16.to_be_bytes());

    // Build path attributes
    #[rustfmt::skip]
    let mut path_attrs = vec![
        // ORIGIN (type 1) - IGP
        0x40, // Transitive
        1,    // ORIGIN
        1,    // Length
        0,    // IGP
        // AS_PATH (type 2) - AS_SEQUENCE with our ASN
        0x40, // Transitive
        2,    // AS_PATH
        6,    // Length (1 + 1 + 4)
        2,    // AS_SEQUENCE
        1,    // 1 ASN
    ];
    path_attrs.extend_from_slice(&local_asn.to_be_bytes());

    // MP_REACH_NLRI (type 14) for IPv4
    // Using MP_REACH_NLRI is more compatible when using link-local sessions
    let mut mp_reach = Vec::new();
    mp_reach.extend_from_slice(&1u16.to_be_bytes()); // AFI = 1 (IPv4)
    mp_reach.push(1); // SAFI = 1 (unicast)

    // Next hop - 4 bytes for IPv4
    mp_reach.push(4); // Next hop length
    // Use a placeholder next-hop (10.0.0.1) - GoBGP should rewrite this
    mp_reach.extend_from_slice(&[10, 0, 0, 1]);

    mp_reach.push(0); // Reserved

    // NLRI
    mp_reach.push(prefix_len);
    let bytes_needed = prefix_len.div_ceil(8) as usize;
    mp_reach.extend_from_slice(&addr.octets()[..bytes_needed]);

    // MP_REACH_NLRI attribute (optional, non-transitive per RFC 4760)
    // Use extended length if needed
    if mp_reach.len() > 255 {
        path_attrs.push(0x90); // Optional, Extended Length
        path_attrs.push(14);   // MP_REACH_NLRI
        path_attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    } else {
        path_attrs.push(0x80); // Optional
        path_attrs.push(14);   // MP_REACH_NLRI
        path_attrs.push(mp_reach.len() as u8);
    }
    path_attrs.extend_from_slice(&mp_reach);

    // Total Path Attribute Length
    update.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
    update.extend_from_slice(&path_attrs);

    // No traditional NLRI - using MP_REACH_NLRI instead

    Some(update)
}

/// Build a BGP UPDATE message for an IPv6 prefix using MP_REACH_NLRI
fn build_ipv6_update(prefix_str: &str, local_asn: u32, _router_id: Ipv4Addr) -> Option<Vec<u8>> {
    let parts: Vec<&str> = prefix_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: Ipv6Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    let mut update = Vec::new();

    // Withdrawn Routes Length (0)
    update.extend_from_slice(&0u16.to_be_bytes());

    // Build path attributes
    #[rustfmt::skip]
    let mut path_attrs = vec![
        // ORIGIN (type 1) - IGP
        0x40, // Transitive
        1,    // ORIGIN
        1,    // Length
        0,    // IGP
        // AS_PATH (type 2) - AS_SEQUENCE with our ASN
        0x40, // Transitive
        2,    // AS_PATH
        6,    // Length
        2,    // AS_SEQUENCE
        1,    // 1 ASN
    ];
    path_attrs.extend_from_slice(&local_asn.to_be_bytes());

    // MP_REACH_NLRI (type 14) for IPv6
    let mut mp_reach = Vec::new();
    mp_reach.extend_from_slice(&2u16.to_be_bytes()); // AFI = 2 (IPv6)
    mp_reach.push(1); // SAFI = 1 (unicast)

    // Next hop - use a link-local address (fe80::1)
    // For link-local BGP sessions, the next-hop should be link-local
    let next_hop: Ipv6Addr = "fe80::1".parse().unwrap();
    mp_reach.push(16); // Next hop length (16 bytes for single IPv6)
    mp_reach.extend_from_slice(&next_hop.octets());

    mp_reach.push(0); // Reserved

    // NLRI
    mp_reach.push(prefix_len);
    let bytes_needed = prefix_len.div_ceil(8) as usize;
    mp_reach.extend_from_slice(&addr.octets()[..bytes_needed]);

    // MP_REACH_NLRI attribute (optional, non-transitive per RFC 4760)
    // Use extended length if needed
    if mp_reach.len() > 255 {
        path_attrs.push(0x90); // Optional, Extended Length
        path_attrs.push(14);   // MP_REACH_NLRI
        path_attrs.extend_from_slice(&(mp_reach.len() as u16).to_be_bytes());
    } else {
        path_attrs.push(0x80); // Optional
        path_attrs.push(14);   // MP_REACH_NLRI
        path_attrs.push(mp_reach.len() as u8);
    }
    path_attrs.extend_from_slice(&mp_reach);

    // Total Path Attribute Length
    update.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
    update.extend_from_slice(&path_attrs);

    // No IPv4 NLRI for IPv6 updates

    Some(update)
}
