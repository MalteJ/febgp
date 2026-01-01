// Test daemons are spawned and later killed via daemon.kill() - not zombie processes
#![allow(clippy::zombie_processes)]

mod common;

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use common::gobgp::{get_link_local_address, GobgpConfig, GobgpInstance, GobgpNeighbor};
use common::netns::{create_veth_pair, NetNs};

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Test that FeBGP can establish a BGP session with GoBGP using link-local addresses.
///
/// This test requires root privileges to create network namespaces.
/// Run with: sudo cargo test --test febgp_to_gobgp
#[test]
fn test_febgp_to_gobgp_link_local() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_r1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_r2").expect("Failed to create namespace r2");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    println!("FeBGP (ns1) link-local: {}", addr1);
    println!("GoBGP (ns2) link-local: {}", addr2);

    // Configure GoBGP on router 2 (passive - will accept connection from FeBGP)
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Start GoBGP
    let gobgp2 = GobgpInstance::start(&ns2, &config2, 50052).expect("Failed to start GoBGP");

    // Give GoBGP time to start listening
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Get the interface index for eth0 in ns1
    let if_index = get_interface_index(&ns1, "eth0").expect("Failed to get interface index");

    // Run FeBGP connector in ns1
    // We use a helper binary that uses the febgp library
    let febgp_result = run_febgp_in_namespace(
        &ns1,
        &FebgpOptions {
            local_asn: 65001,
            router_id: "1.1.1.1",
            remote_asn: 65002,
            peer_addr: &addr2,
            scope_id: if_index,
            port: 179,
            announce_v4: vec![],
            announce_v6: vec![],
            wait_seconds: 3,
        },
    );

    match febgp_result {
        Ok(output) => {
            println!("FeBGP output:\n{}", output);

            // Check GoBGP state (FeBGP held connection for 3 seconds)
            println!("=== GoBGP neighbor state ===");
            println!("{}", gobgp2.get_neighbor_summary());

            assert!(
                output.contains("ESTABLISHED"),
                "FeBGP did not reach ESTABLISHED state"
            );

            // Verify GoBGP saw the session as established at some point
            // (it may have dropped after FeBGP exited)
            assert!(
                output.contains("Session held for 3 seconds"),
                "FeBGP did not hold session"
            );
        }
        Err(e) => {
            eprintln!("=== GoBGP neighbor state ===");
            eprintln!("{}", gobgp2.get_neighbor_summary());
            panic!("FeBGP failed: {}", e);
        }
    }

    println!("BGP session established successfully!");
}

fn wait_for_link_local(ns: &NetNs, interface: &str) -> Option<String> {
    for _ in 0..20 {
        if let Ok(addr) = get_link_local_address(ns, interface) {
            return Some(addr);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    None
}

fn get_interface_index(ns: &NetNs, interface: &str) -> std::io::Result<u32> {
    let output = Command::new("ip")
        .args(["netns", "exec", &ns.name, "cat", &format!("/sys/class/net/{}/ifindex", interface)])
        .output()?;

    let index_str = String::from_utf8_lossy(&output.stdout);
    index_str
        .trim()
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Options for running FeBGP in a namespace
struct FebgpOptions<'a> {
    local_asn: u32,
    router_id: &'a str,
    remote_asn: u32,
    peer_addr: &'a str,
    scope_id: u32,
    port: u16,
    announce_v4: Vec<&'a str>,
    announce_v6: Vec<&'a str>,
    wait_seconds: u64,
}

fn run_febgp_in_namespace(ns: &NetNs, opts: &FebgpOptions) -> std::io::Result<String> {
    // Get workspace root (tests-integration is one level down)
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let binary_path = workspace_root.join("target/debug/febgp-connect");

    // Check that the binary exists (should be built by cargo test)
    if !binary_path.exists() {
        return Err(std::io::Error::other(format!(
            "febgp-connect binary not found at {:?}. Run 'cargo build -p tests-integration' first.",
            binary_path
        )));
    }

    // Build args
    let mut args = vec![
        "netns".to_string(),
        "exec".to_string(),
        ns.name.clone(),
        binary_path.to_str().unwrap().to_string(),
        opts.local_asn.to_string(),
        opts.router_id.to_string(),
        opts.remote_asn.to_string(),
        opts.peer_addr.to_string(),
        opts.scope_id.to_string(),
        opts.port.to_string(),
    ];

    // Add route announcements
    for prefix in &opts.announce_v4 {
        args.push("--announce-v4".to_string());
        args.push(prefix.to_string());
    }
    for prefix in &opts.announce_v6 {
        args.push("--announce-v6".to_string());
        args.push(prefix.to_string());
    }

    // Add wait time
    args.push("--wait".to_string());
    args.push(opts.wait_seconds.to_string());

    // Run the helper in the namespace
    let output = Command::new("ip")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "febgp-connect failed:\nstdout: {}\nstderr: {}",
            stdout, stderr
        )));
    }

    Ok(format!("{}\n{}", stdout, stderr))
}

/// Test that FeBGP can receive IPv4 routes from GoBGP.
#[test]
fn test_febgp_receives_ipv4_from_gobgp() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_v4r1").expect("Failed to create namespace");
    let ns2 = NetNs::new("febgp_test_v4r2").expect("Failed to create namespace");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    // Configure GoBGP
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Start GoBGP
    let gobgp2 = GobgpInstance::start(&ns2, &config2, 50053).expect("Failed to start GoBGP");

    // Give GoBGP time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Have GoBGP announce an IPv4 prefix
    gobgp2.announce_prefix_v4("10.100.0.0/24").expect("Failed to announce IPv4 prefix");

    let if_index = get_interface_index(&ns1, "eth0").expect("Failed to get interface index");

    // Run FeBGP and wait for routes
    let febgp_result = run_febgp_in_namespace(
        &ns1,
        &FebgpOptions {
            local_asn: 65001,
            router_id: "1.1.1.1",
            remote_asn: 65002,
            peer_addr: &addr2,
            scope_id: if_index,
            port: 179,
            announce_v4: vec![],
            announce_v6: vec![],
            wait_seconds: 5,
        },
    );

    match febgp_result {
        Ok(output) => {
            println!("FeBGP output:\n{}", output);

            assert!(
                output.contains("ESTABLISHED"),
                "FeBGP did not reach ESTABLISHED state"
            );

            assert!(
                output.contains("RECEIVED_V4: 10.100.0.0/24"),
                "FeBGP did not receive expected IPv4 prefix. Output:\n{}",
                output
            );

            println!("IPv4 route receive test passed!");
        }
        Err(e) => {
            eprintln!("=== GoBGP neighbor state ===");
            eprintln!("{}", gobgp2.get_neighbor_summary());
            panic!("FeBGP failed: {}", e);
        }
    }
}

/// Test that FeBGP can receive IPv6 routes from GoBGP.
#[test]
fn test_febgp_receives_ipv6_from_gobgp() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_v6r1").expect("Failed to create namespace");
    let ns2 = NetNs::new("febgp_test_v6r2").expect("Failed to create namespace");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    // Configure GoBGP
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Start GoBGP
    let gobgp2 = GobgpInstance::start(&ns2, &config2, 50054).expect("Failed to start GoBGP");

    // Give GoBGP time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Have GoBGP announce an IPv6 prefix
    gobgp2.announce_prefix("2001:db8:100::/48").expect("Failed to announce IPv6 prefix");

    let if_index = get_interface_index(&ns1, "eth0").expect("Failed to get interface index");

    // Run FeBGP and wait for routes
    let febgp_result = run_febgp_in_namespace(
        &ns1,
        &FebgpOptions {
            local_asn: 65001,
            router_id: "1.1.1.1",
            remote_asn: 65002,
            peer_addr: &addr2,
            scope_id: if_index,
            port: 179,
            announce_v4: vec![],
            announce_v6: vec![],
            wait_seconds: 5,
        },
    );

    match febgp_result {
        Ok(output) => {
            println!("FeBGP output:\n{}", output);

            assert!(
                output.contains("ESTABLISHED"),
                "FeBGP did not reach ESTABLISHED state"
            );

            assert!(
                output.contains("RECEIVED_V6: 2001:db8:100::/48"),
                "FeBGP did not receive expected IPv6 prefix. Output:\n{}",
                output
            );

            println!("IPv6 route receive test passed!");
        }
        Err(e) => {
            eprintln!("=== GoBGP neighbor state ===");
            eprintln!("{}", gobgp2.get_neighbor_summary());
            panic!("FeBGP failed: {}", e);
        }
    }
}

/// Test that FeBGP can send IPv4 routes to GoBGP.
#[test]
fn test_febgp_sends_ipv4_to_gobgp() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_s4r1").expect("Failed to create namespace");
    let ns2 = NetNs::new("febgp_test_s4r2").expect("Failed to create namespace");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    // Configure GoBGP
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Start GoBGP
    let gobgp2 = GobgpInstance::start(&ns2, &config2, 50055).expect("Failed to start GoBGP");

    // Give GoBGP time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    let if_index = get_interface_index(&ns1, "eth0").expect("Failed to get interface index");

    // Spawn FeBGP in background so we can check routes while session is active
    let ns1_name = ns1.name.clone();
    let addr2_clone = addr2.clone();
    let febgp_handle = std::thread::spawn(move || {
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let binary_path = workspace_root.join("target/debug/febgp-connect");

        Command::new("ip")
            .args([
                "netns", "exec", &ns1_name,
                binary_path.to_str().unwrap(),
                "65001", "1.1.1.1", "65002", &addr2_clone,
                &if_index.to_string(), "179",
                "--announce-v4", "10.200.0.0/24",
                "--wait", "10",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
    });

    // Wait for session to establish and routes to be exchanged
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check if GoBGP received the route while session is still active
    let gobgp_routes = gobgp2.get_routes_v4();
    println!("GoBGP IPv4 RIB:\n{}", gobgp_routes);

    // Show per-AFI received count (more accurate than generic neighbor summary)
    let received_count = gobgp2.get_neighbor_received_count("ipv4");
    println!("GoBGP IPv4 received count from neighbor: {:?}", received_count);
    println!("GoBGP neighbor state:\n{}", gobgp2.get_neighbor_summary());

    let has_route = gobgp2.has_prefix_v4("10.200.0.0/24");

    // Wait for FeBGP to finish
    let febgp_result = febgp_handle.join().expect("FeBGP thread panicked");
    match febgp_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("FeBGP output:\n{}\n{}", stdout, stderr);

            assert!(
                stdout.contains("ESTABLISHED") || stderr.contains("ESTABLISHED"),
                "FeBGP did not reach ESTABLISHED state"
            );

            assert!(
                stdout.contains("SENT_UPDATE_V4: 10.200.0.0/24") || stderr.contains("SENT_UPDATE_V4: 10.200.0.0/24"),
                "FeBGP did not send expected IPv4 prefix"
            );
        }
        Err(e) => {
            panic!("FeBGP failed: {}", e);
        }
    }

    assert!(
        has_route,
        "GoBGP did not receive expected IPv4 prefix from FeBGP. Routes:\n{}",
        gobgp_routes
    );

    // Note: The RIB check above is the source of truth.
    // The neighbor received count may show None due to GoBGP's JSON API structure.
    // The route being in the RIB with AS_PATH 65001 proves it was received from FeBGP.
    if let Some(count) = received_count {
        println!("GoBGP reports {} routes received from neighbor", count);
    }

    println!("IPv4 route send test passed!");
}

/// Test that FeBGP can send IPv6 routes to GoBGP.
#[test]
fn test_febgp_sends_ipv6_to_gobgp() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_s6r1").expect("Failed to create namespace");
    let ns2 = NetNs::new("febgp_test_s6r2").expect("Failed to create namespace");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    // Configure GoBGP
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Start GoBGP
    let gobgp2 = GobgpInstance::start(&ns2, &config2, 50056).expect("Failed to start GoBGP");

    // Give GoBGP time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    let if_index = get_interface_index(&ns1, "eth0").expect("Failed to get interface index");

    // Spawn FeBGP in background so we can check routes while session is active
    let ns1_name = ns1.name.clone();
    let addr2_clone = addr2.clone();
    let febgp_handle = std::thread::spawn(move || {
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let binary_path = workspace_root.join("target/debug/febgp-connect");

        Command::new("ip")
            .args([
                "netns", "exec", &ns1_name,
                binary_path.to_str().unwrap(),
                "65001", "1.1.1.1", "65002", &addr2_clone,
                &if_index.to_string(), "179",
                "--announce-v6", "2001:db8:200::/48",
                "--wait", "10",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
    });

    // Wait for session to establish and routes to be exchanged
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check if GoBGP received the route while session is still active
    let gobgp_routes = gobgp2.get_routes();
    println!("GoBGP IPv6 RIB:\n{}", gobgp_routes);

    // Show per-AFI received count (more accurate than generic neighbor summary)
    let received_count = gobgp2.get_neighbor_received_count("ipv6");
    println!("GoBGP IPv6 received count from neighbor: {:?}", received_count);
    println!("GoBGP neighbor state:\n{}", gobgp2.get_neighbor_summary());

    let has_route = gobgp2.has_prefix("2001:db8:200::/48");

    // Wait for FeBGP to finish
    let febgp_result = febgp_handle.join().expect("FeBGP thread panicked");
    match febgp_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("FeBGP output:\n{}\n{}", stdout, stderr);

            assert!(
                stdout.contains("ESTABLISHED") || stderr.contains("ESTABLISHED"),
                "FeBGP did not reach ESTABLISHED state"
            );

            assert!(
                stdout.contains("SENT_UPDATE_V6: 2001:db8:200::/48") || stderr.contains("SENT_UPDATE_V6: 2001:db8:200::/48"),
                "FeBGP did not send expected IPv6 prefix"
            );
        }
        Err(e) => {
            panic!("FeBGP failed: {}", e);
        }
    }

    assert!(
        has_route,
        "GoBGP did not receive expected IPv6 prefix from FeBGP. Routes:\n{}",
        gobgp_routes
    );

    // Note: The RIB check above is the source of truth.
    // The neighbor received count may show None due to GoBGP's JSON API structure.
    // The route being in the RIB with AS_PATH 65001 proves it was received from FeBGP.
    if let Some(count) = received_count {
        println!("GoBGP reports {} routes received from neighbor", count);
    }

    println!("IPv6 route send test passed!");
}

/// Test that FeBGP daemon properly stores received routes in RIB.
#[test]
fn test_febgp_daemon_rib() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_rib1").expect("Failed to create namespace");
    let ns2 = NetNs::new("febgp_test_rib2").expect("Failed to create namespace");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    // Configure GoBGP
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Start GoBGP
    let gobgp2 = GobgpInstance::start(&ns2, &config2, 50060).expect("Failed to start GoBGP");

    // Give GoBGP time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Have GoBGP announce some prefixes
    gobgp2.announce_prefix_v4("10.50.0.0/24").expect("Failed to announce IPv4 prefix");
    gobgp2.announce_prefix_v4("10.50.1.0/24").expect("Failed to announce IPv4 prefix");
    gobgp2.announce_prefix("2001:db8:50::/48").expect("Failed to announce IPv6 prefix");

    // Create FeBGP config
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_rib_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_rib_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002
"#,
            addr2
        ),
    )
    .expect("Failed to write config");

    // Start FeBGP daemon
    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon",
            "-c",
            &config_path,
            "--socket",
            &socket_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for session to establish and routes to be received
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Run febgp routes command
    let routes_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "routes",
            "-s",
            &socket_path,
        ])
        .output()
        .expect("Failed to run febgp routes");

    let routes_stdout = String::from_utf8_lossy(&routes_output.stdout);
    println!("FeBGP routes output:\n{}", routes_stdout);

    // Run febgp status command
    let status_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "status",
            "-s",
            &socket_path,
        ])
        .output()
        .expect("Failed to run febgp status");

    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    println!("FeBGP status output:\n{}", status_stdout);

    // Kill daemon
    let _ = daemon.kill();

    // Clean up config
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // Verify routes are in output
    assert!(
        routes_stdout.contains("10.50.0.0/24"),
        "RIB should contain 10.50.0.0/24"
    );
    assert!(
        routes_stdout.contains("10.50.1.0/24"),
        "RIB should contain 10.50.1.0/24"
    );
    assert!(
        routes_stdout.contains("2001:db8:50::/48"),
        "RIB should contain 2001:db8:50::/48"
    );

    // Verify status shows prefixes received
    assert!(
        status_stdout.contains("Established"),
        "Session should be Established"
    );

    println!("FeBGP daemon RIB test passed!");
}

/// Test that FeBGP daemon can establish sessions with two GoBGP peers simultaneously.
///
/// Topology:
///          GoBGP1 (AS 65002, ns2)
///         /  eth0 <-> eth0
/// FeBGP (AS 65001, ns1)
///         \  eth1 <-> eth0
///          GoBGP2 (AS 65003, ns3)
#[test]
fn test_febgp_two_gobgp_peers() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create three network namespaces
    let ns1 = NetNs::new("febgp_test_2p_r1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_2p_r2").expect("Failed to create namespace r2");
    let ns3 = NetNs::new("febgp_test_2p_r3").expect("Failed to create namespace r3");

    // Create veth pairs: ns1:eth0 <-> ns2:eth0, ns1:eth1 <-> ns3:eth0
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair 1");
    create_veth_pair(&ns1, "eth1", &ns3, "eth0").expect("Failed to create veth pair 2");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1_eth0 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1 eth0");
    let addr1_eth1 = wait_for_link_local(&ns1, "eth1").expect("Failed to get link-local for r1 eth1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");
    let addr3 = wait_for_link_local(&ns3, "eth0").expect("Failed to get link-local for r3");

    println!("FeBGP (ns1) eth0 link-local: {}", addr1_eth0);
    println!("FeBGP (ns1) eth1 link-local: {}", addr1_eth1);
    println!("GoBGP1 (ns2) link-local: {}", addr2);
    println!("GoBGP2 (ns3) link-local: {}", addr3);

    // Configure GoBGP1 (AS 65002)
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth0),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Configure GoBGP2 (AS 65003)
    let config3 = GobgpConfig {
        asn: 65003,
        router_id: Ipv4Addr::new(3, 3, 3, 3),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth1),
            local_address: format!("{}%eth0", addr3),
            remote_asn: 65001,
        }],
    };

    // Start both GoBGP instances
    let gobgp1 = GobgpInstance::start(&ns2, &config2, 50061).expect("Failed to start GoBGP1");
    let gobgp2 = GobgpInstance::start(&ns3, &config3, 50062).expect("Failed to start GoBGP2");

    // Give GoBGP time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Have each GoBGP announce a unique prefix
    gobgp1.announce_prefix_v4("10.2.0.0/24").expect("Failed to announce prefix from GoBGP1");
    gobgp2.announce_prefix_v4("10.3.0.0/24").expect("Failed to announce prefix from GoBGP2");

    // Have both announce the same prefix (basic multi-path test - just verifies receipt)
    gobgp1.announce_prefix_v4("10.4.0.0/24").expect("Failed to announce shared prefix from GoBGP1");
    gobgp2.announce_prefix_v4("10.4.0.0/24").expect("Failed to announce shared prefix from GoBGP2");

    // Create FeBGP config with two peers
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_2peers_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_2peers_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002

[[peer]]
interface = "eth1"
address = "{}%eth1"
remote_asn = 65003
"#,
            addr2, addr3
        ),
    )
    .expect("Failed to write config");

    // Start FeBGP daemon
    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon",
            "-c",
            &config_path,
            "--socket",
            &socket_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for sessions to establish and routes to be received
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Run febgp status command
    let status_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "status",
            "-s",
            &socket_path,
        ])
        .output()
        .expect("Failed to run febgp status");

    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    println!("FeBGP status output:\n{}", status_stdout);

    // Run febgp routes command
    let routes_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "routes",
            "-s",
            &socket_path,
        ])
        .output()
        .expect("Failed to run febgp routes");

    let routes_stdout = String::from_utf8_lossy(&routes_output.stdout);
    println!("FeBGP routes output:\n{}", routes_stdout);

    // Check GoBGP neighbor states
    println!("=== GoBGP1 neighbor state ===");
    println!("{}", gobgp1.get_neighbor_summary());
    println!("=== GoBGP2 neighbor state ===");
    println!("{}", gobgp2.get_neighbor_summary());

    // Kill daemon
    let _ = daemon.kill();

    // Clean up config
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // Verify both sessions are established
    let established_count = status_stdout.matches("Established").count();
    assert!(
        established_count >= 2,
        "Expected 2 Established sessions, found {}. Status:\n{}",
        established_count,
        status_stdout
    );

    // Verify routes from both peers are received
    assert!(
        routes_stdout.contains("10.2.0.0/24"),
        "RIB should contain 10.2.0.0/24 from GoBGP1"
    );
    assert!(
        routes_stdout.contains("10.3.0.0/24"),
        "RIB should contain 10.3.0.0/24 from GoBGP2"
    );
    assert!(
        routes_stdout.contains("10.4.0.0/24"),
        "RIB should contain 10.4.0.0/24 (announced by both peers)"
    );

    // Note: Best path selection and ECMP are tested separately in
    // test_febgp_aspath_selection and test_febgp_ecmp

    println!("Two GoBGP peers test passed!");
}

/// Test AS path length selection: shorter AS path should be preferred.
/// This test announces the SHORTER path FIRST, then the LONGER path.
/// With proper best path selection, the shorter path should still be selected.
/// With last-received-wins, this test will FAIL (longer path wins).
///
/// See docs/implementation-status.md for details.
#[test]
fn test_febgp_aspath_selection() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create three network namespaces
    let ns1 = NetNs::new("febgp_test_asp1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_asp2").expect("Failed to create namespace r2");
    let ns3 = NetNs::new("febgp_test_asp3").expect("Failed to create namespace r3");

    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair 1");
    create_veth_pair(&ns1, "eth1", &ns3, "eth0").expect("Failed to create veth pair 2");

    std::thread::sleep(std::time::Duration::from_secs(2));

    let addr1_eth0 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1 eth0");
    let addr1_eth1 = wait_for_link_local(&ns1, "eth1").expect("Failed to get link-local for r1 eth1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");
    let addr3 = wait_for_link_local(&ns3, "eth0").expect("Failed to get link-local for r3");

    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth0),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    let config3 = GobgpConfig {
        asn: 65003,
        router_id: Ipv4Addr::new(3, 3, 3, 3),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth1),
            local_address: format!("{}%eth0", addr3),
            remote_asn: 65001,
        }],
    };

    let gobgp1 = GobgpInstance::start(&ns2, &config2, 50081).expect("Failed to start GoBGP1");
    let gobgp2 = GobgpInstance::start(&ns3, &config3, 50082).expect("Failed to start GoBGP2");

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Create FeBGP config
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_aspath_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_aspath_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002

[[peer]]
interface = "eth1"
address = "{}%eth1"
remote_asn = 65003
"#,
            addr2, addr3
        ),
    )
    .expect("Failed to write config");

    // Start FeBGP FIRST
    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon", "-c", &config_path, "--socket", &socket_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for sessions to establish
    std::thread::sleep(std::time::Duration::from_secs(3));

    // NOW announce routes in a deterministic order:
    // GoBGP1: AS_PATH [65002] (length 1) - announced FIRST
    // GoBGP2: AS_PATH [65003, 65099, 65098] (length 3) - announced SECOND
    // If best path selection works: shorter path (65002) wins
    // If last-received wins: longer path (65003 65099 65098) wins - TEST FAILS
    gobgp1.announce_prefix_v4("10.6.0.0/24").expect("Failed to announce from GoBGP1");
    std::thread::sleep(std::time::Duration::from_millis(500));
    gobgp2.announce_prefix_v4_with_aspath("10.6.0.0/24", "65099 65098").expect("Failed to announce from GoBGP2");

    // Wait for routes to be received
    std::thread::sleep(std::time::Duration::from_secs(2));

    let routes_output = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "routes", "-s", &socket_path,
        ])
        .output()
        .expect("Failed to run febgp routes");

    let routes_stdout = String::from_utf8_lossy(&routes_output.stdout);
    println!("FeBGP routes output:\n{}", routes_stdout);

    let _ = daemon.kill();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // Find the route for 10.6.0.0/24
    let route_line = routes_stdout
        .lines()
        .find(|l| l.contains("10.6.0.0/24"))
        .expect("Should find 10.6.0.0/24 in routes");

    println!("Route for 10.6.0.0/24: {}", route_line);

    // The shorter AS path (via 65002) should be selected
    assert!(
        route_line.contains("65002") && !route_line.contains("65099"),
        "AS path selection failed: 10.6.0.0/24 should be via AS 65002 (shorter path), got: {}",
        route_line
    );

    println!("AS path selection test passed!");
}

/// Test ECMP: when two peers announce the same prefix with equal AS path length,
/// both paths should be kept in the RIB.
///
/// See docs/implementation-status.md for details.
#[test]
fn test_febgp_ecmp() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create three network namespaces
    let ns1 = NetNs::new("febgp_test_ecmp1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_ecmp2").expect("Failed to create namespace r2");
    let ns3 = NetNs::new("febgp_test_ecmp3").expect("Failed to create namespace r3");

    // Create veth pairs
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair 1");
    create_veth_pair(&ns1, "eth1", &ns3, "eth0").expect("Failed to create veth pair 2");

    // Wait for DAD
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1_eth0 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1 eth0");
    let addr1_eth1 = wait_for_link_local(&ns1, "eth1").expect("Failed to get link-local for r1 eth1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");
    let addr3 = wait_for_link_local(&ns3, "eth0").expect("Failed to get link-local for r3");

    // Configure GoBGP1 (AS 65002)
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth0),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Configure GoBGP2 (AS 65003)
    let config3 = GobgpConfig {
        asn: 65003,
        router_id: Ipv4Addr::new(3, 3, 3, 3),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth1),
            local_address: format!("{}%eth0", addr3),
            remote_asn: 65001,
        }],
    };

    // Start both GoBGP instances
    let gobgp1 = GobgpInstance::start(&ns2, &config2, 50071).expect("Failed to start GoBGP1");
    let gobgp2 = GobgpInstance::start(&ns3, &config3, 50072).expect("Failed to start GoBGP2");

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Both announce the same prefix with equal AS path length (1 hop each)
    // GoBGP1: 10.5.0.0/24 with AS_PATH [65002]
    // GoBGP2: 10.5.0.0/24 with AS_PATH [65003]
    gobgp1.announce_prefix_v4("10.5.0.0/24").expect("Failed to announce from GoBGP1");
    gobgp2.announce_prefix_v4("10.5.0.0/24").expect("Failed to announce from GoBGP2");

    // Create FeBGP config
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_ecmp_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_ecmp_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002

[[peer]]
interface = "eth1"
address = "{}%eth1"
remote_asn = 65003
"#,
            addr2, addr3
        ),
    )
    .expect("Failed to write config");

    // Start FeBGP daemon
    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon", "-c", &config_path, "--socket", &socket_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    std::thread::sleep(std::time::Duration::from_secs(5));

    // Get routes
    let routes_output = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "routes", "-s", &socket_path,
        ])
        .output()
        .expect("Failed to run febgp routes");

    let routes_stdout = String::from_utf8_lossy(&routes_output.stdout);
    println!("FeBGP routes output:\n{}", routes_stdout);

    let _ = daemon.kill();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // For ECMP, we expect BOTH paths to be in the RIB for 10.5.0.0/24
    // The CLI groups routes by prefix, so we need to check for both AS paths
    // being present in the output (the second ECMP path won't repeat the prefix)
    let has_65002 = routes_stdout.contains("65002");
    let has_65003 = routes_stdout.contains("65003");

    // Count best path markers (*) to verify both paths are marked as best
    let best_markers = routes_stdout.lines()
        .filter(|l| l.starts_with("*"))
        .count();

    println!("Has path via 65002: {}, Has path via 65003: {}", has_65002, has_65003);
    println!("Best path markers: {}", best_markers);

    assert!(
        has_65002 && has_65003,
        "ECMP: Expected paths via both 65002 and 65003. Routes:\n{}",
        routes_stdout
    );

    assert!(
        best_markers >= 2,
        "ECMP: Expected at least 2 best paths (*), found {}. Routes:\n{}",
        best_markers,
        routes_stdout
    );

    println!("ECMP test passed!");
}

/// Test ECMP withdrawal: when one peer disconnects, the remaining path should still be valid.
#[test]
fn test_febgp_ecmp_withdrawal() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create three network namespaces
    let ns1 = NetNs::new("febgp_test_ecmpw1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_ecmpw2").expect("Failed to create namespace r2");
    let ns3 = NetNs::new("febgp_test_ecmpw3").expect("Failed to create namespace r3");

    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair 1");
    create_veth_pair(&ns1, "eth1", &ns3, "eth0").expect("Failed to create veth pair 2");

    std::thread::sleep(std::time::Duration::from_secs(2));

    let addr1_eth0 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1 eth0");
    let addr1_eth1 = wait_for_link_local(&ns1, "eth1").expect("Failed to get link-local for r1 eth1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");
    let addr3 = wait_for_link_local(&ns3, "eth0").expect("Failed to get link-local for r3");

    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth0),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    let config3 = GobgpConfig {
        asn: 65003,
        router_id: Ipv4Addr::new(3, 3, 3, 3),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth1),
            local_address: format!("{}%eth0", addr3),
            remote_asn: 65001,
        }],
    };

    // Start both GoBGP instances - gobgp2 will be killed later
    let gobgp1 = GobgpInstance::start(&ns2, &config2, 50091).expect("Failed to start GoBGP1");
    let mut gobgp2 = GobgpInstance::start(&ns3, &config3, 50092).expect("Failed to start GoBGP2");

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Both announce the same prefix
    gobgp1.announce_prefix_v4("10.7.0.0/24").expect("Failed to announce from GoBGP1");
    gobgp2.announce_prefix_v4("10.7.0.0/24").expect("Failed to announce from GoBGP2");

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_ecmpw_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_ecmpw_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002

[[peer]]
interface = "eth1"
address = "{}%eth1"
remote_asn = 65003
"#,
            addr2, addr3
        ),
    )
    .expect("Failed to write config");

    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon", "-c", &config_path, "--socket", &socket_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for sessions to establish and routes to be received
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check initial state - should have ECMP (2 paths)
    let routes_output = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "routes", "-s", &socket_path,
        ])
        .output()
        .expect("Failed to run febgp routes");

    let routes_before = String::from_utf8_lossy(&routes_output.stdout);
    println!("Routes BEFORE withdrawal:\n{}", routes_before);

    let has_65002_before = routes_before.contains("65002");
    let has_65003_before = routes_before.contains("65003");
    assert!(
        has_65002_before && has_65003_before,
        "Should have ECMP paths via both 65002 and 65003 before withdrawal"
    );

    // Kill GoBGP2 - this should trigger session down and route removal
    println!("Killing GoBGP2...");
    gobgp2.stop();

    // Wait for session to go down and routes to be updated
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check state after withdrawal - should have only 1 path via 65002
    let routes_output = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "routes", "-s", &socket_path,
        ])
        .output()
        .expect("Failed to run febgp routes");

    let routes_after = String::from_utf8_lossy(&routes_output.stdout);
    println!("Routes AFTER withdrawal:\n{}", routes_after);

    let _ = daemon.kill();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // Verify: should still have route via 65002, but NOT via 65003
    let has_65002_after = routes_after.contains("65002");
    let has_65003_after = routes_after.contains("65003");

    assert!(
        has_65002_after,
        "Should still have route via 65002 after 65003 withdrawal. Routes:\n{}",
        routes_after
    );
    assert!(
        !has_65003_after,
        "Should NOT have route via 65003 after withdrawal. Routes:\n{}",
        routes_after
    );

    // Verify the remaining route is marked as best
    let best_count = routes_after.lines().filter(|l| l.starts_with("*")).count();
    assert!(
        best_count >= 1,
        "Remaining route should be marked as best. Routes:\n{}",
        routes_after
    );

    println!("ECMP withdrawal test passed!");
}

/// Test that FeBGP installs routes into the Linux routing table when --install-routes is set.
#[test]
fn test_febgp_install_routes() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_ir1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_ir2").expect("Failed to create namespace r2");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    // Configure GoBGP
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Start GoBGP
    let gobgp = GobgpInstance::start(&ns2, &config2, 50095).expect("Failed to start GoBGP");

    // Give GoBGP time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Have GoBGP announce an IPv4 prefix
    gobgp.announce_prefix_v4("10.99.0.0/24").expect("Failed to announce IPv4 prefix");

    // Create FeBGP config
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_install_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_install_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002
"#,
            addr2
        ),
    )
    .expect("Failed to write config");

    // Start FeBGP daemon WITH --install-routes flag
    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon",
            "-c",
            &config_path,
            "--socket",
            &socket_path,
            "--install-routes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for session to establish and routes to be received and installed
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check the Linux routing table in ns1
    let route_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            "ip",
            "route",
            "show",
            "10.99.0.0/24",
        ])
        .output()
        .expect("Failed to run ip route show");

    let route_stdout = String::from_utf8_lossy(&route_output.stdout);
    println!("Linux routing table:\n{}", route_stdout);

    // Also check FeBGP RIB for comparison
    let routes_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "routes",
            "-s",
            &socket_path,
        ])
        .output()
        .expect("Failed to run febgp routes");

    let routes_stdout = String::from_utf8_lossy(&routes_output.stdout);
    println!("FeBGP RIB:\n{}", routes_stdout);

    // Kill daemon
    let _ = daemon.kill();

    // Clean up config
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // Verify the route is in the Linux routing table
    assert!(
        route_stdout.contains("10.99.0.0/24"),
        "Route 10.99.0.0/24 should be installed in Linux routing table. Got:\n{}",
        route_stdout
    );

    // The route should point to the link-local next-hop via eth0
    assert!(
        route_stdout.contains("dev eth0"),
        "Route should be via eth0. Got:\n{}",
        route_stdout
    );

    println!("Route installation test passed!");
}

/// Test that FeBGP installs ECMP routes into the Linux routing table.
#[test]
fn test_febgp_install_routes_ecmp() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create three network namespaces (hub-and-spoke topology)
    let ns1 = NetNs::new("febgp_test_ire1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_ire2").expect("Failed to create namespace r2");
    let ns3 = NetNs::new("febgp_test_ire3").expect("Failed to create namespace r3");

    // Create veth pairs
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair 1");
    create_veth_pair(&ns1, "eth1", &ns3, "eth0").expect("Failed to create veth pair 2");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1_eth0 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1 eth0");
    let addr1_eth1 = wait_for_link_local(&ns1, "eth1").expect("Failed to get link-local for r1 eth1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");
    let addr3 = wait_for_link_local(&ns3, "eth0").expect("Failed to get link-local for r3");

    // Configure GoBGP1 (AS 65002)
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth0),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Configure GoBGP2 (AS 65003)
    let config3 = GobgpConfig {
        asn: 65003,
        router_id: Ipv4Addr::new(3, 3, 3, 3),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth1),
            local_address: format!("{}%eth0", addr3),
            remote_asn: 65001,
        }],
    };

    // Start both GoBGP instances
    let gobgp1 = GobgpInstance::start(&ns2, &config2, 50096).expect("Failed to start GoBGP1");
    let gobgp2 = GobgpInstance::start(&ns3, &config3, 50097).expect("Failed to start GoBGP2");

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Both announce the same prefix with equal AS path length (ECMP)
    gobgp1.announce_prefix_v4("10.88.0.0/24").expect("Failed to announce from GoBGP1");
    gobgp2.announce_prefix_v4("10.88.0.0/24").expect("Failed to announce from GoBGP2");

    // Create FeBGP config
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_ecmp_install_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_ecmp_install_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002

[[peer]]
interface = "eth1"
address = "{}%eth1"
remote_asn = 65003
"#,
            addr2, addr3
        ),
    )
    .expect("Failed to write config");

    // Start FeBGP daemon WITH --install-routes flag
    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon",
            "-c",
            &config_path,
            "--socket",
            &socket_path,
            "--install-routes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for sessions to establish and routes to be received and installed
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check the Linux routing table in ns1 for ECMP routes
    let route_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            "ip",
            "route",
            "show",
            "10.88.0.0/24",
        ])
        .output()
        .expect("Failed to run ip route show");

    let route_stdout = String::from_utf8_lossy(&route_output.stdout);
    println!("Linux routing table:\n{}", route_stdout);

    // Also check FeBGP RIB
    let routes_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "routes",
            "-s",
            &socket_path,
        ])
        .output()
        .expect("Failed to run febgp routes");

    let routes_stdout = String::from_utf8_lossy(&routes_output.stdout);
    println!("FeBGP RIB:\n{}", routes_stdout);

    // Kill daemon
    let _ = daemon.kill();

    // Clean up
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // Verify ECMP: should have two routes (or one multipath route with two nexthops)
    // Linux shows ECMP either as multiple lines or as "nexthop via ... nexthop via ..."
    let route_count = route_stdout.lines().count();
    let has_eth0 = route_stdout.contains("eth0");
    let has_eth1 = route_stdout.contains("eth1");

    println!("Route lines: {}, has eth0: {}, has eth1: {}", route_count, has_eth0, has_eth1);

    assert!(
        route_stdout.contains("10.88.0.0/24"),
        "Route 10.88.0.0/24 should be installed. Got:\n{}",
        route_stdout
    );

    assert!(
        has_eth0 && has_eth1,
        "ECMP: Should have routes via both eth0 and eth1. Got:\n{}",
        route_stdout
    );

    println!("ECMP route installation test passed!");
}

/// Test that routes are removed from the Linux routing table when a peer disconnects.
#[test]
fn test_febgp_install_routes_removal() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_irr1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_irr2").expect("Failed to create namespace r2");

    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    std::thread::sleep(std::time::Duration::from_secs(2));

    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    let mut gobgp = GobgpInstance::start(&ns2, &config2, 50098).expect("Failed to start GoBGP");

    std::thread::sleep(std::time::Duration::from_secs(1));

    gobgp.announce_prefix_v4("10.77.0.0/24").expect("Failed to announce prefix");

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_removal_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_removal_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002
"#,
            addr2
        ),
    )
    .expect("Failed to write config");

    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon", "-c", &config_path, "--socket", &socket_path, "--install-routes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for route to be installed
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Verify route is installed
    let route_before = Command::new("ip")
        .args(["netns", "exec", &ns1.name, "ip", "route", "show", "10.77.0.0/24"])
        .output()
        .expect("Failed to run ip route show");

    let route_before_stdout = String::from_utf8_lossy(&route_before.stdout);
    println!("Route BEFORE peer disconnect:\n{}", route_before_stdout);

    assert!(
        route_before_stdout.contains("10.77.0.0/24"),
        "Route should be installed before disconnect. Got:\n{}",
        route_before_stdout
    );

    // Kill GoBGP to simulate peer disconnect
    println!("Stopping GoBGP...");
    gobgp.stop();

    // Wait for FeBGP to detect disconnect and remove routes
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Verify route is removed
    let route_after = Command::new("ip")
        .args(["netns", "exec", &ns1.name, "ip", "route", "show", "10.77.0.0/24"])
        .output()
        .expect("Failed to run ip route show");

    let route_after_stdout = String::from_utf8_lossy(&route_after.stdout);
    println!("Route AFTER peer disconnect:\n{}", route_after_stdout);

    let _ = daemon.kill();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    assert!(
        route_after_stdout.trim().is_empty() || !route_after_stdout.contains("10.77.0.0/24"),
        "Route should be removed after disconnect. Got:\n{}",
        route_after_stdout
    );

    println!("Route removal test passed!");
}

/// Test ECMP withdrawal: when one peer disconnects, its route is removed but the other stays.
#[test]
fn test_febgp_install_routes_ecmp_withdrawal() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create three network namespaces
    let ns1 = NetNs::new("febgp_test_irew1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_irew2").expect("Failed to create namespace r2");
    let ns3 = NetNs::new("febgp_test_irew3").expect("Failed to create namespace r3");

    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair 1");
    create_veth_pair(&ns1, "eth1", &ns3, "eth0").expect("Failed to create veth pair 2");

    std::thread::sleep(std::time::Duration::from_secs(2));

    let addr1_eth0 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1 eth0");
    let addr1_eth1 = wait_for_link_local(&ns1, "eth1").expect("Failed to get link-local for r1 eth1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");
    let addr3 = wait_for_link_local(&ns3, "eth0").expect("Failed to get link-local for r3");

    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth0),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    let config3 = GobgpConfig {
        asn: 65003,
        router_id: Ipv4Addr::new(3, 3, 3, 3),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth1),
            local_address: format!("{}%eth0", addr3),
            remote_asn: 65001,
        }],
    };

    let gobgp1 = GobgpInstance::start(&ns2, &config2, 50099).expect("Failed to start GoBGP1");
    let mut gobgp2 = GobgpInstance::start(&ns3, &config3, 50100).expect("Failed to start GoBGP2");

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Both announce the same prefix (ECMP)
    gobgp1.announce_prefix_v4("10.66.0.0/24").expect("Failed to announce from GoBGP1");
    gobgp2.announce_prefix_v4("10.66.0.0/24").expect("Failed to announce from GoBGP2");

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_ecmp_withdrawal_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_ecmp_withdrawal_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002

[[peer]]
interface = "eth1"
address = "{}%eth1"
remote_asn = 65003
"#,
            addr2, addr3
        ),
    )
    .expect("Failed to write config");

    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon", "-c", &config_path, "--socket", &socket_path, "--install-routes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for ECMP routes to be installed
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Verify both ECMP routes are installed
    let route_before = Command::new("ip")
        .args(["netns", "exec", &ns1.name, "ip", "route", "show", "10.66.0.0/24"])
        .output()
        .expect("Failed to run ip route show");

    let route_before_stdout = String::from_utf8_lossy(&route_before.stdout);
    println!("Routes BEFORE withdrawal:\n{}", route_before_stdout);

    let has_eth0_before = route_before_stdout.contains("eth0");
    let has_eth1_before = route_before_stdout.contains("eth1");
    assert!(
        has_eth0_before && has_eth1_before,
        "Should have ECMP routes via both interfaces. Got:\n{}",
        route_before_stdout
    );

    // Kill GoBGP2 (eth1) to withdraw one ECMP path
    println!("Stopping GoBGP2 (eth1)...");
    gobgp2.stop();

    // Wait for FeBGP to detect disconnect and update routes
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Verify: eth0 route should remain, eth1 route should be gone
    let route_after = Command::new("ip")
        .args(["netns", "exec", &ns1.name, "ip", "route", "show", "10.66.0.0/24"])
        .output()
        .expect("Failed to run ip route show");

    let route_after_stdout = String::from_utf8_lossy(&route_after.stdout);
    println!("Routes AFTER withdrawal:\n{}", route_after_stdout);

    let _ = daemon.kill();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // Keep gobgp1 alive until we're done checking
    drop(gobgp1);

    let has_eth0_after = route_after_stdout.contains("eth0");
    let has_eth1_after = route_after_stdout.contains("eth1");

    assert!(
        has_eth0_after,
        "Route via eth0 should still exist. Got:\n{}",
        route_after_stdout
    );
    assert!(
        !has_eth1_after,
        "Route via eth1 should be removed. Got:\n{}",
        route_after_stdout
    );

    println!("ECMP withdrawal route removal test passed!");
}

/// Test that a single route becomes ECMP when a second peer announces the same prefix.
#[test]
fn test_febgp_install_routes_upgrade_to_ecmp() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create three network namespaces
    let ns1 = NetNs::new("febgp_test_iru1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_iru2").expect("Failed to create namespace r2");
    let ns3 = NetNs::new("febgp_test_iru3").expect("Failed to create namespace r3");

    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair 1");
    create_veth_pair(&ns1, "eth1", &ns3, "eth0").expect("Failed to create veth pair 2");

    std::thread::sleep(std::time::Duration::from_secs(2));

    let addr1_eth0 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1 eth0");
    let addr1_eth1 = wait_for_link_local(&ns1, "eth1").expect("Failed to get link-local for r1 eth1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");
    let addr3 = wait_for_link_local(&ns3, "eth0").expect("Failed to get link-local for r3");

    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth0),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    let config3 = GobgpConfig {
        asn: 65003,
        router_id: Ipv4Addr::new(3, 3, 3, 3),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1_eth1),
            local_address: format!("{}%eth0", addr3),
            remote_asn: 65001,
        }],
    };

    // Start both GoBGPs, but only have GoBGP1 announce initially
    let gobgp1 = GobgpInstance::start(&ns2, &config2, 50101).expect("Failed to start GoBGP1");
    let gobgp2 = GobgpInstance::start(&ns3, &config3, 50102).expect("Failed to start GoBGP2");
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Only GoBGP1 announces the prefix initially
    gobgp1.announce_prefix_v4("10.55.0.0/24").expect("Failed to announce from GoBGP1");

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_upgrade_ecmp_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_upgrade_ecmp_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002

[[peer]]
interface = "eth1"
address = "{}%eth1"
remote_asn = 65003
"#,
            addr2, addr3
        ),
    )
    .expect("Failed to write config");

    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon", "-c", &config_path, "--socket", &socket_path, "--install-routes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for sessions to establish and first route to be installed
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check: should have single route via eth0 (GoBGP2 hasn't announced yet)
    let route_single = Command::new("ip")
        .args(["netns", "exec", &ns1.name, "ip", "route", "show", "10.55.0.0/24"])
        .output()
        .expect("Failed to run ip route show");

    let route_single_stdout = String::from_utf8_lossy(&route_single.stdout);
    println!("Route with SINGLE path:\n{}", route_single_stdout);

    assert!(
        route_single_stdout.contains("eth0"),
        "Should have route via eth0. Got:\n{}",
        route_single_stdout
    );
    assert!(
        !route_single_stdout.contains("eth1"),
        "Should NOT have route via eth1 yet. Got:\n{}",
        route_single_stdout
    );

    // Now have GoBGP2 announce the same prefix (session already established)
    gobgp2.announce_prefix_v4("10.55.0.0/24").expect("Failed to announce from GoBGP2");

    // Wait for second route to be added (upgrade to ECMP)
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Check: should now have ECMP routes via both eth0 and eth1
    let route_ecmp = Command::new("ip")
        .args(["netns", "exec", &ns1.name, "ip", "route", "show", "10.55.0.0/24"])
        .output()
        .expect("Failed to run ip route show");

    let route_ecmp_stdout = String::from_utf8_lossy(&route_ecmp.stdout);
    println!("Route with ECMP (after second peer):\n{}", route_ecmp_stdout);

    let _ = daemon.kill();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);
    drop(gobgp1);
    drop(gobgp2);

    let has_eth0 = route_ecmp_stdout.contains("eth0");
    let has_eth1 = route_ecmp_stdout.contains("eth1");

    assert!(
        has_eth0 && has_eth1,
        "Should have ECMP routes via both eth0 and eth1. Got:\n{}",
        route_ecmp_stdout
    );

    println!("Upgrade to ECMP test passed!");
}

/// Test that GoBGP receives routes announced by the FeBGP daemon.
///
/// This test verifies the full route announcement flow:
/// 1. FeBGP daemon starts with configured prefixes
/// 2. Session is established with GoBGP
/// 3. FeBGP announces its configured prefixes
/// 4. GoBGP receives and stores the routes in its RIB
#[test]
fn test_gobgp_receives_routes_from_febgp_daemon() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_ann1").expect("Failed to create namespace");
    let ns2 = NetNs::new("febgp_test_ann2").expect("Failed to create namespace");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    // Configure GoBGP (will receive routes from FeBGP)
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Start GoBGP
    let gobgp2 = GobgpInstance::start(&ns2, &config2, 50070).expect("Failed to start GoBGP");

    // Give GoBGP time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Create FeBGP config with prefixes to announce
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_ann_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_ann_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = ["10.99.0.0/24", "10.99.1.0/24", "2001:db8:99::/48"]
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002
"#,
            addr2
        ),
    )
    .expect("Failed to write config");

    // Start FeBGP daemon
    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon",
            "-c",
            &config_path,
            "--socket",
            &socket_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for session to establish and routes to be announced
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check if GoBGP received the IPv4 routes
    let gobgp_routes_v4 = gobgp2.get_routes_v4();
    println!("GoBGP IPv4 RIB:\n{}", gobgp_routes_v4);

    let has_route_v4_1 = gobgp2.has_prefix_v4("10.99.0.0/24");
    let has_route_v4_2 = gobgp2.has_prefix_v4("10.99.1.0/24");

    // Check if GoBGP received the IPv6 route
    let gobgp_routes_v6 = gobgp2.get_routes();
    println!("GoBGP IPv6 RIB:\n{}", gobgp_routes_v6);

    let has_route_v6 = gobgp2.has_prefix("2001:db8:99::/48");

    // Show neighbor summary for debugging
    println!("GoBGP neighbor summary:\n{}", gobgp2.get_neighbor_summary());

    // Kill daemon and clean up
    let _ = daemon.kill();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // Verify routes
    assert!(
        has_route_v4_1,
        "GoBGP did not receive IPv4 prefix 10.99.0.0/24 from FeBGP. Routes:\n{}",
        gobgp_routes_v4
    );
    assert!(
        has_route_v4_2,
        "GoBGP did not receive IPv4 prefix 10.99.1.0/24 from FeBGP. Routes:\n{}",
        gobgp_routes_v4
    );
    assert!(
        has_route_v6,
        "GoBGP did not receive IPv6 prefix 2001:db8:99::/48 from FeBGP. Routes:\n{}",
        gobgp_routes_v6
    );

    println!("GoBGP receives routes from FeBGP daemon test passed!");
}

/// Test that routes are withdrawn when a link goes down and re-installed when it comes back up.
///
/// This test simulates a link flap scenario:
/// 1. Establish BGP session and receive routes
/// 2. Bring the link down (simulating cable disconnect)
/// 3. Verify routes are withdrawn from the kernel
/// 4. Bring the link back up
/// 5. Verify the BGP session re-establishes and routes are re-installed
#[test]
fn test_febgp_link_flap_route_recovery() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_lf1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_lf2").expect("Failed to create namespace r2");

    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    std::thread::sleep(std::time::Duration::from_secs(2));

    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    println!("FeBGP (ns1) link-local: {}", addr1);
    println!("GoBGP (ns2) link-local: {}", addr2);

    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    let gobgp = GobgpInstance::start(&ns2, &config2, 50110).expect("Failed to start GoBGP");

    std::thread::sleep(std::time::Duration::from_secs(1));

    gobgp
        .announce_prefix_v4("10.80.0.0/24")
        .expect("Failed to announce prefix");

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_link_flap_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_link_flap_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []
ipv4_unicast = true

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002
"#,
            addr2
        ),
    )
    .expect("Failed to write config");

    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon",
            "-c",
            &config_path,
            "--socket",
            &socket_path,
            "--install-routes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for session to establish and routes to be installed
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Verify routes are installed before link down
    let route_before = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            "ip",
            "route",
            "show",
            "10.80.0.0/24",
        ])
        .output()
        .expect("Failed to run ip route show");

    let route_before_stdout = String::from_utf8_lossy(&route_before.stdout);
    println!("Route BEFORE link down:\n{}", route_before_stdout);

    assert!(
        route_before_stdout.contains("10.80.0.0/24"),
        "Route should be installed before link down. Got:\n{}",
        route_before_stdout
    );

    // === LINK DOWN ===
    println!("\n=== Bringing link DOWN ===");
    let link_down = Command::new("ip")
        .args(["netns", "exec", &ns1.name, "ip", "link", "set", "eth0", "down"])
        .status()
        .expect("Failed to bring link down");
    assert!(link_down.success(), "Failed to bring link down");

    // Wait for TCP connection to fail and routes to be withdrawn
    // The hold timer is typically 90 seconds, but TCP will fail faster
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Verify routes are removed after link down
    let route_during_down = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            "ip",
            "route",
            "show",
            "10.80.0.0/24",
        ])
        .output()
        .expect("Failed to run ip route show");

    let route_during_down_stdout = String::from_utf8_lossy(&route_during_down.stdout);
    println!("Route DURING link down:\n{}", route_during_down_stdout);

    assert!(
        route_during_down_stdout.trim().is_empty()
            || !route_during_down_stdout.contains("10.80.0.0/24"),
        "Route should be removed during link down. Got:\n{}",
        route_during_down_stdout
    );

    // === LINK UP ===
    println!("\n=== Bringing link UP ===");
    let link_up = Command::new("ip")
        .args(["netns", "exec", &ns1.name, "ip", "link", "set", "eth0", "up"])
        .status()
        .expect("Failed to bring link up");
    assert!(link_up.success(), "Failed to bring link up");

    // Wait for link-local address to be available again (DAD)
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Debug: Check link-local addresses after link up
    let addr1_after = wait_for_link_local(&ns1, "eth0");
    let addr2_after = wait_for_link_local(&ns2, "eth0");
    println!(
        "Link-local addresses after link up - ns1: {:?}, ns2: {:?}",
        addr1_after, addr2_after
    );

    // Debug: Check GoBGP neighbor state
    println!("GoBGP neighbor state after link up:");
    println!("{}", gobgp.get_neighbor_summary());

    // Wait for BGP session re-establishment and route installation
    // Poll for the route to appear (with timeout)
    let mut route_reinstalled = false;
    for attempt in 1..=15 {
        let route_check = Command::new("ip")
            .args([
                "netns",
                "exec",
                &ns1.name,
                "ip",
                "route",
                "show",
                "10.80.0.0/24",
            ])
            .output()
            .expect("Failed to run ip route show");

        let route_check_stdout = String::from_utf8_lossy(&route_check.stdout);
        if route_check_stdout.contains("10.80.0.0/24") {
            println!(
                "Route re-installed after {} seconds:\n{}",
                attempt * 2,
                route_check_stdout
            );
            route_reinstalled = true;
            break;
        }
        // Show GoBGP state every 5 attempts
        if attempt % 5 == 0 {
            println!("GoBGP state at attempt {}:", attempt);
            println!("{}", gobgp.get_neighbor_summary());
        }
        println!("Attempt {}/15: Route not yet re-installed, waiting...", attempt);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // Verify routes are re-installed after link up
    let route_after = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            "ip",
            "route",
            "show",
            "10.80.0.0/24",
        ])
        .output()
        .expect("Failed to run ip route show");

    let route_after_stdout = String::from_utf8_lossy(&route_after.stdout);
    if !route_reinstalled {
        println!("Route AFTER link up (final check):\n{}", route_after_stdout);
    }

    // Capture daemon output before cleanup
    let _ = daemon.kill();
    let output = daemon.wait_with_output();
    if let Ok(out) = output {
        println!("FeBGP daemon stdout:\n{}", String::from_utf8_lossy(&out.stdout));
        println!("FeBGP daemon stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);
    drop(gobgp);

    // Final assertion
    assert!(
        route_after_stdout.contains("10.80.0.0/24"),
        "Route should be re-installed after link up. Got:\n{}",
        route_after_stdout
    );

    println!("Link flap route recovery test passed!");
}

/// Test that FeBGP installs IPv6 routes into the Linux routing table when --install-routes is set.
/// This specifically tests the IPv6-prefix-with-IPv6-link-local-next-hop code path.
#[test]
fn test_febgp_install_routes_ipv6() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_v6ir1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_v6ir2").expect("Failed to create namespace r2");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD to complete
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    // Configure GoBGP
    let config2 = GobgpConfig {
        asn: 65002,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr1),
            local_address: format!("{}%eth0", addr2),
            remote_asn: 65001,
        }],
    };

    // Start GoBGP
    let gobgp = GobgpInstance::start(&ns2, &config2, 50111).expect("Failed to start GoBGP");

    // Give GoBGP time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Have GoBGP announce an IPv6 prefix (this is the key difference from test_febgp_install_routes)
    gobgp.announce_prefix("2001:db8:99::/48").expect("Failed to announce IPv6 prefix");

    // Create FeBGP config - note: NO ipv4_unicast, just default IPv6
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config_path = format!("/tmp/febgp_install_v6_test_{}.toml", std::process::id());
    let socket_path = format!("/tmp/febgp_install_v6_test_{}.sock", std::process::id());

    std::fs::write(
        &config_path,
        format!(
            r#"asn = 65001
router_id = "1.1.1.1"
prefixes = []

[[peer]]
interface = "eth0"
address = "{}%eth0"
remote_asn = 65002
"#,
            addr2
        ),
    )
    .expect("Failed to write config");

    // Start FeBGP daemon WITH --install-routes flag
    let febgp_binary = workspace_root.join("target/debug/febgp");
    let mut daemon = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "daemon",
            "-c",
            &config_path,
            "--socket",
            &socket_path,
            "--install-routes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start FeBGP daemon");

    // Wait for session to establish and routes to be received and installed
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Check the Linux routing table in ns1 for IPv6 routes
    let route_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            "ip",
            "-6",
            "route",
            "show",
            "2001:db8:99::/48",
        ])
        .output()
        .expect("Failed to run ip -6 route show");

    let route_stdout = String::from_utf8_lossy(&route_output.stdout);
    let route_stderr = String::from_utf8_lossy(&route_output.stderr);
    println!("Linux IPv6 routing table:\n{}", route_stdout);
    if !route_stderr.is_empty() {
        println!("Route stderr:\n{}", route_stderr);
    }

    // Also check FeBGP RIB for comparison
    let routes_output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns1.name,
            febgp_binary.to_str().unwrap(),
            "routes",
            "-s",
            &socket_path,
        ])
        .output()
        .expect("Failed to run febgp routes");

    let routes_stdout = String::from_utf8_lossy(&routes_output.stdout);
    println!("FeBGP RIB:\n{}", routes_stdout);

    // Capture daemon output for debugging
    let _ = daemon.kill();
    let output = daemon.wait_with_output();
    if let Ok(out) = output {
        let stderr = String::from_utf8_lossy(&out.stderr);
        println!("FeBGP daemon stderr:\n{}", stderr);
        // Check for route installation errors
        if stderr.contains("Failed to install route") {
            println!("WARNING: Route installation errors detected in daemon output!");
        }
    }

    // Clean up config
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&socket_path);

    // Verify the route is in the Linux routing table
    assert!(
        route_stdout.contains("2001:db8:99::/48"),
        "Route 2001:db8:99::/48 should be installed in Linux routing table. Got:\n{}",
        route_stdout
    );

    // The route should point to the link-local next-hop via eth0
    assert!(
        route_stdout.contains("dev eth0"),
        "Route should be via eth0. Got:\n{}",
        route_stdout
    );

    println!("IPv6 route installation test passed!");
}
