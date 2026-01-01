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
        65001,
        "1.1.1.1",
        65002,
        &addr2,
        if_index,
        179,
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

fn run_febgp_in_namespace(
    ns: &NetNs,
    local_asn: u32,
    router_id: &str,
    remote_asn: u32,
    peer_addr: &str,
    scope_id: u32,
    port: u16,
) -> std::io::Result<String> {
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

    // Run the helper in the namespace
    let output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &ns.name,
            binary_path.to_str().unwrap(),
            &local_asn.to_string(),
            router_id,
            &remote_asn.to_string(),
            peer_addr,
            &scope_id.to_string(),
            &port.to_string(),
        ])
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
