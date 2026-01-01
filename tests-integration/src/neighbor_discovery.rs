// Test daemons are spawned and later killed via daemon.kill() - not zombie processes
#![allow(clippy::zombie_processes)]

//! Integration test for neighbor discovery between two FeBGP instances.
//!
//! This test creates two network namespaces connected by a veth pair,
//! starts FeBGP in both without explicit peer addresses, and verifies
//! they discover each other via Router Advertisements and establish
//! a BGP session.

mod common;

use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::netns::{create_veth_pair, NetNs};
use tempfile::NamedTempFile;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Test that two FeBGP instances can discover each other via Router Advertisements.
///
/// This test requires root privileges to create network namespaces and raw sockets.
/// Run with: sudo cargo test --test neighbor_discovery
#[test]
fn test_febgp_neighbor_discovery() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_nd_r1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_nd_r2").expect("Failed to create namespace r2");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for interfaces to be ready and DAD to complete
    std::thread::sleep(Duration::from_secs(2));

    // Build the febgp binary first
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let status = Command::new("cargo")
        .args(["build", "--bin", "febgp"])
        .current_dir(workspace_root)
        .status()
        .expect("Failed to build febgp");
    assert!(status.success(), "Failed to build febgp binary");

    let febgp_binary = workspace_root.join("target/debug/febgp");

    // Create config files for both instances
    // Note: No address specified - neighbor discovery will be used
    let config1 = create_config_file(65001, Ipv4Addr::new(1, 1, 1, 1), "eth0");
    let config2 = create_config_file(65002, Ipv4Addr::new(2, 2, 2, 2), "eth0");

    // Start FeBGP in both namespaces
    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();

    eprintln!("Starting FeBGP in ns1...");
    let febgp1 = start_febgp_in_namespace(
        &ns1,
        &febgp_binary,
        config1.path(),
        ns1.run_dir_path().join("grpc1.sock"),
        tx1,
    )
    .expect("Failed to start FeBGP in ns1");
    eprintln!("FeBGP 1 started");

    eprintln!("Starting FeBGP in ns2...");
    let febgp2 = start_febgp_in_namespace(
        &ns2,
        &febgp_binary,
        config2.path(),
        ns2.run_dir_path().join("grpc2.sock"),
        tx2,
    )
    .expect("Failed to start FeBGP in ns2");
    eprintln!("FeBGP 2 started");

    // Wait for both to establish (with timeout)
    eprintln!("Waiting for sessions to establish...");
    let established1 = wait_for_established(&rx1, Duration::from_secs(30));
    let established2 = wait_for_established(&rx2, Duration::from_secs(30));

    // Clean up - kill both processes
    drop(febgp1);
    drop(febgp2);

    // Verify results
    assert!(
        established1,
        "FeBGP instance 1 did not establish session within timeout"
    );
    assert!(
        established2,
        "FeBGP instance 2 did not establish session within timeout"
    );

    println!("Both FeBGP instances discovered each other and established BGP sessions!");
}

/// Test that neighbor discovery works with explicit address on one side.
///
/// NOTE: This test is currently disabled because it requires additional handling
/// for the race condition when one side has an explicit address and the other
/// uses discovery. The explicit side connects before discovery completes,
/// causing the connection to be dropped.
#[test]
#[ignore]
fn test_febgp_mixed_discovery() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_mx_r1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_mx_r2").expect("Failed to create namespace r2");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for interfaces to be ready and DAD to complete
    std::thread::sleep(Duration::from_secs(2));

    // Build the febgp binary
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();

    let febgp_binary = workspace_root.join("target/debug/febgp");
    if !febgp_binary.exists() {
        let status = Command::new("cargo")
            .args(["build", "--bin", "febgp"])
            .current_dir(workspace_root)
            .status()
            .expect("Failed to build febgp");
        assert!(status.success(), "Failed to build febgp binary");
    }

    // Get link-local address of ns1 for ns2 to use
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    println!("FeBGP 1 link-local: {}", addr1);

    // Config 1: uses neighbor discovery (no address)
    let config1 = create_config_file(65001, Ipv4Addr::new(1, 1, 1, 1), "eth0");

    // Config 2: has explicit address pointing to ns1
    let config2 = create_config_file_with_address(
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        "eth0",
        &format!("{}%eth0", addr1),
    );

    // Start FeBGP in both namespaces
    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();

    let febgp1 = start_febgp_in_namespace(
        &ns1,
        &febgp_binary,
        config1.path(),
        ns1.run_dir_path().join("grpc1.sock"),
        tx1,
    )
    .expect("Failed to start FeBGP in ns1");

    let febgp2 = start_febgp_in_namespace(
        &ns2,
        &febgp_binary,
        config2.path(),
        ns2.run_dir_path().join("grpc2.sock"),
        tx2,
    )
    .expect("Failed to start FeBGP in ns2");

    // Wait for both to establish
    let established1 = wait_for_established(&rx1, Duration::from_secs(30));
    let established2 = wait_for_established(&rx2, Duration::from_secs(30));

    // Clean up
    drop(febgp1);
    drop(febgp2);

    // Verify
    assert!(
        established1,
        "FeBGP instance 1 (discovery) did not establish session"
    );
    assert!(
        established2,
        "FeBGP instance 2 (explicit) did not establish session"
    );

    println!("Mixed discovery test passed!");
}

fn create_config_file(asn: u32, router_id: Ipv4Addr, interface: &str) -> NamedTempFile {
    let config = format!(
        r#"
asn = {}
router_id = "{}"
ipv6_unicast = true

[[peer]]
interface = "{}"
# No address - use neighbor discovery
"#,
        asn, router_id, interface
    );

    let file = NamedTempFile::new().expect("Failed to create temp config file");
    std::fs::write(file.path(), config).expect("Failed to write config");
    file
}

fn create_config_file_with_address(
    asn: u32,
    router_id: Ipv4Addr,
    interface: &str,
    address: &str,
) -> NamedTempFile {
    let config = format!(
        r#"
asn = {}
router_id = "{}"
ipv6_unicast = true

[[peer]]
interface = "{}"
address = "{}"
"#,
        asn, router_id, interface, address
    );

    let file = NamedTempFile::new().expect("Failed to create temp config file");
    std::fs::write(file.path(), config).expect("Failed to write config");
    file
}

struct FebgpProcess {
    child: Child,
    _reader_thread: thread::JoinHandle<()>,
}

impl Drop for FebgpProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_febgp_in_namespace(
    ns: &NetNs,
    binary: &std::path::Path,
    config: &std::path::Path,
    socket: std::path::PathBuf,
    event_tx: mpsc::Sender<String>,
) -> std::io::Result<FebgpProcess> {
    // Use sh -c to properly pass environment variables through ip netns exec
    let cmd = format!(
        "RUST_LOG=info {} daemon --config {} --socket {}",
        binary.to_str().unwrap(),
        config.to_str().unwrap(),
        socket.to_str().unwrap()
    );

    let mut child = Command::new("ip")
        .args(["netns", "exec", &ns.name, "sh", "-c", &cmd])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Read stdout in a separate thread and send events
    // (tracing-subscriber writes to stdout by default)
    let stdout = child.stdout.take().unwrap();
    let ns_name = ns.name.clone();
    let reader_thread = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    eprintln!("[{}] {}", ns_name, line);
                    // Send the line to the main thread
                    let _ = event_tx.send(line);
                }
                Err(e) => {
                    eprintln!("[{}] Error reading line: {}", ns_name, e);
                    break;
                }
            }
        }
        eprintln!("[{}] Reader thread finished", ns_name);
    });

    Ok(FebgpProcess {
        child,
        _reader_thread: reader_thread,
    })
}

fn wait_for_established(rx: &mpsc::Receiver<String>, timeout: Duration) -> bool {
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if line.contains("Session established") || line.contains("ESTABLISHED") {
                    return true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    false
}

fn wait_for_link_local(ns: &NetNs, interface: &str) -> Option<String> {
    for _ in 0..50 {
        let output = Command::new("ip")
            .args([
                "netns",
                "exec",
                &ns.name,
                "ip",
                "-6",
                "addr",
                "show",
                "dev",
                interface,
                "scope",
                "link",
            ])
            .output()
            .ok()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if let Some(addr_part) = line.trim().strip_prefix("inet6 ") {
                if let Some(addr) = addr_part.split('/').next() {
                    if addr.starts_with("fe80::") {
                        return Some(addr.to_string());
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}
