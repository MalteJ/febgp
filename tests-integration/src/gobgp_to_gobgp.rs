mod common;

use std::net::Ipv4Addr;

use common::gobgp::{get_link_local_address, GobgpConfig, GobgpInstance, GobgpNeighbor};
use common::netns::{create_veth_pair, wait_for, NetNs};

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Test that two GoBGP instances can establish a BGP session using link-local addresses
/// and exchange IPv6 prefixes.
///
/// This test requires root privileges to create network namespaces.
/// Run with: sudo cargo test --test gobgp_to_gobgp
#[test]
fn test_gobgp_to_gobgp_link_local() {
    if !is_root() {
        eprintln!("Skipping test: requires root (run with sudo)");
        return;
    }

    // Create two network namespaces
    let ns1 = NetNs::new("febgp_test_r1").expect("Failed to create namespace r1");
    let ns2 = NetNs::new("febgp_test_r2").expect("Failed to create namespace r2");

    // Create a veth pair between them
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").expect("Failed to create veth pair");

    // Wait for DAD (Duplicate Address Detection) to complete
    // IPv6 link-local addresses are in "tentative" state for ~1-2 seconds
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Get link-local addresses
    let addr1 = wait_for_link_local(&ns1, "eth0").expect("Failed to get link-local for r1");
    let addr2 = wait_for_link_local(&ns2, "eth0").expect("Failed to get link-local for r2");

    println!("R1 link-local: {}", addr1);
    println!("R2 link-local: {}", addr2);

    // Configure GoBGP on router 1
    // Neighbor address needs zone ID for link-local
    let config1 = GobgpConfig {
        asn: 65001,
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        listen_port: 179,
        neighbors: vec![GobgpNeighbor {
            address: format!("{}%eth0", addr2),
            local_address: format!("{}%eth0", addr1),
            remote_asn: 65002,
        }],
    };

    // Configure GoBGP on router 2
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

    // Start GoBGP instances
    let gobgp1 = GobgpInstance::start(&ns1, &config1, 50051).expect("Failed to start GoBGP on r1");
    let gobgp2 = GobgpInstance::start(&ns2, &config2, 50052).expect("Failed to start GoBGP on r2");

    // Give them time to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Debug: show initial state
    println!("=== Initial R1 neighbors ===");
    println!("{}", gobgp1.get_neighbor_summary());
    println!("=== Initial R2 neighbors ===");
    println!("{}", gobgp2.get_neighbor_summary());

    // Wait for BGP session to establish
    let established = wait_for(
        || gobgp1.is_neighbor_established() && gobgp2.is_neighbor_established(),
        30,  // timeout in seconds
        500, // poll interval in ms
    );

    if !established {
        eprintln!("=== R1 Neighbor Summary ===");
        eprintln!("{}", gobgp1.get_neighbor_summary());
        eprintln!("=== R2 Neighbor Summary ===");
        eprintln!("{}", gobgp2.get_neighbor_summary());
        panic!("BGP session did not establish within timeout");
    }

    println!("BGP session established!");

    // Announce prefixes
    gobgp1.announce_prefix("2001:db8:1::/48").expect("Failed to announce prefix on r1");
    gobgp2.announce_prefix("2001:db8:2::/48").expect("Failed to announce prefix on r2");

    // Wait for prefix exchange
    let prefixes_exchanged = wait_for(
        || gobgp1.has_prefix("2001:db8:2::/48") && gobgp2.has_prefix("2001:db8:1::/48"),
        10,  // timeout in seconds
        500, // poll interval in ms
    );

    if !prefixes_exchanged {
        eprintln!("=== R1 Routes ===");
        eprintln!("{}", gobgp1.get_routes());
        eprintln!("=== R2 Routes ===");
        eprintln!("{}", gobgp2.get_routes());
        panic!("Prefixes were not exchanged within timeout");
    }

    println!("Prefixes exchanged successfully!");
    println!("=== R1 Routes ===");
    println!("{}", gobgp1.get_routes());
    println!("=== R2 Routes ===");
    println!("{}", gobgp2.get_routes());
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
