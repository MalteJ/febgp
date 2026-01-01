use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Child;

use super::netns::NetNs;

// Path to gobgp binaries (from workspace root tools/ directory)
const GOBGPD_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/gobgpd");
const GOBGP_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/gobgp");

/// Configuration for a GoBGP instance
pub struct GobgpConfig {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub listen_port: u16,
    pub neighbors: Vec<GobgpNeighbor>,
}

/// A BGP neighbor using link-local address
pub struct GobgpNeighbor {
    pub address: String,       // Link-local address with interface (e.g., "fe80::1%eth0")
    pub local_address: String, // Our link-local address with interface
    pub remote_asn: u32,
}

impl GobgpConfig {
    /// Generate the GoBGP TOML configuration
    pub fn generate(&self) -> String {
        let mut config = String::new();

        // Global configuration
        config.push_str("[global.config]\n");
        config.push_str(&format!("  as = {}\n", self.asn));
        config.push_str(&format!("  router-id = \"{}\"\n", self.router_id));
        config.push_str(&format!("  port = {}\n", self.listen_port));
        config.push('\n');

        // Neighbors
        for neighbor in &self.neighbors {
            config.push_str("[[neighbors]]\n");
            config.push_str("  [neighbors.config]\n");
            config.push_str(&format!("    neighbor-address = \"{}\"\n", neighbor.address));
            config.push_str(&format!("    peer-as = {}\n", neighbor.remote_asn));
            config.push_str("  [neighbors.transport.config]\n");
            config.push_str(&format!("    local-address = \"{}\"\n", neighbor.local_address));
            config.push_str("  [[neighbors.afi-safis]]\n");
            config.push_str("    [neighbors.afi-safis.config]\n");
            config.push_str("      afi-safi-name = \"ipv4-unicast\"\n");
            config.push_str("  [[neighbors.afi-safis]]\n");
            config.push_str("    [neighbors.afi-safis.config]\n");
            config.push_str("      afi-safi-name = \"ipv6-unicast\"\n");
            config.push('\n');
        }

        config
    }
}

/// A running GoBGP instance
pub struct GobgpInstance {
    #[allow(dead_code)]
    config_dir: PathBuf,
    gobgpd: Child,
    ns_name: String,
    api_port: u16,
}

impl GobgpInstance {
    /// Start GoBGP in the given namespace with the given config
    pub fn start(ns: &NetNs, config: &GobgpConfig, api_port: u16) -> io::Result<Self> {
        let config_dir = ns.run_dir_path();
        let config_content = config.generate();

        // Write the config file
        let config_path = config_dir.join("gobgpd.conf");
        fs::write(&config_path, &config_content)?;

        // Start gobgpd
        let gobgpd = ns.spawn(
            GOBGPD_PATH,
            &[
                "-f", config_path.to_str().unwrap(),
                "-l", "debug",
                "-a", &format!(":{}", api_port),
            ],
        )?;

        // Give gobgpd time to start
        std::thread::sleep(std::time::Duration::from_millis(500));

        Ok(Self {
            config_dir,
            gobgpd,
            ns_name: ns.name.clone(),
            api_port,
        })
    }

    /// Run gobgp command and return output
    pub fn gobgp(&self, args: &[&str]) -> io::Result<String> {
        let api_addr = format!("127.0.0.1:{}", self.api_port);
        let mut all_args = vec![
            "netns", "exec", &self.ns_name,
            GOBGP_PATH, "-a", &api_addr,
        ];
        all_args.extend(args);

        let output = std::process::Command::new("ip")
            .args(&all_args)
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !stderr.is_empty() && !stdout.is_empty() {
            Ok(format!("{}\n{}", stdout, stderr))
        } else if !stdout.is_empty() {
            Ok(stdout)
        } else {
            Ok(stderr)
        }
    }

    /// Check if any BGP neighbor is established
    /// Session states: 1=Idle, 2=Connect, 3=Active, 4=OpenSent, 5=OpenConfirm, 6=Established
    #[allow(dead_code)]
    pub fn is_neighbor_established(&self) -> bool {
        if let Ok(output) = self.gobgp(&["neighbor", "-j"]) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output) {
                if let Some(neighbors) = json.as_array() {
                    for neighbor in neighbors {
                        if let Some(state) = neighbor.get("state")
                            .and_then(|s| s.get("session_state"))
                            .and_then(|s| s.as_u64())
                        {
                            if state == 6 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a prefix is received from BGP
    #[allow(dead_code)]
    pub fn has_prefix(&self, prefix: &str) -> bool {
        if let Ok(output) = self.gobgp(&["global", "rib", "-a", "ipv6", "-j"]) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output) {
                // RIB JSON is an object with prefixes as keys
                if let Some(routes) = json.as_object() {
                    return routes.contains_key(prefix);
                }
            }
        }
        false
    }

    /// Announce an IPv6 prefix
    #[allow(dead_code)]
    pub fn announce_prefix(&self, prefix: &str) -> io::Result<()> {
        self.gobgp(&["global", "rib", "add", prefix, "-a", "ipv6"])?;
        Ok(())
    }

    /// Announce an IPv4 prefix
    #[allow(dead_code)]
    pub fn announce_prefix_v4(&self, prefix: &str) -> io::Result<()> {
        self.gobgp(&["global", "rib", "add", prefix, "-a", "ipv4"])?;
        Ok(())
    }

    /// Check if an IPv4 prefix is received from BGP
    #[allow(dead_code)]
    pub fn has_prefix_v4(&self, prefix: &str) -> bool {
        if let Ok(output) = self.gobgp(&["global", "rib", "-a", "ipv4", "-j"]) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output) {
                if let Some(routes) = json.as_object() {
                    return routes.contains_key(prefix);
                }
            }
        }
        false
    }

    /// Get neighbor summary for debugging
    pub fn get_neighbor_summary(&self) -> String {
        self.gobgp(&["neighbor"]).unwrap_or_default()
    }

    /// Get detailed neighbor info for a specific AFI
    #[allow(dead_code)]
    pub fn get_neighbor_afi(&self, neighbor: &str, afi: &str) -> String {
        self.gobgp(&["neighbor", neighbor, "-a", afi]).unwrap_or_default()
    }

    /// Get received route count for a neighbor on a specific AFI
    #[allow(dead_code)]
    pub fn get_neighbor_received_count(&self, afi: &str) -> Option<u64> {
        if let Ok(output) = self.gobgp(&["neighbor", "-a", afi, "-j"]) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output) {
                if let Some(neighbors) = json.as_array() {
                    if let Some(first) = neighbors.first() {
                        return first.get("state")
                            .and_then(|s| s.get("adj_rib_in_count"))
                            .and_then(|c| c.as_u64());
                    }
                }
            }
        }
        None
    }

    /// Get IPv6 routes for debugging
    #[allow(dead_code)]
    pub fn get_routes(&self) -> String {
        self.gobgp(&["global", "rib", "-a", "ipv6"]).unwrap_or_default()
    }

    /// Get IPv4 routes for debugging
    #[allow(dead_code)]
    pub fn get_routes_v4(&self) -> String {
        self.gobgp(&["global", "rib", "-a", "ipv4"]).unwrap_or_default()
    }
}

impl Drop for GobgpInstance {
    fn drop(&mut self) {
        let _ = self.gobgpd.kill();
        let _ = self.gobgpd.wait();
    }
}

/// Get the link-local address of an interface in a namespace
pub fn get_link_local_address(ns: &NetNs, interface: &str) -> io::Result<String> {
    let output = std::process::Command::new("ip")
        .args([
            "netns", "exec", &ns.name,
            "ip", "-6", "addr", "show", "dev", interface, "scope", "link",
        ])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output like: "inet6 fe80::1/64 scope link"
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("inet6 ") {
            if let Some(addr) = line.strip_prefix("inet6 ") {
                if let Some(addr) = addr.split('/').next() {
                    if let Some(addr) = addr.split_whitespace().next() {
                        return Ok(addr.to_string());
                    }
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("No link-local address found on {}", interface),
    ))
}
