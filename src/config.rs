use serde::Deserialize;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    #[serde(default)]
    pub prefixes: Vec<String>,
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// Interface name for link-local peering (required)
    pub interface: String,
    /// Remote ASN - if not specified, learned from peer's OPEN message (BGP unnumbered)
    pub remote_asn: Option<u32>,
    /// Explicit peer address - if not specified, uses neighbor discovery
    pub address: Option<String>,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// BGP port number.
const BGP_PORT: u16 = 179;

/// Parse peer address from configuration.
///
/// Supports:
/// - Plain IP addresses (e.g., "192.0.2.1", "2001:db8::1")
/// - IPv6 with scope ID (e.g., "fe80::1%eth0")
pub fn parse_peer_address(peer: &PeerConfig) -> Result<SocketAddr, String> {
    if let Some(addr_str) = &peer.address {
        // Explicit address provided
        if let Ok(addr) = addr_str.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(addr, BGP_PORT));
        }

        // Try parsing as IPv6 with scope ID (fe80::1%eth0 format)
        if let Some((ip_part, scope_part)) = addr_str.split_once('%') {
            let ip: Ipv6Addr = ip_part
                .parse()
                .map_err(|e| format!("Invalid IPv6 address: {}", e))?;
            let scope_id = get_interface_index(scope_part)
                .ok_or_else(|| format!("Unknown interface: {}", scope_part))?;
            return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip, BGP_PORT, 0, scope_id,
            )));
        }

        return Err(format!("Invalid address format: {}", addr_str));
    }

    // No address specified - for now, require explicit address
    // TODO: Implement neighbor discovery for link-local peering
    Err("No peer address specified and neighbor discovery not yet implemented".to_string())
}

/// Get interface index by name.
pub fn get_interface_index(name: &str) -> Option<u32> {
    nix::net::if_::if_nametoindex(name).ok()
}
