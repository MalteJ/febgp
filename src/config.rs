use serde::Deserialize;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// Default BGP hold time in seconds (keepalive = hold_time / 3).
pub const DEFAULT_HOLD_TIME: u16 = 9;
/// Default connect retry timer in seconds.
pub const DEFAULT_CONNECT_RETRY_TIME: u64 = 30;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    #[serde(default)]
    pub prefixes: Vec<String>,
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerConfig>,
    /// BGP hold time in seconds (keepalive = hold_time / 3).
    /// Default: 9 seconds (keepalive = 3 seconds).
    #[serde(default = "default_hold_time")]
    pub hold_time: u16,
    /// Connect retry timer in seconds.
    /// Default: 30 seconds.
    #[serde(default = "default_connect_retry_time")]
    pub connect_retry_time: u64,
    /// Enable IPv4 unicast address family.
    /// Default: false (for BGP unnumbered compatibility).
    #[serde(default)]
    pub ipv4_unicast: bool,
    /// Enable IPv6 unicast address family.
    /// Default: true.
    #[serde(default = "default_true")]
    pub ipv6_unicast: bool,
    /// Install routes into Linux routing table via netlink.
    /// Default: false.
    #[serde(default)]
    pub install_routes: bool,
}

fn default_true() -> bool {
    true
}

fn default_hold_time() -> u16 {
    DEFAULT_HOLD_TIME
}

fn default_connect_retry_time() -> u64 {
    DEFAULT_CONNECT_RETRY_TIME
}

impl Default for Config {
    fn default() -> Self {
        Self {
            asn: 0,
            router_id: Ipv4Addr::new(0, 0, 0, 0),
            prefixes: Vec::new(),
            peers: Vec::new(),
            hold_time: DEFAULT_HOLD_TIME,
            connect_retry_time: DEFAULT_CONNECT_RETRY_TIME,
            ipv4_unicast: false,
            ipv6_unicast: true,
            install_routes: false,
        }
    }
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
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> io::Result<Self> {
        toml::from_str(content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// BGP port number.
const BGP_PORT: u16 = 179;

/// Parse peer address from configuration.
///
/// Supports:
/// - Plain IP addresses (e.g., "192.0.2.1", "2001:db8::1")
/// - IPv6 with scope ID (e.g., "fe80::1%eth0")
///
/// Returns:
/// - `Ok(Some(addr))` - explicit address configured
/// - `Ok(None)` - no address, use neighbor discovery
/// - `Err(e)` - invalid address format
pub fn parse_peer_address(peer: &PeerConfig) -> Result<Option<SocketAddr>, String> {
    if let Some(addr_str) = &peer.address {
        // Explicit address provided
        if let Ok(addr) = addr_str.parse::<std::net::IpAddr>() {
            return Ok(Some(SocketAddr::new(addr, BGP_PORT)));
        }

        // Try parsing as IPv6 with scope ID (fe80::1%eth0 format)
        if let Some((ip_part, scope_part)) = addr_str.split_once('%') {
            let ip: Ipv6Addr = ip_part
                .parse()
                .map_err(|e| format!("Invalid IPv6 address: {}", e))?;
            let scope_id = get_interface_index(scope_part)
                .ok_or_else(|| format!("Unknown interface: {}", scope_part))?;
            return Ok(Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip, BGP_PORT, 0, scope_id,
            ))));
        }

        return Err(format!("Invalid address format: {}", addr_str));
    }

    // No address specified - use neighbor discovery
    Ok(None)
}

/// Get interface index by name.
pub fn get_interface_index(name: &str) -> Option<u32> {
    nix::net::if_::if_nametoindex(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default_timers() {
        let config: Config = Config::parse(
            r#"
            asn = 65000
            router_id = "1.2.3.4"
            "#,
        )
        .unwrap();

        assert_eq!(config.hold_time, 9);
        assert_eq!(config.connect_retry_time, 30);
    }

    #[test]
    fn test_config_custom_timers() {
        let config: Config = Config::parse(
            r#"
            asn = 65000
            router_id = "1.2.3.4"
            hold_time = 90
            connect_retry_time = 120
            "#,
        )
        .unwrap();

        assert_eq!(config.hold_time, 90);
        assert_eq!(config.connect_retry_time, 120);
    }

    #[test]
    fn test_config_partial_timer_override() {
        let config: Config = Config::parse(
            r#"
            asn = 65000
            router_id = "1.2.3.4"
            hold_time = 15
            "#,
        )
        .unwrap();

        assert_eq!(config.hold_time, 15);
        assert_eq!(config.connect_retry_time, 30); // Default
    }

    #[test]
    fn test_config_timers_3_9() {
        // Test the "timers 3 9" equivalent config
        let config: Config = Config::parse(
            r#"
            asn = 65000
            router_id = "1.2.3.4"
            hold_time = 9
            "#,
        )
        .unwrap();

        assert_eq!(config.hold_time, 9);
        // Keepalive is hold_time / 3
        assert_eq!(config.hold_time / 3, 3);
    }

    #[test]
    fn test_config_with_peers_and_timers() {
        let config: Config = Config::parse(
            r#"
            asn = 65000
            router_id = "1.2.3.4"
            hold_time = 30
            connect_retry_time = 60

            [[peer]]
            interface = "eth0"
            address = "192.168.1.1"
            "#,
        )
        .unwrap();

        assert_eq!(config.hold_time, 30);
        assert_eq!(config.connect_retry_time, 60);
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].interface, "eth0");
    }
}
