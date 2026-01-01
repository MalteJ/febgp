use serde::Deserialize;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
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

#[derive(Debug, Deserialize)]
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
