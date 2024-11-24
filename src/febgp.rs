use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use log::*;
use zettabgp::prelude::*;
use std::str::FromStr;
use tokio::task::JoinHandle;
use crate::session::BgpSession;


/// BGP Daemon is the FeBGP daemon. It's the best.
pub struct BgpDaemon {
    params: BgpSessionParams,
    session_handles: Vec<JoinHandle<()>>,
}

impl BgpDaemon {
    pub fn new(as_number: u32, hold_time: u16, router_id: Ipv4Addr) -> BgpDaemon {
        let asn: u32;
        if as_number > 2^16 - 1 {
            asn = 23456;
        } else {
            asn = as_number;
        }

        let params = BgpSessionParams::new(
            asn,
            hold_time,
            BgpTransportMode::IPv6,
            router_id,
            vec![
                BgpCapability::SafiIPv6u,
                BgpCapability::CapASN32(as_number),
            ].into_iter().collect()
        );

        BgpDaemon{
            params: params,
            session_handles: vec![]
        }
    }

    pub fn add_neighbor(self: &mut Self, peer: BgpPeer) {
        let (tx, rx) = std::sync::mpsc::channel();
        let params = self.params.clone();

        tokio::spawn(async move {
            BgpSession::new(params, rx, tx, peer).start().await.unwrap();
        });

        //self.session_handles.push(handle);
    }

    pub fn announce(self: &mut Self, prefix: Prefix) {
        info!("announcing {}", prefix);
    }

    pub fn shutdown(self) {
        for handle in self.session_handles {
            handle.abort();
        }
    }
}


/// Represents a BGP peer, which can be an interface or an IP address (IPv4/IPv6).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BgpPeer {
    Interface(String),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
}


#[derive(Debug, PartialEq)]
pub enum Prefix {
    V4(Ipv4Addr, u8), // Holds an IPv4 address and prefix length
    V6(Ipv6Addr, u8), // Holds an IPv6 address and prefix length
}

impl FromStr for Prefix {
    type Err = String; // Error type for parsing

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split the string into address and prefix parts
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid prefix format. Expected <IP>/<prefix_length>".to_string());
        }

        let addr = parts[0];
        let prefix_length: u8 = parts[1]
            .parse()
            .map_err(|_| "Invalid prefix length".to_string())?;

        if let Ok(ipv4) = addr.parse::<Ipv4Addr>() {
            // IPv4 case
            if prefix_length > 32 {
                return Err("IPv4 prefix length cannot exceed 32".to_string());
            }
            Ok(Prefix::V4(ipv4, prefix_length))
        } else if let Ok(ipv6) = addr.parse::<Ipv6Addr>() {
            // IPv6 case
            if prefix_length > 128 {
                return Err("IPv6 prefix length cannot exceed 128".to_string());
            }
            Ok(Prefix::V6(ipv6, prefix_length))
        } else {
            Err("Invalid IP address".to_string())
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Prefix::V4(addr, length) => write!(f, "{}/{}", addr, length),
            Prefix::V6(addr, length) => write!(f, "{}/{}", addr, length),
        }
    }
}
