mod febgp;
mod session;

use simple_logger::SimpleLogger;
use log::*;
use clap::Parser;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use thiserror::Error;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Autonomous system number
    #[arg(long)]
    asn: u32,

    /// Hold time in seconds (default: 30)
    #[arg(long, default_value_t = 30)]
    hold_time: u16,

    /// Router ID as an IPv4 address
    #[arg(long)]
    router_id: Ipv4Addr,

    /// BGP neighbors
    #[arg(long = "neighbor", value_name = "NEIGHBOR", action = clap::ArgAction::Append)]
    neighbors: Vec<febgp::BgpPeer>,
}

#[derive(Error, Debug)]
pub enum ParseBgpPeerError {
    #[error("Invalid IPv4 address")]
    InvalidIpv4Address,
    #[error("Invalid IPv6 address")]
    InvalidIpv6Address,
    #[error("Invalid format for peer; expected 'interface:<name>', IPv4, or IPv6 address")]
    InvalidFormat,
}

impl FromStr for febgp::BgpPeer {
    type Err = ParseBgpPeerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(interface) = s.strip_prefix("interface:") {
            return Ok(febgp::BgpPeer::Interface(interface.to_string()));
        }

        if let Ok(ipv4) = s.parse::<Ipv4Addr>() {
            return Ok(febgp::BgpPeer::Ipv4Address(ipv4));
        }

        if let Ok(ipv6) = s.parse::<Ipv6Addr>() {
            return Ok(febgp::BgpPeer::Ipv6Address(ipv6));
        }

        Err(ParseBgpPeerError::InvalidFormat)
    }
}

#[tokio::main]
async fn main() {
    SimpleLogger::new().env().init().unwrap();
    info!("FeBGP starting...");

    let args = Args::parse();

    info!("Neighbors: {:?}", args.neighbors);
    info!("AS Number: {}", args.asn);
    info!("Hold Time: {} seconds", args.hold_time);
    info!("Router ID: {}", args.router_id);

    let mut febgp = febgp::BgpDaemon::new(args.asn, args.hold_time, args.router_id);

    for neighbor in args.neighbors {
        febgp.add_neighbor(neighbor);
    }

    febgp.announce("2001:db8:1::/64".parse().unwrap());
    febgp.announce("192.168.0.0/16".parse().unwrap());

    tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
    info!("Shutting down FeBGP...");

    febgp.shutdown();
}
