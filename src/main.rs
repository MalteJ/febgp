mod bgp;

use simple_logger::SimpleLogger;
use log::*;
use clap::Parser;
use std::net::Ipv4Addr;
use std::rc::Rc;

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
    neighbors: Vec<bgp::BgpPeer>,
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

    let mut bgp_daemon = Rc::new(bgp::BgpDaemon::new(args.asn, args.hold_time, args.router_id));

    for neighbor in args.neighbors {
        bgp_daemon.add_neighbor(neighbor);
    }
}
