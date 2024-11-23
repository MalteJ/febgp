use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
use std::sync::RwLock;
use log::*;
use zettabgp::prelude::*;
use std::str::FromStr;
use tokio::net::TcpSocket;
use std::io::{Read, Write};

const BGP_PORT: u16 = 179;

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


/// Represents a BGP peer, which can be an interface or an IP address (IPv4/IPv6).
#[derive(Debug, Clone)]
pub enum BgpPeer {
    Interface(String),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
}


#[derive(Debug, PartialEq)]
pub enum BgpState {
    /// The initial state where BGP is idle and not attempting to connect.
    Idle,

    /// BGP is attempting to establish a TCP connection.
    Connect,

    /// BGP actively retries to connect after a failed attempt.
    Active,

    /// BGP has sent an OPEN message and is waiting for a response.
    OpenSent,

    /// BGP has received a valid OPEN message and is waiting for KEEPALIVE.
    OpenConfirm,

    /// The BGP session is fully established, and routes are exchanged.
    Established,
}

struct BgpSession {
    remote: BgpPeer,
    socket: Option<TcpSocket>,
    params: BgpSessionParams,

    status: BgpState,
    connect_retry_counter: u32,
    connect_retry_timer: u32,
    connect_retry_time: u32,
    hold_timer: u32,
    hold_time: u32,
    keepalive_timer: u32,
    keepalive_time: u32,
}

impl BgpSession {
    fn start(&mut self) {
        self.status = BgpState::Connect;


        match TcpStream::connect(format!("{}:{}", "[2001:db8::1]", BGP_PORT)) {
            Ok(mut socket) => {
                let mut buf = [0 as u8; 32768];

                let open_my = self.params.open_message();
                let open_sz = open_my.encode_to(&self.params, &mut buf[19..]).unwrap();
                let to_send = self.params.prepare_message_buf(&mut buf, BgpMessageType::Open, open_sz).unwrap();

                socket.write_all(&buf[0..to_send]).unwrap();
                socket.read_exact(&mut buf[0..19]).unwrap();

                let message_head = self.params.decode_message_head(&buf).unwrap();
                if message_head.0 == BgpMessageType::Open {
                    socket.read_exact(&mut buf[0..message_head.1]).unwrap();
                    let mut bom = BgpOpenMessage::new();
                    bom.decode_from(&self.params, &buf[0..message_head.1]).unwrap();
                    info!("BGP Open message received: {:?}", bom);
                    info!("Connected to AS {}, hold-time: {}, router-id: {:?}, capabilities: {:?}",
                        bom.as_num,
                        bom.hold_time,
                        bom.router_id,
                        bom.caps);
                }
            }
            Err(_) => {
                error!("Failed to establish connection with {}", "2001:db8::1");
            }
        }
    }
}

pub(crate) struct BgpDaemon {
    params: BgpSessionParams,
    peers: RwLock<Vec<BgpSession>>
}

impl BgpDaemon {
    pub(crate) fn new(as_number: u32, hold_time: u16, router_id: Ipv4Addr) -> BgpDaemon {
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

        BgpDaemon{ params: params, peers: Default::default() }
    }

    fn get_as_number(&self) -> u32 {
        if self.params.as_num == 23456 {
            for cap in &self.params.caps {
                match cap {
                    BgpCapability::CapASN32(asn) => return *asn,
                    _ => continue,
                }
            }
        }

        self.params.as_num
    }

    fn get_hold_time(&self) -> u16 {
        self.params.hold_time
    }

    fn get_router_id(&self) -> Ipv4Addr {
        self.params.router_id
    }

    pub fn add_neighbor(self: &mut Self, peer: BgpPeer) {
        let mut session = BgpSession{
            params: self.params.clone(),
            remote: peer,
            status: BgpState::Idle,
            connect_retry_counter: 0,
            connect_retry_timer: 0,
            connect_retry_time: 0,
            hold_timer: 0,
            hold_time: 0,
            keepalive_timer: 0,
            socket: None,
            keepalive_time: 0,
        };

        std::thread::spawn( move || {
            session.start();
        });
    }

    pub fn announce(self: &mut Self, prefix: Prefix) {
        info!("announcing {}", prefix);
    }

    pub fn withdraw(self: &mut Self, prefix: Prefix) {
        info!("withdrawing {}", prefix);
    }

    pub fn shutdown(self) {
    }
}