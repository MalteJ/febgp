use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::sync::RwLock;
use log::*;
use zettabgp::prelude::*;
use std::str::FromStr;
use thiserror::Error;
use tokio::net::TcpSocket;

const BGP_PORT: u16 = 179;

/// Represents a BGP peer, which can be an interface or an IP address (IPv4/IPv6).
#[derive(Debug, Clone)]
pub enum BgpPeer {
    Interface(String),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
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

impl FromStr for BgpPeer {
    type Err = ParseBgpPeerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(interface) = s.strip_prefix("interface:") {
            return Ok(BgpPeer::Interface(interface.to_string()));
        }

        if let Ok(ipv4) = s.parse::<Ipv4Addr>() {
            return Ok(BgpPeer::Ipv4Address(ipv4));
        }

        if let Ok(ipv6) = s.parse::<Ipv6Addr>() {
            return Ok(BgpPeer::Ipv6Address(ipv6));
        }

        Err(ParseBgpPeerError::InvalidFormat)
    }
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
    daemon: Rc<BgpDaemon>,
    remote: BgpPeer,
    status: BgpState,
    socket: Option<TcpSocket>,
}

impl BgpSession {
    async fn start(&mut self) {
        self.status = BgpState::Connect;
        /*
        match TcpStream::connect(format!("{}:{}", peer, BGP_PORT)) {
            Ok(mut socket) => {
                let mut buf = [0 as u8; 32768];

                let open_my = self.params.open_message();
                let open_sz = open_my.encode_to(&self.params, &mut buf[19..]).unwrap();
                let to_send = params.prepare_message_buf(&mut buf, BgpMessageType::Open, open_sz).unwrap();

                socket.write_all(&buf[0..to_send]).unwrap();
                socket.read_exact(&mut buf[0..19]).unwrap();

                let message_head = params.decode_message_head(&buf).unwrap();
                if message_head.0 == BgpMessageType::Open {
                    socket.read_exact(&mut buf[0..message_head.1]).unwrap();
                    let mut bom = BgpOpenMessage::new();
                    bom.decode_from(&params, &buf[0..message_head.1]).unwrap();
                    info!("BGP Open message received: {:?}", bom);
                    info!("Connected to AS {}, hold-time: {}, router-id: {:?}, capabilities: {:?}",
                        bom.as_num,
                        bom.hold_time,
                        bom.router_id,
                        bom.caps);
                }
            }
            Err(_) => {
                error!("Failed to establish connection with {}", peer);
            }
        }
         */
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

    pub async fn add_neighbor(self: &mut Rc<Self>, peer: BgpPeer) {
        let mut vec = self.peers.write().expect("RwLock write lock poisoned");
        let mut session = BgpSession{
            daemon: Rc::clone(self),
            remote: peer,
            status: BgpState::Idle,
            socket: None,
        };
        session.start();
        vec.push(session);
    }
}