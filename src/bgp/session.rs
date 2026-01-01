use std::io::{self, BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream};
use std::time::Duration;

use socket2::{Domain, Socket, Type};

use super::message::{KeepaliveMessage, Message, OpenMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

pub struct Session {
    pub state: SessionState,
    pub local_asn: u32,
    pub remote_asn: u32,
    pub router_id: Ipv4Addr,
    pub hold_time: u16,
    stream: Option<TcpStream>,
}

impl Session {
    pub fn new(local_asn: u32, router_id: Ipv4Addr, remote_asn: u32) -> Self {
        Self {
            state: SessionState::Idle,
            local_asn,
            remote_asn,
            router_id,
            hold_time: 90,
            stream: None,
        }
    }

    /// Connect to a peer using IPv6 link-local address with scope ID
    pub fn connect_link_local(
        &mut self,
        peer_addr: Ipv6Addr,
        scope_id: u32,
        port: u16,
    ) -> io::Result<()> {
        let socket_addr = SocketAddrV6::new(peer_addr, port, 0, scope_id);
        self.connect(SocketAddr::V6(socket_addr))
    }

    /// Connect to a peer and establish the BGP session
    pub fn connect(&mut self, addr: SocketAddr) -> io::Result<()> {
        self.state = SessionState::Connect;

        // Use socket2 for proper IPv6 link-local support
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::STREAM, None)?;
        socket.set_nonblocking(false)?;

        // Connect with timeout
        socket.connect_timeout(&addr.into(), Duration::from_secs(10))?;

        let stream: TcpStream = socket.into();
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.set_nodelay(true)?;

        self.stream = Some(stream);
        self.state = SessionState::Active;

        self.send_open()?;
        self.state = SessionState::OpenSent;

        // Wait for OPEN from peer
        self.receive_open()?;
        self.state = SessionState::OpenConfirm;

        // Send KEEPALIVE
        self.send_keepalive()?;

        // Wait for KEEPALIVE from peer
        self.receive_keepalive()?;
        self.state = SessionState::Established;

        Ok(())
    }

    fn send_open(&mut self) -> io::Result<()> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Not connected")
        })?;

        let open = OpenMessage::new(self.local_asn, self.hold_time, self.router_id);
        let bytes = open.to_bytes();

        stream.write_all(&bytes)?;
        stream.flush()?;

        Ok(())
    }

    fn receive_open(&mut self) -> io::Result<OpenMessage> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Not connected")
        })?;

        let mut reader = BufReader::new(stream);
        let msg = Message::read(&mut reader)?;

        match msg {
            Message::Open(open) => Ok(open),
            Message::Notification { code, subcode, .. } => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Received NOTIFICATION: code={}, subcode={}", code, subcode),
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected OPEN message",
            )),
        }
    }

    fn send_keepalive(&mut self) -> io::Result<()> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Not connected")
        })?;

        let bytes = KeepaliveMessage::to_bytes();
        stream.write_all(&bytes)?;
        stream.flush()?;

        Ok(())
    }

    fn receive_keepalive(&mut self) -> io::Result<()> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Not connected")
        })?;

        let mut reader = BufReader::new(stream);
        let msg = Message::read(&mut reader)?;

        match msg {
            Message::Keepalive => Ok(()),
            Message::Notification { code, subcode, .. } => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Received NOTIFICATION: code={}, subcode={}", code, subcode),
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected KEEPALIVE message",
            )),
        }
    }

    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }
}
