//! Real TCP transport implementation using tokio.

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

use super::{BgpTransport, TransportError, TransportResult};
use crate::bgp::message::{Message, BGP_HEADER_LEN, BGP_MARKER};

/// Default timeout for connect operations.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for read operations.
const READ_TIMEOUT: Duration = Duration::from_secs(90);

/// Maximum BGP message size per RFC 4271.
const MAX_MESSAGE_SIZE: usize = 4096;

/// TCP transport for BGP sessions.
#[derive(Debug)]
pub struct TcpTransport {
    /// Peer address to connect to.
    peer_addr: SocketAddr,
    /// Optional local address to bind to.
    local_addr: Option<SocketAddr>,
    /// The TCP stream (None if not connected).
    stream: Option<TcpStream>,
    /// Connect timeout.
    connect_timeout: Duration,
    /// Read timeout.
    read_timeout: Duration,
}

/// Builder methods and constructors for TcpTransport.
///
/// Several builder methods (`with_*`) are provided for customization
/// but not yet used in production code. They are available for:
/// - Link-local peering with custom source addresses
/// - Adjusting timeouts per-peer
#[allow(dead_code)]
impl TcpTransport {
    /// Create a new TCP transport for the given peer address.
    pub fn new(peer_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            local_addr: None,
            stream: None,
            connect_timeout: CONNECT_TIMEOUT,
            read_timeout: READ_TIMEOUT,
        }
    }

    /// Create a TCP transport from an already-accepted stream.
    /// Used for incoming connections from a TCP listener.
    pub fn from_stream(stream: TcpStream, peer_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            local_addr: None,
            stream: Some(stream),
            connect_timeout: CONNECT_TIMEOUT,
            read_timeout: READ_TIMEOUT,
        }
    }

    /// Create a TCP transport for an IPv6 link-local peer.
    ///
    /// # Arguments
    /// * `peer_addr` - The peer's IPv6 link-local address
    /// * `scope_id` - The interface scope ID (e.g., from `if_nametoindex`)
    /// * `port` - The BGP port (typically 179)
    pub fn new_link_local(peer_addr: Ipv6Addr, scope_id: u32, port: u16) -> Self {
        let socket_addr = SocketAddrV6::new(peer_addr, port, 0, scope_id);
        Self::new(SocketAddr::V6(socket_addr))
    }

    /// Set the local address to bind to before connecting.
    pub fn with_local_addr(mut self, addr: SocketAddr) -> Self {
        self.local_addr = Some(addr);
        self
    }

    /// Set the connect timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the read timeout.
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Read exactly `n` bytes from the stream.
    async fn read_exact(&mut self, buf: &mut [u8]) -> TransportResult<()> {
        let stream = self.stream.as_mut().ok_or(TransportError::ConnectionClosed)?;

        match timeout(self.read_timeout, stream.read_exact(buf)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                Err(TransportError::ConnectionClosed)
            }
            Ok(Err(e)) => Err(TransportError::from(e)),
            Err(_) => Err(TransportError::Timeout),
        }
    }

    /// Read a BGP message from the stream.
    async fn read_message(&mut self) -> TransportResult<Message> {
        // Read the 19-byte header
        let mut header_buf = [0u8; BGP_HEADER_LEN];
        self.read_exact(&mut header_buf).await?;

        // Validate marker
        if header_buf[0..16] != BGP_MARKER {
            return Err(TransportError::InvalidMessage(
                "Invalid BGP marker".to_string(),
            ));
        }

        // Parse length and type
        let length = u16::from_be_bytes([header_buf[16], header_buf[17]]) as usize;
        let msg_type = header_buf[18];

        // Validate length
        if !(BGP_HEADER_LEN..=MAX_MESSAGE_SIZE).contains(&length) {
            return Err(TransportError::InvalidMessage(format!(
                "Invalid message length: {}",
                length
            )));
        }

        // Read the body
        let body_len = length - BGP_HEADER_LEN;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            self.read_exact(&mut body).await?;
        }

        // Parse the message
        self.parse_message(msg_type, body)
    }

    /// Parse a BGP message from its type and body.
    fn parse_message(&self, msg_type: u8, body: Vec<u8>) -> TransportResult<Message> {
        use crate::bgp::message::{MessageType, OpenMessage};

        let msg_type = MessageType::try_from(msg_type).map_err(|e| {
            TransportError::InvalidMessage(format!("Invalid message type: {}", e))
        })?;

        match msg_type {
            MessageType::Open => {
                let open = OpenMessage::decode(&body).map_err(|e| {
                    TransportError::InvalidMessage(format!("Invalid OPEN: {}", e))
                })?;
                Ok(Message::Open(open))
            }
            MessageType::Update => Ok(Message::Update(body)),
            MessageType::Notification => {
                let code = body.first().copied().unwrap_or(0);
                let subcode = body.get(1).copied().unwrap_or(0);
                let data = if body.len() > 2 {
                    body[2..].to_vec()
                } else {
                    Vec::new()
                };
                Ok(Message::Notification { code, subcode, data })
            }
            MessageType::Keepalive => Ok(Message::Keepalive),
        }
    }
}

impl BgpTransport for TcpTransport {
    async fn connect(&mut self) -> TransportResult<()> {
        // Close any existing connection
        if self.stream.is_some() {
            let _ = self.close().await;
        }

        debug!(peer = %self.peer_addr, "Connecting to BGP peer {}", self.peer_addr);

        // Connect with timeout
        let stream = match timeout(self.connect_timeout, async {
            if let Some(local_addr) = self.local_addr {
                // Bind to local address first (for link-local)
                let socket = match self.peer_addr {
                    SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                    SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
                };
                socket.bind(local_addr)?;
                socket.connect(self.peer_addr).await
            } else {
                TcpStream::connect(self.peer_addr).await
            }
        })
        .await
        {
            Ok(Ok(stream)) => {
                debug!(peer = %self.peer_addr, "TCP connection established to {}", self.peer_addr);
                stream
            }
            Ok(Err(e)) => {
                debug!(peer = %self.peer_addr, error = %e, "TCP connection failed to {}: {}", self.peer_addr, e);
                return Err(TransportError::ConnectionFailed(e));
            }
            Err(_) => {
                warn!(peer = %self.peer_addr, "TCP connection timed out to {}", self.peer_addr);
                return Err(TransportError::Timeout);
            }
        };

        // Configure the socket
        stream.set_nodelay(true).map_err(TransportError::Io)?;

        self.stream = Some(stream);
        Ok(())
    }

    async fn send(&mut self, message: &[u8]) -> TransportResult<()> {
        let stream = self.stream.as_mut().ok_or(TransportError::ConnectionClosed)?;

        stream
            .write_all(message)
            .await
            .map_err(TransportError::from)?;

        stream.flush().await.map_err(TransportError::from)?;

        Ok(())
    }

    async fn receive(&mut self) -> TransportResult<Message> {
        self.read_message().await
    }

    async fn close(&mut self) -> TransportResult<()> {
        if let Some(mut stream) = self.stream.take() {
            debug!(peer = %self.peer_addr, "Closing TCP connection to {}", self.peer_addr);
            let _ = stream.shutdown().await;
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    fn peer_addr(&self) -> std::net::SocketAddr {
        self.peer_addr
    }

    fn accept_incoming(&mut self, stream: TcpStream) {
        // Close any existing connection
        if let Some(old_stream) = self.stream.take() {
            debug!(peer = %self.peer_addr, "Closing existing connection to accept incoming");
            // Just drop it - the stream will be closed
            drop(old_stream);
        }
        debug!(peer = %self.peer_addr, "Accepting incoming TCP connection from {}", self.peer_addr);
        self.stream = Some(stream);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_tcp_transport_new() {
        let addr = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 179);
        let transport = TcpTransport::new(addr);

        assert_eq!(transport.peer_addr, addr);
        assert!(transport.local_addr.is_none());
        assert!(!transport.is_connected());
    }

    #[test]
    fn test_tcp_transport_new_link_local() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1, 0x2, 0x3, 0x4);
        let transport = TcpTransport::new_link_local(peer, 5, 179);

        match transport.peer_addr {
            SocketAddr::V6(addr) => {
                assert_eq!(*addr.ip(), peer);
                assert_eq!(addr.scope_id(), 5);
                assert_eq!(addr.port(), 179);
            }
            _ => panic!("Expected V6 address"),
        }
    }

    #[test]
    fn test_tcp_transport_with_local_addr() {
        let peer = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 179);
        let local = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 2).into(), 0);

        let transport = TcpTransport::new(peer).with_local_addr(local);

        assert_eq!(transport.local_addr, Some(local));
    }

    #[test]
    fn test_tcp_transport_with_timeouts() {
        let addr = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 179);
        let transport = TcpTransport::new(addr)
            .with_connect_timeout(Duration::from_secs(10))
            .with_read_timeout(Duration::from_secs(60));

        assert_eq!(transport.connect_timeout, Duration::from_secs(10));
        assert_eq!(transport.read_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_parse_keepalive() {
        let transport = TcpTransport::new(SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            179,
        ));

        let msg = transport.parse_message(4, vec![]).unwrap();
        assert!(matches!(msg, Message::Keepalive));
    }

    #[test]
    fn test_parse_notification() {
        let transport = TcpTransport::new(SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            179,
        ));

        let body = vec![6, 4, 0x01, 0x02]; // Cease, Administrative Reset, data
        let msg = transport.parse_message(3, body).unwrap();

        match msg {
            Message::Notification { code, subcode, data } => {
                assert_eq!(code, 6);
                assert_eq!(subcode, 4);
                assert_eq!(data, vec![0x01, 0x02]);
            }
            _ => panic!("Expected Notification"),
        }
    }

    #[test]
    fn test_parse_update() {
        let transport = TcpTransport::new(SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            179,
        ));

        let body = vec![0x00, 0x00, 0x00, 0x00];
        let msg = transport.parse_message(2, body.clone()).unwrap();

        match msg {
            Message::Update(data) => {
                assert_eq!(data, body);
            }
            _ => panic!("Expected Update"),
        }
    }

    #[test]
    fn test_parse_invalid_type() {
        let transport = TcpTransport::new(SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            179,
        ));

        let result = transport.parse_message(99, vec![]);
        assert!(result.is_err());
    }

    // Integration tests would require actual network connectivity
    // and are in tests-integration/
}
