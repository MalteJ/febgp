//! BGP Transport abstraction for testability.
//!
//! This module provides a trait-based abstraction over TCP transport,
//! allowing the session actor to be tested with mock transports.

pub mod mock;
pub mod tcp;

use std::io;

use thiserror::Error;

use crate::bgp::message::Message;

/// Error type for transport operations.
///
/// The `MessageTooLarge` variant is defined for RFC compliance but not yet used;
/// currently oversized messages are rejected with `InvalidMessage`.
#[derive(Error, Debug)]
pub enum TransportError {
    /// TCP connection failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(#[source] io::Error),

    /// Connection was closed by the peer.
    #[error("connection closed")]
    ConnectionClosed,

    /// Message was too large (>4096 bytes per RFC 4271).
    #[allow(dead_code)]
    #[error("message too large")]
    MessageTooLarge,

    /// Invalid or malformed message.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// Other I/O error.
    #[error("I/O error: {0}")]
    Io(#[source] io::Error),
}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted => TransportError::ConnectionClosed,
            io::ErrorKind::TimedOut => TransportError::Timeout,
            _ => TransportError::Io(e),
        }
    }
}

/// Result type for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

/// Trait for BGP transport implementations.
///
/// This trait abstracts the underlying transport (TCP) to allow for:
/// - Unit testing with mock transports
/// - Future support for different transport mechanisms
#[allow(async_fn_in_trait)]
pub trait BgpTransport: Send {
    /// Initiate a TCP connection to the peer.
    async fn connect(&mut self) -> TransportResult<()>;

    /// Send a BGP message to the peer.
    async fn send(&mut self, message: &[u8]) -> TransportResult<()>;

    /// Receive a BGP message from the peer.
    /// Returns the raw message bytes.
    async fn receive(&mut self) -> TransportResult<Message>;

    /// Close the transport connection.
    async fn close(&mut self) -> TransportResult<()>;

    /// Check if the transport is currently connected.
    fn is_connected(&self) -> bool;

    /// Get the peer address.
    fn peer_addr(&self) -> std::net::SocketAddr;

    /// Accept an incoming connection, replacing any existing connection.
    /// This is used for connection collision handling.
    fn accept_incoming(&mut self, stream: tokio::net::TcpStream);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::ConnectionClosed;
        assert_eq!(format!("{}", err), "connection closed");

        let err = TransportError::Timeout;
        assert_eq!(format!("{}", err), "operation timed out");
    }

    #[test]
    fn test_transport_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let err: TransportError = io_err.into();
        assert!(matches!(err, TransportError::ConnectionClosed));

        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let err: TransportError = io_err.into();
        assert!(matches!(err, TransportError::Timeout));
    }
}
