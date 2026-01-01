//! Mock transport for unit testing the BGP session.
//!
//! This module is used by unit tests in `session_actor` and other modules.
//! The `dead_code` warnings appear because tests are compiled separately.

use std::collections::VecDeque;

use super::{BgpTransport, TransportError, TransportResult};
use crate::bgp::message::Message;

/// A mock transport for testing BGP session logic.
///
/// This transport allows tests to:
/// - Queue messages to be "received"
/// - Capture messages that were "sent"
/// - Simulate connection success/failure
/// - Simulate disconnection
#[allow(dead_code)]
#[derive(Debug)]
pub struct MockTransport {
    /// Whether the transport is currently connected.
    connected: bool,
    /// Messages that have been sent (for verification).
    sent_messages: VecDeque<Vec<u8>>,
    /// Messages queued to be received.
    incoming_queue: VecDeque<TransportResult<Message>>,
    /// Result to return on next connect() call.
    connect_result: Option<TransportResult<()>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl MockTransport {
    /// Create a new mock transport.
    pub fn new() -> Self {
        Self {
            connected: false,
            sent_messages: VecDeque::new(),
            incoming_queue: VecDeque::new(),
            connect_result: None,
        }
    }

    /// Configure the result of the next connect() call.
    /// If not set, connect() will succeed.
    pub fn set_connect_result(&mut self, result: TransportResult<()>) {
        self.connect_result = Some(result);
    }

    /// Configure connect() to fail with the given error.
    pub fn fail_connect(&mut self, error: TransportError) {
        self.connect_result = Some(Err(error));
    }

    /// Queue a message to be returned by the next receive() call.
    pub fn queue_receive(&mut self, message: Message) {
        self.incoming_queue.push_back(Ok(message));
    }

    /// Queue an error to be returned by the next receive() call.
    pub fn queue_receive_error(&mut self, error: TransportError) {
        self.incoming_queue.push_back(Err(error));
    }

    /// Get all messages that have been sent.
    pub fn sent_messages(&self) -> &VecDeque<Vec<u8>> {
        &self.sent_messages
    }

    /// Take the next sent message (removes it from the queue).
    pub fn take_sent(&mut self) -> Option<Vec<u8>> {
        self.sent_messages.pop_front()
    }

    /// Get the number of messages sent.
    pub fn sent_count(&self) -> usize {
        self.sent_messages.len()
    }

    /// Clear all sent messages.
    pub fn clear_sent(&mut self) {
        self.sent_messages.clear();
    }

    /// Simulate the connection being dropped.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Force the connection state (for testing edge cases).
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }
}

impl BgpTransport for MockTransport {
    async fn connect(&mut self) -> TransportResult<()> {
        let result = self.connect_result.take().unwrap_or(Ok(()));
        if result.is_ok() {
            self.connected = true;
        }
        result
    }

    async fn send(&mut self, message: &[u8]) -> TransportResult<()> {
        if !self.connected {
            return Err(TransportError::ConnectionClosed);
        }
        self.sent_messages.push_back(message.to_vec());
        Ok(())
    }

    async fn receive(&mut self) -> TransportResult<Message> {
        if !self.connected {
            return Err(TransportError::ConnectionClosed);
        }
        self.incoming_queue
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }

    async fn close(&mut self) -> TransportResult<()> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::message::{KeepaliveMessage, OpenMessage};
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_mock_transport_connect_success() {
        let mut transport = MockTransport::new();
        assert!(!transport.is_connected());

        let result = transport.connect().await;

        assert!(result.is_ok());
        assert!(transport.is_connected());
    }

    #[tokio::test]
    async fn test_mock_transport_connect_failure() {
        let mut transport = MockTransport::new();
        transport.fail_connect(TransportError::ConnectionClosed);

        let result = transport.connect().await;

        assert!(result.is_err());
        assert!(!transport.is_connected());
    }

    #[tokio::test]
    async fn test_mock_transport_send() {
        let mut transport = MockTransport::new();
        transport.connect().await.unwrap();

        let bytes = KeepaliveMessage::to_bytes();
        let result = transport.send(&bytes).await;

        assert!(result.is_ok());
        assert_eq!(transport.sent_count(), 1);
        assert_eq!(transport.take_sent(), Some(bytes));
    }

    #[tokio::test]
    async fn test_mock_transport_send_when_disconnected() {
        let mut transport = MockTransport::new();
        // Don't connect

        let result = transport.send(&[1, 2, 3]).await;

        assert!(matches!(result, Err(TransportError::ConnectionClosed)));
    }

    #[tokio::test]
    async fn test_mock_transport_receive() {
        let mut transport = MockTransport::new();
        transport.connect().await.unwrap();

        let open = OpenMessage::new(65001, 90, Ipv4Addr::new(1, 1, 1, 1));
        transport.queue_receive(Message::Open(open));

        let result = transport.receive().await;

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Message::Open(_)));
    }

    #[tokio::test]
    async fn test_mock_transport_receive_error() {
        let mut transport = MockTransport::new();
        transport.connect().await.unwrap();
        transport.queue_receive_error(TransportError::Timeout);

        let result = transport.receive().await;

        assert!(matches!(result, Err(TransportError::Timeout)));
    }

    #[tokio::test]
    async fn test_mock_transport_receive_when_empty() {
        let mut transport = MockTransport::new();
        transport.connect().await.unwrap();
        // Don't queue anything

        let result = transport.receive().await;

        assert!(matches!(result, Err(TransportError::Timeout)));
    }

    #[tokio::test]
    async fn test_mock_transport_close() {
        let mut transport = MockTransport::new();
        transport.connect().await.unwrap();
        assert!(transport.is_connected());

        let result = transport.close().await;

        assert!(result.is_ok());
        assert!(!transport.is_connected());
    }

    #[tokio::test]
    async fn test_mock_transport_disconnect() {
        let mut transport = MockTransport::new();
        transport.connect().await.unwrap();
        transport.disconnect();

        let result = transport.receive().await;

        assert!(matches!(result, Err(TransportError::ConnectionClosed)));
    }

    #[tokio::test]
    async fn test_mock_transport_multiple_messages() {
        let mut transport = MockTransport::new();
        transport.connect().await.unwrap();

        transport.queue_receive(Message::Keepalive);
        transport.queue_receive(Message::Keepalive);
        transport.queue_receive(Message::Keepalive);

        let r1 = transport.receive().await;
        let r2 = transport.receive().await;
        let r3 = transport.receive().await;
        let r4 = transport.receive().await;

        assert!(matches!(r1, Ok(Message::Keepalive)));
        assert!(matches!(r2, Ok(Message::Keepalive)));
        assert!(matches!(r3, Ok(Message::Keepalive)));
        assert!(matches!(r4, Err(TransportError::Timeout)));
    }
}
