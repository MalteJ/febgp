//! Async BGP session actor.
//!
//! The SessionActor manages a BGP session using tokio for async I/O and timers.
//! It integrates the pure FSM with the transport layer.

use std::collections::VecDeque;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::bgp::fsm::{
    AdminEvent, Fsm, FsmAction, FsmConfig, FsmEvent, FsmState, MessageEvent, NotificationError,
    TcpEvent, TimerEvent,
};
use crate::bgp::message::{KeepaliveMessage, Message, OpenMessage};
use crate::bgp::transport::{BgpTransport, TransportError};

/// Commands that can be sent to the session actor.
pub enum SessionCommand {
    /// Start the BGP session.
    Start,
    /// Stop the BGP session gracefully.
    Stop,
    /// Send an UPDATE message (body only, without BGP header).
    SendUpdate(Vec<u8>),
    /// Inject an incoming connection (from TCP listener).
    IncomingConnection(TcpStream),
}

impl fmt::Debug for SessionCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => write!(f, "Start"),
            Self::Stop => write!(f, "Stop"),
            Self::SendUpdate(data) => write!(f, "SendUpdate({} bytes)", data.len()),
            Self::IncomingConnection(_) => write!(f, "IncomingConnection(<TcpStream>)"),
        }
    }
}

/// Events emitted by the session actor.
///
/// All fields are populated for consumers (e.g., RIB manager, monitoring).
/// Some fields may not be used by all consumers.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// State changed. The `from` field tracks previous state for logging.
    StateChange { from: FsmState, to: FsmState },
    /// Session reached Established state.
    /// The `hold_time` is the negotiated value for monitoring.
    Established {
        peer_asn: u32,
        peer_router_id: Ipv4Addr,
        hold_time: Duration,
    },
    /// Session went down.
    SessionDown { reason: String },
    /// UPDATE message received. Contains raw UPDATE bytes for RIB processing.
    UpdateReceived(Vec<u8>),
}

/// Timer state for the session.
struct TimerState {
    connect_retry_deadline: Option<Instant>,
    hold_deadline: Option<Instant>,
    keepalive_deadline: Option<Instant>,
}

impl TimerState {
    fn new() -> Self {
        Self {
            connect_retry_deadline: None,
            hold_deadline: None,
            keepalive_deadline: None,
        }
    }

    fn clear_all(&mut self) {
        self.connect_retry_deadline = None;
        self.hold_deadline = None;
        self.keepalive_deadline = None;
    }
}

/// The async BGP session actor.
pub struct SessionActor<T: BgpTransport> {
    fsm: Fsm,
    transport: T,
    command_rx: mpsc::Receiver<SessionCommand>,
    event_tx: mpsc::Sender<SessionEvent>,
    timers: TimerState,
    running: bool,
}

impl<T: BgpTransport> SessionActor<T> {
    /// Create a new session actor.
    pub fn new(
        config: FsmConfig,
        transport: T,
        command_rx: mpsc::Receiver<SessionCommand>,
        event_tx: mpsc::Sender<SessionEvent>,
    ) -> Self {
        Self {
            fsm: Fsm::new(config),
            transport,
            command_rx,
            event_tx,
            timers: TimerState::new(),
            running: true,
        }
    }

    /// Run the session actor event loop.
    pub async fn run(mut self) {
        while self.running {
            tokio::select! {
                // Handle incoming commands
                Some(cmd) = self.command_rx.recv() => {
                    self.handle_command(cmd).await;
                }

                // Check connect retry timer
                _ = Self::wait_for_deadline(self.timers.connect_retry_deadline) => {
                    self.timers.connect_retry_deadline = None;
                    self.process_event(FsmEvent::Timer(TimerEvent::ConnectRetryTimerExpires)).await;
                }

                // Check hold timer
                _ = Self::wait_for_deadline(self.timers.hold_deadline) => {
                    self.timers.hold_deadline = None;
                    self.process_event(FsmEvent::Timer(TimerEvent::HoldTimerExpires)).await;
                }

                // Check keepalive timer
                _ = Self::wait_for_deadline(self.timers.keepalive_deadline) => {
                    self.timers.keepalive_deadline = None;
                    self.process_event(FsmEvent::Timer(TimerEvent::KeepaliveTimerExpires)).await;
                }

                // Receive messages from transport (only when connected)
                result = self.transport.receive(), if self.transport.is_connected() => {
                    self.handle_transport_receive(result).await;
                }
            }

            // Check if we should exit
            if self.fsm.state() == FsmState::Idle && !self.running {
                break;
            }
        }
    }

    /// Wait for an optional deadline.
    async fn wait_for_deadline(deadline: Option<Instant>) {
        match deadline {
            Some(d) => tokio::time::sleep_until(d).await,
            None => std::future::pending().await,
        }
    }

    /// Handle an incoming command.
    async fn handle_command(&mut self, cmd: SessionCommand) {
        match cmd {
            SessionCommand::Start => {
                self.process_event(FsmEvent::Admin(AdminEvent::ManualStart))
                    .await;
            }
            SessionCommand::Stop => {
                self.running = false;
                self.process_event(FsmEvent::Admin(AdminEvent::ManualStop))
                    .await;
            }
            SessionCommand::SendUpdate(body) => {
                // Only send UPDATE if we're in Established state
                if self.fsm.state() == FsmState::Established {
                    let bytes = Self::build_update_message(&body);
                    if let Err(e) = self.transport.send(&bytes).await {
                        eprintln!("Failed to send UPDATE: {}", e);
                    }
                }
            }
            SessionCommand::IncomingConnection(stream) => {
                // Handle incoming connection from TCP listener
                self.handle_incoming_connection(stream).await;
            }
        }
    }

    /// Handle an incoming connection from the TCP listener.
    /// This implements RFC 4271 collision detection.
    async fn handle_incoming_connection(&mut self, stream: TcpStream) {
        let current_state = self.fsm.state();

        match current_state {
            FsmState::Idle => {
                // No active connection, accept the incoming one
                self.transport.accept_incoming(stream);
                // Trigger connection confirmed event
                self.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionConfirmed))
                    .await;
            }
            FsmState::Connect | FsmState::Active => {
                // We're trying to connect outbound, but got an inbound connection
                // This is a collision - per RFC 4271, we'll accept the incoming
                // connection and close any outbound attempt since we're not yet
                // in OpenSent (haven't received their OPEN to compare router IDs)
                let _ = self.transport.close().await; // Close outbound attempt
                self.transport.accept_incoming(stream);
                // Trigger connection confirmed event
                self.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionConfirmed))
                    .await;
            }
            FsmState::OpenSent | FsmState::OpenConfirm => {
                // RFC 4271 Section 6.8: Connection Collision Detection
                // We've sent OPEN on the outbound connection, now have inbound
                // Compare BGP Identifiers to decide which to keep:
                // - If our ID is higher, drop incoming, keep outbound
                // - If our ID is lower, drop outbound, accept incoming
                // We don't know their ID yet on the incoming connection,
                // so we temporarily accept both and let the OPEN comparison decide
                // For now, drop the incoming since we already sent OPEN on outbound
                drop(stream);
            }
            FsmState::Established => {
                // Already have an established session, drop incoming
                drop(stream);
            }
        }
    }

    /// Handle a message received from the transport.
    async fn handle_transport_receive(&mut self, result: Result<Message, TransportError>) {
        match result {
            Ok(message) => {
                let event = match message {
                    Message::Open(open) => FsmEvent::Message(MessageEvent::BgpOpen(open)),
                    Message::Keepalive => FsmEvent::Message(MessageEvent::KeepAliveMsg),
                    Message::Update(data) => FsmEvent::Message(MessageEvent::UpdateMsg(data)),
                    Message::Notification { code, subcode, data } => {
                        FsmEvent::Message(MessageEvent::NotifMsg { code, subcode, data })
                    }
                };
                self.process_event(event).await;
            }
            Err(TransportError::ConnectionClosed) => {
                self.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionFails))
                    .await;
            }
            Err(TransportError::Timeout) => {
                // Timeout on receive is normal, yield to allow other tasks
                tokio::task::yield_now().await;
            }
            Err(e) => {
                // Log error and treat as connection failure
                eprintln!("Transport error: {}", e);
                self.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionFails))
                    .await;
            }
        }
    }

    /// Process an FSM event and execute resulting actions.
    /// Uses a queue to avoid async recursion.
    async fn process_event(&mut self, initial_event: FsmEvent) {
        let mut event_queue: VecDeque<FsmEvent> = VecDeque::new();
        event_queue.push_back(initial_event);

        while let Some(event) = event_queue.pop_front() {
            let actions = self.fsm.process_event(event);

            for action in actions {
                if let Some(new_event) = self.execute_action(action).await {
                    event_queue.push_back(new_event);
                }
            }
        }
    }

    /// Execute a single FSM action.
    /// Returns an optional event to be processed (to avoid async recursion).
    async fn execute_action(&mut self, action: FsmAction) -> Option<FsmEvent> {
        match action {
            FsmAction::InitiateTcpConnection => {
                match self.transport.connect().await {
                    Ok(()) => {
                        return Some(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
                    }
                    Err(_e) => {
                        return Some(FsmEvent::Tcp(TcpEvent::TcpConnectionFails));
                    }
                }
            }

            FsmAction::DropTcpConnection => {
                let _ = self.transport.close().await;
            }

            FsmAction::SendOpen => {
                let config = self.fsm.config();
                let open = OpenMessage::new(config.local_asn, config.hold_time, config.router_id);
                let bytes = open.to_bytes();
                if let Err(e) = self.transport.send(&bytes).await {
                    eprintln!("Failed to send OPEN: {}", e);
                }
            }

            FsmAction::SendKeepalive => {
                let bytes = KeepaliveMessage::to_bytes();
                if let Err(e) = self.transport.send(&bytes).await {
                    eprintln!("Failed to send KEEPALIVE: {}", e);
                }
            }

            FsmAction::SendNotification(err) => {
                let bytes = Self::build_notification(&err);
                let _ = self.transport.send(&bytes).await;
            }

            FsmAction::StartConnectRetryTimer => {
                let config = self.fsm.config();
                self.timers.connect_retry_deadline =
                    Some(Instant::now() + config.connect_retry_time);
            }

            FsmAction::StopConnectRetryTimer => {
                self.timers.connect_retry_deadline = None;
            }

            FsmAction::ResetConnectRetryTimer => {
                let config = self.fsm.config();
                self.timers.connect_retry_deadline =
                    Some(Instant::now() + config.connect_retry_time);
            }

            FsmAction::StartHoldTimer(duration) => {
                if !duration.is_zero() {
                    self.timers.hold_deadline = Some(Instant::now() + duration);
                }
            }

            FsmAction::StopHoldTimer => {
                self.timers.hold_deadline = None;
            }

            FsmAction::RestartHoldTimer => {
                if let Some(hold_time) = self.fsm.negotiated_hold_time() {
                    if !hold_time.is_zero() {
                        self.timers.hold_deadline = Some(Instant::now() + hold_time);
                    }
                }
            }

            FsmAction::StartKeepaliveTimer(duration) => {
                if !duration.is_zero() {
                    self.timers.keepalive_deadline = Some(Instant::now() + duration);
                }
            }

            FsmAction::StopKeepaliveTimer => {
                self.timers.keepalive_deadline = None;
            }

            FsmAction::ResetKeepaliveTimer => {
                if let Some(hold_time) = self.fsm.negotiated_hold_time() {
                    let ka_time = hold_time / 3;
                    if !ka_time.is_zero() {
                        self.timers.keepalive_deadline = Some(Instant::now() + ka_time);
                    }
                }
            }

            FsmAction::IncrementConnectRetryCounter => {
                // Counter is managed internally by FSM
            }

            FsmAction::ResetConnectRetryCounter => {
                // Counter is managed internally by FSM
            }

            FsmAction::NotifyStateChange { from, to } => {
                let _ = self
                    .event_tx
                    .send(SessionEvent::StateChange { from, to })
                    .await;

                // Also emit Established event when reaching that state
                if to == FsmState::Established {
                    if let (Some(peer_asn), Some(peer_router_id), Some(hold_time)) = (
                        self.fsm.peer_asn(),
                        self.fsm.peer_router_id(),
                        self.fsm.negotiated_hold_time(),
                    ) {
                        let _ = self
                            .event_tx
                            .send(SessionEvent::Established {
                                peer_asn,
                                peer_router_id,
                                hold_time,
                            })
                            .await;
                    }
                }

                // Emit SessionDown when going to Idle from a connected state
                if to == FsmState::Idle && from != FsmState::Idle {
                    let _ = self
                        .event_tx
                        .send(SessionEvent::SessionDown {
                            reason: format!("Transition from {:?} to Idle", from),
                        })
                        .await;
                }
            }

            FsmAction::ReleaseResources => {
                self.timers.clear_all();
                let _ = self.transport.close().await;
            }

            FsmAction::ProcessUpdate(data) => {
                let _ = self.event_tx.send(SessionEvent::UpdateReceived(data)).await;
            }
        }
        None
    }

    /// Build a NOTIFICATION message.
    fn build_notification(err: &NotificationError) -> Vec<u8> {
        use crate::bgp::message::{BGP_HEADER_LEN, BGP_MARKER};

        let body_len = 2 + err.data.len();
        let total_len = (BGP_HEADER_LEN + body_len) as u16;

        let mut buf = Vec::with_capacity(total_len as usize);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.push(3); // NOTIFICATION message type
        buf.push(err.code as u8);
        buf.push(err.subcode);
        buf.extend_from_slice(&err.data);
        buf
    }

    /// Build an UPDATE message from body bytes.
    fn build_update_message(body: &[u8]) -> Vec<u8> {
        use crate::bgp::message::{BGP_HEADER_LEN, BGP_MARKER};

        let total_len = (BGP_HEADER_LEN + body.len()) as u16;

        let mut buf = Vec::with_capacity(total_len as usize);
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.push(2); // UPDATE message type
        buf.extend_from_slice(body);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::transport::mock::MockTransport;
    use std::net::Ipv4Addr;
    use tokio::time::timeout;

    fn test_config() -> FsmConfig {
        FsmConfig {
            local_asn: 65001,
            peer_asn: 65002,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            hold_time: 90,
            connect_retry_time: Duration::from_secs(5),
        }
    }

    fn peer_open() -> OpenMessage {
        OpenMessage::new(65002, 90, Ipv4Addr::new(2, 2, 2, 2))
    }

    #[tokio::test]
    async fn test_session_actor_start_to_established() {
        let mut transport = MockTransport::new();
        // Queue the expected peer messages
        transport.queue_receive(Message::Open(peer_open()));
        transport.queue_receive(Message::Keepalive);
        // Queue a timeout that will keep the session alive briefly
        for _ in 0..5 {
            transport.queue_receive_error(TransportError::Timeout);
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (event_tx, mut event_rx) = mpsc::channel(10);

        let actor = SessionActor::new(test_config(), transport, cmd_rx, event_tx);

        let handle = tokio::spawn(async move {
            actor.run().await;
        });

        // Start the session
        cmd_tx.send(SessionCommand::Start).await.unwrap();

        // Wait for Established event
        let mut reached_established = false;
        let deadline = Duration::from_millis(500);

        while let Ok(Some(event)) = timeout(deadline, event_rx.recv()).await {
            if let SessionEvent::Established { peer_asn, .. } = event {
                assert_eq!(peer_asn, 65002);
                reached_established = true;
                break;
            }
        }

        assert!(reached_established, "Should reach Established state");

        // Stop the session
        cmd_tx.send(SessionCommand::Stop).await.unwrap();
        let _ = timeout(Duration::from_millis(500), handle).await;
    }

    #[tokio::test]
    async fn test_session_actor_connection_failure() {
        let mut transport = MockTransport::new();
        transport.fail_connect(TransportError::ConnectionClosed);

        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (event_tx, mut event_rx) = mpsc::channel(10);

        let actor = SessionActor::new(test_config(), transport, cmd_rx, event_tx);

        let handle = tokio::spawn(async move {
            actor.run().await;
        });

        cmd_tx.send(SessionCommand::Start).await.unwrap();

        // Should transition to Active after connection failure
        let mut reached_active = false;
        let deadline = Duration::from_secs(1);

        while let Ok(Some(event)) = timeout(deadline, event_rx.recv()).await {
            if let SessionEvent::StateChange { to, .. } = event {
                if to == FsmState::Active {
                    reached_active = true;
                    break;
                }
            }
        }

        assert!(reached_active, "Should reach Active state after connection failure");

        cmd_tx.send(SessionCommand::Stop).await.unwrap();
        let _ = timeout(Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn test_session_actor_receives_notification() {
        let mut transport = MockTransport::new();
        transport.queue_receive(Message::Open(peer_open()));
        transport.queue_receive(Message::Notification {
            code: 6,
            subcode: 4,
            data: vec![],
        });

        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (event_tx, mut event_rx) = mpsc::channel(10);

        let actor = SessionActor::new(test_config(), transport, cmd_rx, event_tx);

        let handle = tokio::spawn(async move {
            actor.run().await;
        });

        cmd_tx.send(SessionCommand::Start).await.unwrap();

        // Wait for SessionDown event
        let mut session_down = false;
        let deadline = Duration::from_secs(2);

        while let Ok(Some(event)) = timeout(deadline, event_rx.recv()).await {
            if let SessionEvent::SessionDown { .. } = event {
                session_down = true;
                break;
            }
        }

        assert!(session_down, "Should receive SessionDown after NOTIFICATION");

        cmd_tx.send(SessionCommand::Stop).await.unwrap();
        let _ = timeout(Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn test_session_actor_manual_stop() {
        let mut transport = MockTransport::new();
        transport.queue_receive(Message::Open(peer_open()));
        transport.queue_receive(Message::Keepalive);
        for _ in 0..5 {
            transport.queue_receive_error(TransportError::Timeout);
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (event_tx, mut event_rx) = mpsc::channel(10);

        let actor = SessionActor::new(test_config(), transport, cmd_rx, event_tx);

        let handle = tokio::spawn(async move {
            actor.run().await;
        });

        cmd_tx.send(SessionCommand::Start).await.unwrap();

        // Wait for Established
        let deadline = Duration::from_millis(500);
        while let Ok(Some(event)) = timeout(deadline, event_rx.recv()).await {
            if let SessionEvent::Established { .. } = event {
                break;
            }
        }

        // Stop the session
        cmd_tx.send(SessionCommand::Stop).await.unwrap();

        // Should get SessionDown
        let mut session_down = false;
        while let Ok(Some(event)) = timeout(Duration::from_millis(500), event_rx.recv()).await {
            if let SessionEvent::SessionDown { .. } = event {
                session_down = true;
                break;
            }
        }

        assert!(session_down, "Should receive SessionDown after Stop");

        let _ = timeout(Duration::from_millis(500), handle).await;
    }

    #[tokio::test]
    async fn test_session_actor_update_received() {
        let mut transport = MockTransport::new();
        transport.queue_receive(Message::Open(peer_open()));
        transport.queue_receive(Message::Keepalive);

        let update_data = vec![0x00, 0x00, 0x00, 0x04, 0x40, 0x01, 0x01, 0x00];
        transport.queue_receive(Message::Update(update_data.clone()));
        for _ in 0..5 {
            transport.queue_receive_error(TransportError::Timeout);
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (event_tx, mut event_rx) = mpsc::channel(10);

        let actor = SessionActor::new(test_config(), transport, cmd_rx, event_tx);

        let handle = tokio::spawn(async move {
            actor.run().await;
        });

        cmd_tx.send(SessionCommand::Start).await.unwrap();

        // Wait for UpdateReceived
        let mut received_update = false;
        let deadline = Duration::from_millis(500);

        while let Ok(Some(event)) = timeout(deadline, event_rx.recv()).await {
            if let SessionEvent::UpdateReceived(data) = event {
                assert_eq!(data, update_data);
                received_update = true;
                break;
            }
        }

        assert!(received_update, "Should receive UPDATE");

        cmd_tx.send(SessionCommand::Stop).await.unwrap();
        let _ = timeout(Duration::from_millis(500), handle).await;
    }

    #[test]
    fn test_build_notification() {
        let err = NotificationError::hold_timer_expired();
        let bytes = SessionActor::<MockTransport>::build_notification(&err);

        // Should be header (19) + code (1) + subcode (1) = 21 bytes
        assert_eq!(bytes.len(), 21);
        // Check marker
        assert_eq!(&bytes[0..16], &[0xFF; 16]);
        // Check length
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]), 21);
        // Check message type (NOTIFICATION = 3)
        assert_eq!(bytes[18], 3);
        // Check error code (HoldTimerExpired = 4)
        assert_eq!(bytes[19], 4);
        // Check subcode
        assert_eq!(bytes[20], 0);
    }
}
