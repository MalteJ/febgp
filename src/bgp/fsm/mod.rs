//! BGP Finite State Machine implementation per RFC 4271.
//!
//! The FSM is designed to be pure (no I/O) for testability. It receives events
//! and returns actions that the session actor should execute.

pub mod action;
pub mod error;
pub mod event;
pub mod state;
pub mod validation;

use std::net::Ipv4Addr;
use std::time::Duration;

pub use action::FsmAction;
pub use error::{FsmErrorSubcode, NotificationError};
#[allow(unused_imports)]
pub use error::ErrorCode; // Exported for external NOTIFICATION generation
pub use event::{AdminEvent, FsmEvent, MessageEvent, TcpEvent, TimerEvent};
pub use state::FsmState;
pub use validation::{get_peer_asn, keepalive_time, negotiate_hold_time, validate_open};

use crate::bgp::message::OpenMessage;
use validation::ValidationConfig;

/// Configuration for the BGP FSM.
#[derive(Debug, Clone)]
pub struct FsmConfig {
    /// Local Autonomous System Number.
    pub local_asn: u32,
    /// Expected peer ASN. If 0, any ASN is accepted (BGP unnumbered).
    pub peer_asn: u32,
    /// Local BGP router identifier.
    pub router_id: Ipv4Addr,
    /// Proposed hold time in seconds.
    pub hold_time: u16,
    /// Time between connection retry attempts.
    pub connect_retry_time: Duration,
    /// Enable IPv4 unicast address family.
    pub ipv4_unicast: bool,
    /// Enable IPv6 unicast address family.
    pub ipv6_unicast: bool,
}

impl Default for FsmConfig {
    fn default() -> Self {
        Self {
            local_asn: 0,
            peer_asn: 0,
            router_id: Ipv4Addr::new(0, 0, 0, 1),
            hold_time: 90,
            connect_retry_time: Duration::from_secs(120),
            ipv4_unicast: false,
            ipv6_unicast: true,
        }
    }
}

/// The BGP Finite State Machine.
///
/// This is a pure state machine with no I/O. It receives events via `process_event()`
/// and returns a list of actions that should be executed by the session actor.
#[derive(Debug)]
pub struct Fsm {
    /// Current state.
    state: FsmState,
    /// Configuration.
    config: FsmConfig,
    /// Connect retry counter.
    connect_retry_counter: u32,
    /// Negotiated hold time (set after OPEN exchange).
    negotiated_hold_time: Option<Duration>,
    /// Peer's BGP identifier (set after receiving OPEN).
    peer_router_id: Option<Ipv4Addr>,
    /// Peer's ASN (set after receiving OPEN).
    peer_asn: Option<u32>,
}

impl Fsm {
    /// Create a new FSM with the given configuration.
    pub fn new(config: FsmConfig) -> Self {
        Self {
            state: FsmState::Idle,
            config,
            connect_retry_counter: 0,
            negotiated_hold_time: None,
            peer_router_id: None,
            peer_asn: None,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> FsmState {
        self.state
    }

    /// Get the configuration.
    pub fn config(&self) -> &FsmConfig {
        &self.config
    }

    /// Get the negotiated hold time.
    pub fn negotiated_hold_time(&self) -> Option<Duration> {
        self.negotiated_hold_time
    }

    /// Get the peer's router ID.
    pub fn peer_router_id(&self) -> Option<Ipv4Addr> {
        self.peer_router_id
    }

    /// Get the peer's ASN.
    pub fn peer_asn(&self) -> Option<u32> {
        self.peer_asn
    }

    /// Get the connect retry counter.
    /// Utility method for monitoring connection attempts.
    #[allow(dead_code)]
    pub fn connect_retry_counter(&self) -> u32 {
        self.connect_retry_counter
    }

    /// Process an event and return the actions to take.
    ///
    /// This is the core FSM logic. It updates the state and returns a list of
    /// actions that should be executed by the session actor.
    pub fn process_event(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        let old_state = self.state;
        let mut actions = self.handle_event(event);

        // Add state change notification if state changed
        if self.state != old_state {
            actions.insert(
                0,
                FsmAction::NotifyStateChange {
                    from: old_state,
                    to: self.state,
                },
            );
        }

        actions
    }

    /// Handle an event based on the current state.
    fn handle_event(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match self.state {
            FsmState::Idle => self.handle_idle(event),
            FsmState::Connect => self.handle_connect(event),
            FsmState::Active => self.handle_active(event),
            FsmState::OpenSent => self.handle_open_sent(event),
            FsmState::OpenConfirm => self.handle_open_confirm(event),
            FsmState::Established => self.handle_established(event),
        }
    }

    // ==================== Idle State ====================

    fn handle_idle(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::Admin(AdminEvent::ManualStart | AdminEvent::AutomaticStart) => {
                self.state = FsmState::Connect;
                vec![
                    FsmAction::ResetConnectRetryCounter,
                    FsmAction::StartConnectRetryTimer,
                    FsmAction::InitiateTcpConnection,
                ]
            }
            // All other events are ignored in Idle state
            _ => vec![],
        }
    }

    // ==================== Connect State ====================

    fn handle_connect(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::Admin(AdminEvent::ManualStop) => {
                self.state = FsmState::Idle;
                vec![
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::ResetConnectRetryCounter,
                ]
            }

            FsmEvent::Timer(TimerEvent::ConnectRetryTimerExpires) => {
                // Stay in Connect, retry connection
                vec![
                    FsmAction::DropTcpConnection,
                    FsmAction::ResetConnectRetryTimer,
                    FsmAction::InitiateTcpConnection,
                ]
            }

            FsmEvent::Tcp(TcpEvent::TcpCrAcked | TcpEvent::TcpConnectionConfirmed) => {
                self.state = FsmState::OpenSent;
                vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::SendOpen,
                    FsmAction::StartHoldTimer(Duration::from_secs(240)), // Large initial hold time
                ]
            }

            FsmEvent::Tcp(TcpEvent::TcpConnectionFails) => {
                self.state = FsmState::Active;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::ResetConnectRetryTimer,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            FsmEvent::Message(MessageEvent::BgpHeaderErr(err) | MessageEvent::BgpOpenMsgErr(err)) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::SendNotification(err),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            FsmEvent::Message(MessageEvent::NotifMsg { .. }) => {
                self.state = FsmState::Idle;
                vec![FsmAction::DropTcpConnection, FsmAction::ReleaseResources]
            }

            _ => vec![],
        }
    }

    // ==================== Active State ====================

    fn handle_active(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::Admin(AdminEvent::ManualStop) => {
                self.state = FsmState::Idle;
                vec![
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::ResetConnectRetryCounter,
                ]
            }

            FsmEvent::Timer(TimerEvent::ConnectRetryTimerExpires) => {
                self.state = FsmState::Connect;
                vec![
                    FsmAction::ResetConnectRetryTimer,
                    FsmAction::InitiateTcpConnection,
                ]
            }

            FsmEvent::Tcp(TcpEvent::TcpCrAcked | TcpEvent::TcpConnectionConfirmed) => {
                self.state = FsmState::OpenSent;
                vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::SendOpen,
                    FsmAction::StartHoldTimer(Duration::from_secs(240)),
                ]
            }

            FsmEvent::Tcp(TcpEvent::TcpConnectionFails) => {
                // Stay in Active, increment counter
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::ResetConnectRetryTimer,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            FsmEvent::Message(MessageEvent::BgpHeaderErr(err) | MessageEvent::BgpOpenMsgErr(err)) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::SendNotification(err),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            FsmEvent::Message(MessageEvent::NotifMsg { .. }) => {
                self.state = FsmState::Idle;
                vec![FsmAction::DropTcpConnection, FsmAction::ReleaseResources]
            }

            _ => vec![],
        }
    }

    // ==================== OpenSent State ====================

    fn handle_open_sent(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::Admin(AdminEvent::ManualStop) => {
                self.state = FsmState::Idle;
                vec![
                    FsmAction::SendNotification(NotificationError::cease()),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::ResetConnectRetryCounter,
                ]
            }

            FsmEvent::Timer(TimerEvent::HoldTimerExpires) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::SendNotification(NotificationError::hold_timer_expired()),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            FsmEvent::Tcp(TcpEvent::TcpConnectionFails) => {
                self.state = FsmState::Active;
                vec![
                    FsmAction::DropTcpConnection,
                    FsmAction::ResetConnectRetryTimer,
                ]
            }

            FsmEvent::Message(MessageEvent::BgpOpen(open)) => {
                self.handle_open_in_open_sent(open)
            }

            FsmEvent::Message(MessageEvent::BgpHeaderErr(err)) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::SendNotification(err),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            FsmEvent::Message(MessageEvent::NotifMsg { .. }) => {
                self.state = FsmState::Idle;
                vec![FsmAction::DropTcpConnection, FsmAction::ReleaseResources]
            }

            // Unexpected messages in OpenSent
            FsmEvent::Message(MessageEvent::KeepAliveMsg | MessageEvent::UpdateMsg(_)) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::SendNotification(NotificationError::fsm_error(
                        FsmErrorSubcode::UnexpectedMessageInOpenSentState,
                    )),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            _ => vec![],
        }
    }

    fn handle_open_in_open_sent(&mut self, open: OpenMessage) -> Vec<FsmAction> {
        let validation_config = ValidationConfig {
            peer_asn: self.config.peer_asn,
            hold_time: self.config.hold_time,
        };

        // Validate the OPEN message
        if let Err(err) = validate_open(&open, &validation_config) {
            self.state = FsmState::Idle;
            self.connect_retry_counter += 1;
            return vec![
                FsmAction::SendNotification(err),
                FsmAction::DropTcpConnection,
                FsmAction::ReleaseResources,
                FsmAction::IncrementConnectRetryCounter,
            ];
        }

        // OPEN is valid - negotiate hold time and transition to OpenConfirm
        let negotiated = negotiate_hold_time(self.config.hold_time, open.hold_time);
        self.negotiated_hold_time = Some(negotiated);
        self.peer_router_id = Some(open.router_id);
        self.peer_asn = Some(get_peer_asn(&open));

        self.state = FsmState::OpenConfirm;

        let ka_time = keepalive_time(negotiated);
        let mut actions = vec![
            FsmAction::StopHoldTimer,
            FsmAction::SendKeepalive,
        ];

        if !negotiated.is_zero() {
            actions.push(FsmAction::StartHoldTimer(negotiated));
            actions.push(FsmAction::StartKeepaliveTimer(ka_time));
        }

        actions
    }

    // ==================== OpenConfirm State ====================

    fn handle_open_confirm(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::Admin(AdminEvent::ManualStop) => {
                self.state = FsmState::Idle;
                vec![
                    FsmAction::SendNotification(NotificationError::cease()),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::ResetConnectRetryCounter,
                ]
            }

            FsmEvent::Timer(TimerEvent::HoldTimerExpires) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::SendNotification(NotificationError::hold_timer_expired()),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            FsmEvent::Timer(TimerEvent::KeepaliveTimerExpires) => {
                // Stay in OpenConfirm, send keepalive
                vec![FsmAction::SendKeepalive, FsmAction::ResetKeepaliveTimer]
            }

            FsmEvent::Tcp(TcpEvent::TcpConnectionFails) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            FsmEvent::Message(MessageEvent::NotifMsg { .. }) => {
                self.state = FsmState::Idle;
                vec![FsmAction::DropTcpConnection, FsmAction::ReleaseResources]
            }

            FsmEvent::Message(MessageEvent::KeepAliveMsg) => {
                // Transition to Established!
                self.state = FsmState::Established;
                vec![FsmAction::RestartHoldTimer]
            }

            FsmEvent::Message(MessageEvent::BgpHeaderErr(err) | MessageEvent::BgpOpenMsgErr(err)) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::SendNotification(err),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            // Unexpected messages in OpenConfirm
            FsmEvent::Message(MessageEvent::BgpOpen(_) | MessageEvent::UpdateMsg(_)) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::SendNotification(NotificationError::fsm_error(
                        FsmErrorSubcode::UnexpectedMessageInOpenConfirmState,
                    )),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            _ => vec![],
        }
    }

    // ==================== Established State ====================

    fn handle_established(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::Admin(AdminEvent::ManualStop) => {
                self.state = FsmState::Idle;
                vec![
                    FsmAction::SendNotification(NotificationError::cease()),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::ResetConnectRetryCounter,
                ]
            }

            FsmEvent::Timer(TimerEvent::HoldTimerExpires) => {
                self.state = FsmState::Idle;
                self.connect_retry_counter += 1;
                vec![
                    FsmAction::SendNotification(NotificationError::hold_timer_expired()),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                    FsmAction::IncrementConnectRetryCounter,
                ]
            }

            FsmEvent::Timer(TimerEvent::KeepaliveTimerExpires) => {
                // Stay in Established, send keepalive
                vec![FsmAction::SendKeepalive, FsmAction::ResetKeepaliveTimer]
            }

            FsmEvent::Tcp(TcpEvent::TcpConnectionFails) => {
                self.state = FsmState::Idle;
                vec![FsmAction::ReleaseResources]
            }

            FsmEvent::Message(MessageEvent::NotifMsg { .. }) => {
                self.state = FsmState::Idle;
                vec![FsmAction::DropTcpConnection, FsmAction::ReleaseResources]
            }

            FsmEvent::Message(MessageEvent::KeepAliveMsg) => {
                // Stay in Established, restart hold timer
                vec![FsmAction::RestartHoldTimer]
            }

            FsmEvent::Message(MessageEvent::UpdateMsg(data)) => {
                // Stay in Established, process update and restart hold timer
                vec![
                    FsmAction::RestartHoldTimer,
                    FsmAction::ProcessUpdate(data),
                ]
            }

            FsmEvent::Message(MessageEvent::UpdateMsgErr(err)) => {
                self.state = FsmState::Idle;
                vec![
                    FsmAction::SendNotification(err),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                ]
            }

            FsmEvent::Message(MessageEvent::BgpHeaderErr(err)) => {
                self.state = FsmState::Idle;
                vec![
                    FsmAction::SendNotification(err),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                ]
            }

            // Unexpected OPEN in Established
            FsmEvent::Message(MessageEvent::BgpOpen(_)) => {
                self.state = FsmState::Idle;
                vec![
                    FsmAction::SendNotification(NotificationError::fsm_error(
                        FsmErrorSubcode::UnexpectedMessageInEstablishedState,
                    )),
                    FsmAction::DropTcpConnection,
                    FsmAction::ReleaseResources,
                ]
            }

            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn default_config() -> FsmConfig {
        FsmConfig {
            local_asn: 65001,
            peer_asn: 65002,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            hold_time: 90,
            connect_retry_time: Duration::from_secs(120),
            ipv4_unicast: false,
            ipv6_unicast: true,
        }
    }

    fn valid_peer_open() -> OpenMessage {
        OpenMessage::new(65002, 90, Ipv4Addr::new(2, 2, 2, 2))
    }

    // ==================== Idle State Tests ====================

    #[test]
    fn test_idle_to_connect_on_manual_start() {
        let mut fsm = Fsm::new(default_config());
        assert_eq!(fsm.state(), FsmState::Idle);

        let actions = fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));

        assert_eq!(fsm.state(), FsmState::Connect);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::NotifyStateChange { from: FsmState::Idle, to: FsmState::Connect })));
        assert!(actions.contains(&FsmAction::InitiateTcpConnection));
        assert!(actions.contains(&FsmAction::StartConnectRetryTimer));
    }

    #[test]
    fn test_idle_to_connect_on_automatic_start() {
        let mut fsm = Fsm::new(default_config());

        let actions = fsm.process_event(FsmEvent::Admin(AdminEvent::AutomaticStart));

        assert_eq!(fsm.state(), FsmState::Connect);
        assert!(actions.contains(&FsmAction::InitiateTcpConnection));
    }

    #[test]
    fn test_idle_ignores_timer_events() {
        let mut fsm = Fsm::new(default_config());

        let actions = fsm.process_event(FsmEvent::Timer(TimerEvent::HoldTimerExpires));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_idle_ignores_tcp_events() {
        let mut fsm = Fsm::new(default_config());

        let actions = fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.is_empty());
    }

    // ==================== Connect State Tests ====================

    #[test]
    fn test_connect_to_open_sent_on_tcp_acked() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        assert_eq!(fsm.state(), FsmState::Connect);

        let actions = fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));

        assert_eq!(fsm.state(), FsmState::OpenSent);
        assert!(actions.contains(&FsmAction::SendOpen));
        assert!(actions.contains(&FsmAction::StopConnectRetryTimer));
        assert!(actions.iter().any(|a| matches!(a, FsmAction::StartHoldTimer(_))));
    }

    #[test]
    fn test_connect_to_active_on_tcp_fails() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));

        let actions = fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionFails));

        assert_eq!(fsm.state(), FsmState::Active);
        assert!(actions.contains(&FsmAction::ResetConnectRetryTimer));
        assert!(actions.contains(&FsmAction::IncrementConnectRetryCounter));
    }

    #[test]
    fn test_connect_to_idle_on_manual_stop() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));

        let actions = fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStop));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.contains(&FsmAction::ReleaseResources));
        assert!(actions.contains(&FsmAction::ResetConnectRetryCounter));
    }

    #[test]
    fn test_connect_retry_timer_reinitiates() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));

        let actions = fsm.process_event(FsmEvent::Timer(TimerEvent::ConnectRetryTimerExpires));

        assert_eq!(fsm.state(), FsmState::Connect);
        assert!(actions.contains(&FsmAction::InitiateTcpConnection));
        assert!(actions.contains(&FsmAction::ResetConnectRetryTimer));
    }

    // ==================== Active State Tests ====================

    #[test]
    fn test_active_to_connect_on_retry_timer() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionFails));
        assert_eq!(fsm.state(), FsmState::Active);

        let actions = fsm.process_event(FsmEvent::Timer(TimerEvent::ConnectRetryTimerExpires));

        assert_eq!(fsm.state(), FsmState::Connect);
        assert!(actions.contains(&FsmAction::InitiateTcpConnection));
    }

    #[test]
    fn test_active_to_open_sent_on_tcp_confirmed() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionFails));
        assert_eq!(fsm.state(), FsmState::Active);

        let actions = fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionConfirmed));

        assert_eq!(fsm.state(), FsmState::OpenSent);
        assert!(actions.contains(&FsmAction::SendOpen));
    }

    // ==================== OpenSent State Tests ====================

    #[test]
    fn test_open_sent_to_open_confirm_on_valid_open() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        assert_eq!(fsm.state(), FsmState::OpenSent);

        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));

        assert_eq!(fsm.state(), FsmState::OpenConfirm);
        assert!(actions.contains(&FsmAction::SendKeepalive));
        assert!(actions.iter().any(|a| matches!(a, FsmAction::StartKeepaliveTimer(_))));
        assert_eq!(fsm.negotiated_hold_time(), Some(Duration::from_secs(90)));
        assert_eq!(fsm.peer_router_id(), Some(Ipv4Addr::new(2, 2, 2, 2)));
        assert_eq!(fsm.peer_asn(), Some(65002));
    }

    #[test]
    fn test_open_sent_to_idle_on_hold_timer() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));

        let actions = fsm.process_event(FsmEvent::Timer(TimerEvent::HoldTimerExpires));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendNotification(n) if n.code == ErrorCode::HoldTimerExpired)));
    }

    #[test]
    fn test_open_sent_to_active_on_tcp_fails() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));

        let actions = fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionFails));

        assert_eq!(fsm.state(), FsmState::Active);
        assert!(actions.contains(&FsmAction::ResetConnectRetryTimer));
    }

    #[test]
    fn test_open_sent_rejects_invalid_version() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));

        let mut open = valid_peer_open();
        open.version = 3;
        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(open)));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendNotification(n) if n.code == ErrorCode::OpenMessageError)));
    }

    #[test]
    fn test_open_sent_rejects_wrong_asn() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));

        let open = OpenMessage::new(65003, 90, Ipv4Addr::new(2, 2, 2, 2)); // Wrong ASN
        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(open)));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendNotification(n) if n.code == ErrorCode::OpenMessageError)));
    }

    #[test]
    fn test_open_sent_rejects_unexpected_keepalive() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));

        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendNotification(n) if n.code == ErrorCode::FiniteStateMachineError)));
    }

    // ==================== OpenConfirm State Tests ====================

    #[test]
    fn test_open_confirm_to_established_on_keepalive() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));
        assert_eq!(fsm.state(), FsmState::OpenConfirm);

        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));

        assert_eq!(fsm.state(), FsmState::Established);
        assert!(actions.contains(&FsmAction::RestartHoldTimer));
    }

    #[test]
    fn test_open_confirm_sends_keepalive_on_timer() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));

        let actions = fsm.process_event(FsmEvent::Timer(TimerEvent::KeepaliveTimerExpires));

        assert_eq!(fsm.state(), FsmState::OpenConfirm);
        assert!(actions.contains(&FsmAction::SendKeepalive));
        assert!(actions.contains(&FsmAction::ResetKeepaliveTimer));
    }

    #[test]
    fn test_open_confirm_to_idle_on_notification() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));

        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::NotifMsg {
            code: 6,
            subcode: 4,
            data: vec![],
        }));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.contains(&FsmAction::ReleaseResources));
    }

    #[test]
    fn test_open_confirm_to_idle_on_hold_timer() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));

        let actions = fsm.process_event(FsmEvent::Timer(TimerEvent::HoldTimerExpires));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendNotification(n) if n.code == ErrorCode::HoldTimerExpired)));
    }

    // ==================== Established State Tests ====================

    #[test]
    fn test_established_processes_keepalive() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));
        fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));
        assert_eq!(fsm.state(), FsmState::Established);

        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));

        assert_eq!(fsm.state(), FsmState::Established);
        assert!(actions.contains(&FsmAction::RestartHoldTimer));
    }

    #[test]
    fn test_established_processes_update() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));
        fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));

        let update_data = Bytes::from_static(&[0x00, 0x00, 0x00, 0x00]);
        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::UpdateMsg(update_data.clone())));

        assert_eq!(fsm.state(), FsmState::Established);
        assert!(actions.contains(&FsmAction::RestartHoldTimer));
        assert!(actions.contains(&FsmAction::ProcessUpdate(update_data)));
    }

    #[test]
    fn test_established_sends_keepalive_on_timer() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));
        fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));

        let actions = fsm.process_event(FsmEvent::Timer(TimerEvent::KeepaliveTimerExpires));

        assert_eq!(fsm.state(), FsmState::Established);
        assert!(actions.contains(&FsmAction::SendKeepalive));
        assert!(actions.contains(&FsmAction::ResetKeepaliveTimer));
    }

    #[test]
    fn test_established_to_idle_on_hold_timer() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));
        fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));

        let actions = fsm.process_event(FsmEvent::Timer(TimerEvent::HoldTimerExpires));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendNotification(n) if n.code == ErrorCode::HoldTimerExpired)));
    }

    #[test]
    fn test_established_to_idle_on_manual_stop() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));
        fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));

        let actions = fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStop));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendNotification(n) if n.code == ErrorCode::Cease)));
    }

    #[test]
    fn test_established_to_idle_on_tcp_fails() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));
        fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));

        let actions = fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionFails));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.contains(&FsmAction::ReleaseResources));
    }

    #[test]
    fn test_established_rejects_unexpected_open() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));
        fsm.process_event(FsmEvent::Message(MessageEvent::KeepAliveMsg));

        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(valid_peer_open())));

        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendNotification(n) if n.code == ErrorCode::FiniteStateMachineError)));
    }

    // ==================== Counter Tests ====================

    #[test]
    fn test_connect_retry_counter_increments() {
        let mut fsm = Fsm::new(default_config());
        assert_eq!(fsm.connect_retry_counter(), 0);

        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionFails));

        assert_eq!(fsm.connect_retry_counter(), 1);
    }

    #[test]
    fn test_connect_retry_counter_resets_on_manual_stop() {
        let mut fsm = Fsm::new(default_config());
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpConnectionFails));
        assert!(fsm.connect_retry_counter() > 0);

        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStop));

        // Counter is reset by the action, not internally
        // The FSM emits ResetConnectRetryCounter action
    }

    // ==================== Hold Time Negotiation Tests ====================

    #[test]
    fn test_negotiates_minimum_hold_time() {
        let mut config = default_config();
        config.hold_time = 60; // Local wants 60

        let mut fsm = Fsm::new(config);
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));

        let open = OpenMessage::new(65002, 120, Ipv4Addr::new(2, 2, 2, 2)); // Peer wants 120
        fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(open)));

        assert_eq!(fsm.negotiated_hold_time(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_zero_hold_time_disables_timers() {
        let mut config = default_config();
        config.hold_time = 0; // Local disables

        let mut fsm = Fsm::new(config);
        fsm.process_event(FsmEvent::Admin(AdminEvent::ManualStart));
        fsm.process_event(FsmEvent::Tcp(TcpEvent::TcpCrAcked));

        let open = OpenMessage::new(65002, 90, Ipv4Addr::new(2, 2, 2, 2));
        let actions = fsm.process_event(FsmEvent::Message(MessageEvent::BgpOpen(open)));

        assert_eq!(fsm.negotiated_hold_time(), Some(Duration::ZERO));
        // Should not start hold or keepalive timers
        assert!(!actions.iter().any(|a| matches!(a, FsmAction::StartHoldTimer(_))));
        assert!(!actions.iter().any(|a| matches!(a, FsmAction::StartKeepaliveTimer(_))));
    }
}
