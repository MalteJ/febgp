use super::error::NotificationError;
use super::state::FsmState;
use bytes::Bytes;
use std::time::Duration;

/// Actions the FSM requests the session actor to perform.
/// These are returned by `Fsm::process_event()` and executed by the session actor.
///
/// All actions are defined per RFC 4271. Some are not yet used:
/// - `StopKeepaliveTimer`: Currently keepalive timer runs until session ends
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum FsmAction {
    // === Connection actions ===
    /// Initiate a TCP connection to the peer.
    InitiateTcpConnection,
    /// Drop the current TCP connection.
    DropTcpConnection,

    // === Message sending actions ===
    /// Send a BGP OPEN message.
    SendOpen,
    /// Send a BGP KEEPALIVE message.
    SendKeepalive,
    /// Send a BGP NOTIFICATION message and close the connection.
    SendNotification(NotificationError),

    // === Timer actions ===
    /// Start the ConnectRetryTimer.
    StartConnectRetryTimer,
    /// Stop the ConnectRetryTimer.
    StopConnectRetryTimer,
    /// Reset (restart) the ConnectRetryTimer.
    ResetConnectRetryTimer,

    /// Start the HoldTimer with the specified duration.
    StartHoldTimer(Duration),
    /// Stop the HoldTimer.
    StopHoldTimer,
    /// Restart the HoldTimer with the negotiated hold time.
    RestartHoldTimer,

    /// Start the KeepaliveTimer with the specified duration.
    StartKeepaliveTimer(Duration),
    /// Stop the KeepaliveTimer.
    StopKeepaliveTimer,
    /// Reset (restart) the KeepaliveTimer.
    ResetKeepaliveTimer,

    // === Counter actions ===
    /// Increment the ConnectRetryCounter.
    IncrementConnectRetryCounter,
    /// Reset the ConnectRetryCounter to zero.
    ResetConnectRetryCounter,

    // === State change notification ===
    /// Notify external observers of a state change.
    NotifyStateChange { from: FsmState, to: FsmState },

    // === Resource management ===
    /// Release all resources (timers, connection).
    ReleaseResources,

    /// Process a received UPDATE message (for RIB).
    ProcessUpdate(Bytes),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::fsm::error::ErrorCode;

    #[test]
    fn test_action_equality() {
        assert_eq!(FsmAction::SendOpen, FsmAction::SendOpen);
        assert_eq!(FsmAction::SendKeepalive, FsmAction::SendKeepalive);
        assert_ne!(FsmAction::SendOpen, FsmAction::SendKeepalive);
    }

    #[test]
    fn test_notification_action() {
        let err = NotificationError::hold_timer_expired();
        let action = FsmAction::SendNotification(err.clone());

        if let FsmAction::SendNotification(e) = action {
            assert_eq!(e.code, ErrorCode::HoldTimerExpired);
        } else {
            panic!("Expected SendNotification action");
        }
    }

    #[test]
    fn test_state_change_action() {
        let action = FsmAction::NotifyStateChange {
            from: FsmState::Idle,
            to: FsmState::Connect,
        };

        if let FsmAction::NotifyStateChange { from, to } = action {
            assert_eq!(from, FsmState::Idle);
            assert_eq!(to, FsmState::Connect);
        } else {
            panic!("Expected NotifyStateChange action");
        }
    }
}
