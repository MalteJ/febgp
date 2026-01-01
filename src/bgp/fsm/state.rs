/// BGP FSM States per RFC 4271 Section 8.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsmState {
    /// Initial state. No resources allocated.
    Idle,
    /// Waiting for TCP connection to complete (active open).
    Connect,
    /// Waiting for TCP connection (after failed active open, will retry).
    Active,
    /// TCP connected, OPEN sent, waiting for peer's OPEN.
    OpenSent,
    /// Received peer's OPEN, sent KEEPALIVE, waiting for peer's KEEPALIVE.
    OpenConfirm,
    /// Session established, can exchange UPDATE messages.
    Established,
}

impl FsmState {
    /// Returns true if resources (TCP connection, timers) should be allocated.
    /// Utility method for resource management.
    #[allow(dead_code)]
    pub fn has_resources(&self) -> bool {
        !matches!(self, FsmState::Idle)
    }

    /// Returns true if the session can exchange UPDATE messages.
    /// Utility method for checking session readiness.
    #[allow(dead_code)]
    pub fn is_established(&self) -> bool {
        matches!(self, FsmState::Established)
    }
}

impl Default for FsmState {
    fn default() -> Self {
        FsmState::Idle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_state_is_idle() {
        assert_eq!(FsmState::default(), FsmState::Idle);
    }

    #[test]
    fn test_has_resources() {
        assert!(!FsmState::Idle.has_resources());
        assert!(FsmState::Connect.has_resources());
        assert!(FsmState::Active.has_resources());
        assert!(FsmState::OpenSent.has_resources());
        assert!(FsmState::OpenConfirm.has_resources());
        assert!(FsmState::Established.has_resources());
    }

    #[test]
    fn test_is_established() {
        assert!(!FsmState::Idle.is_established());
        assert!(!FsmState::Connect.is_established());
        assert!(!FsmState::Active.is_established());
        assert!(!FsmState::OpenSent.is_established());
        assert!(!FsmState::OpenConfirm.is_established());
        assert!(FsmState::Established.is_established());
    }
}
