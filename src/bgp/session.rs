//! BGP session state types.

use super::fsm::FsmState;

/// BGP session state for API/monitoring purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl From<FsmState> for SessionState {
    fn from(state: FsmState) -> Self {
        match state {
            FsmState::Idle => SessionState::Idle,
            FsmState::Connect => SessionState::Connect,
            FsmState::Active => SessionState::Active,
            FsmState::OpenSent => SessionState::OpenSent,
            FsmState::OpenConfirm => SessionState::OpenConfirm,
            FsmState::Established => SessionState::Established,
        }
    }
}
