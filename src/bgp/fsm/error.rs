/// BGP NOTIFICATION Error Codes per RFC 4271 Section 4.5
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    MessageHeaderError = 1,
    OpenMessageError = 2,
    UpdateMessageError = 3,
    HoldTimerExpired = 4,
    FiniteStateMachineError = 5,
    Cease = 6,
}

impl From<ErrorCode> for u8 {
    fn from(code: ErrorCode) -> u8 {
        code as u8
    }
}

/// Message Header Error subcodes per RFC 4271 Section 6.1.
///
/// These subcodes are defined for completeness per the RFC specification.
/// Header validation is currently handled in the transport layer; generating
/// proper NOTIFICATION messages with these subcodes is a future enhancement.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderErrorSubcode {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
}

/// OPEN Message Error subcodes per RFC 4271 Section 6.2.
///
/// All subcodes are defined per RFC. Currently implemented:
/// - `UnsupportedVersionNumber` (1): Sent when peer uses version != 4
/// - `BadPeerAs` (2): Sent when peer AS doesn't match expected
/// - `BadBgpIdentifier` (3): Sent for invalid router ID (0.0.0.0, 255.255.255.255)
/// - `UnacceptableHoldTime` (6): Sent when hold time is 1 or 2 seconds
///
/// Not yet used: `UnsupportedOptionalParameter` (4), `UnsupportedCapability` (7).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpenErrorSubcode {
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    // 5 is deprecated (was AuthenticationFailure)
    UnacceptableHoldTime = 6,
    UnsupportedCapability = 7,
}

/// UPDATE Message Error subcodes per RFC 4271 Section 6.3.
///
/// These subcodes are defined for completeness per the RFC specification.
/// UPDATE message parsing and validation is not yet implemented; the FSM
/// currently passes UPDATE messages through as raw bytes for RIB processing.
/// Proper UPDATE validation with these error subcodes is a future enhancement.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UpdateErrorSubcode {
    MalformedAttributeList = 1,
    UnrecognizedWellKnownAttribute = 2,
    MissingWellKnownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    // 7 is deprecated
    InvalidNextHopAttribute = 8,
    OptionalAttributeError = 9,
    InvalidNetworkField = 10,
    MalformedAsPath = 11,
}

/// FSM Error subcodes per RFC 6608.
///
/// Currently implemented:
/// - `UnexpectedMessageInOpenSentState` (1): Sent for unexpected messages in OpenSent
/// - `UnexpectedMessageInOpenConfirmState` (2): Sent for unexpected messages in OpenConfirm
/// - `UnexpectedMessageInEstablishedState` (3): Sent for unexpected messages in Established
///
/// Not yet used: `UnspecifiedError` (0) - reserved for edge cases.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FsmErrorSubcode {
    UnspecifiedError = 0,
    UnexpectedMessageInOpenSentState = 1,
    UnexpectedMessageInOpenConfirmState = 2,
    UnexpectedMessageInEstablishedState = 3,
}

/// Cease NOTIFICATION subcodes per RFC 4486.
///
/// Currently implemented:
/// - `AdministrativeShutdown` (2): Sent when session is manually stopped
///
/// Not yet used - defined for future features:
/// - `MaximumNumberOfPrefixesReached` (1): Prefix limit enforcement
/// - `PeerDeconfigured` (3): Peer removed from configuration
/// - `AdministrativeReset` (4): Graceful restart requests
/// - `ConnectionRejected` (5): Passive mode connection rejection
/// - `OtherConfigurationChange` (6): Config-triggered session reset
/// - `ConnectionCollisionResolution` (7): Requires passive mode
/// - `OutOfResources` (8): Memory/resource exhaustion handling
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CeaseSubcode {
    MaximumNumberOfPrefixesReached = 1,
    AdministrativeShutdown = 2,
    PeerDeconfigured = 3,
    AdministrativeReset = 4,
    ConnectionRejected = 5,
    OtherConfigurationChange = 6,
    ConnectionCollisionResolution = 7,
    OutOfResources = 8,
}

/// A BGP NOTIFICATION error with code, subcode, and optional data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationError {
    pub code: ErrorCode,
    pub subcode: u8,
    pub data: Vec<u8>,
}

impl NotificationError {
    pub fn new(code: ErrorCode, subcode: u8) -> Self {
        Self {
            code,
            subcode,
            data: Vec::new(),
        }
    }

    pub fn with_data(code: ErrorCode, subcode: u8, data: Vec<u8>) -> Self {
        Self {
            code,
            subcode,
            data,
        }
    }

    /// Create a Hold Timer Expired error.
    pub fn hold_timer_expired() -> Self {
        Self::new(ErrorCode::HoldTimerExpired, 0)
    }

    /// Create a Cease error with Administrative Shutdown subcode.
    pub fn cease() -> Self {
        Self::new(ErrorCode::Cease, CeaseSubcode::AdministrativeShutdown as u8)
    }

    /// Create an FSM error for unexpected message.
    pub fn fsm_error(subcode: FsmErrorSubcode) -> Self {
        Self::new(ErrorCode::FiniteStateMachineError, subcode as u8)
    }

    /// Create an OPEN error for unsupported version.
    pub fn unsupported_version(supported_version: u8) -> Self {
        Self::with_data(
            ErrorCode::OpenMessageError,
            OpenErrorSubcode::UnsupportedVersionNumber as u8,
            vec![0, supported_version],
        )
    }

    /// Create an OPEN error for bad peer AS.
    pub fn bad_peer_as() -> Self {
        Self::new(ErrorCode::OpenMessageError, OpenErrorSubcode::BadPeerAs as u8)
    }

    /// Create an OPEN error for bad BGP identifier.
    pub fn bad_bgp_identifier() -> Self {
        Self::new(
            ErrorCode::OpenMessageError,
            OpenErrorSubcode::BadBgpIdentifier as u8,
        )
    }

    /// Create an OPEN error for unacceptable hold time.
    pub fn unacceptable_hold_time() -> Self {
        Self::new(
            ErrorCode::OpenMessageError,
            OpenErrorSubcode::UnacceptableHoldTime as u8,
        )
    }

    /// Create an UPDATE error for malformed attribute list.
    pub fn malformed_attribute_list() -> Self {
        Self::new(
            ErrorCode::UpdateMessageError,
            UpdateErrorSubcode::MalformedAttributeList as u8,
        )
    }

    /// Create an UPDATE error for missing well-known attribute.
    pub fn missing_well_known_attribute(attr_type: u8) -> Self {
        Self::with_data(
            ErrorCode::UpdateMessageError,
            UpdateErrorSubcode::MissingWellKnownAttribute as u8,
            vec![attr_type],
        )
    }

    /// Create an UPDATE error for invalid ORIGIN attribute.
    pub fn invalid_origin() -> Self {
        Self::new(
            ErrorCode::UpdateMessageError,
            UpdateErrorSubcode::InvalidOriginAttribute as u8,
        )
    }

    /// Create an UPDATE error for malformed AS_PATH.
    pub fn malformed_as_path() -> Self {
        Self::new(
            ErrorCode::UpdateMessageError,
            UpdateErrorSubcode::MalformedAsPath as u8,
        )
    }

    /// Create an UPDATE error for invalid NEXT_HOP attribute.
    pub fn invalid_next_hop(next_hop: &[u8]) -> Self {
        Self::with_data(
            ErrorCode::UpdateMessageError,
            UpdateErrorSubcode::InvalidNextHopAttribute as u8,
            next_hop.to_vec(),
        )
    }

    /// Create an UPDATE error for invalid network field (NLRI).
    pub fn invalid_network_field() -> Self {
        Self::new(
            ErrorCode::UpdateMessageError,
            UpdateErrorSubcode::InvalidNetworkField as u8,
        )
    }

    /// Create an UPDATE error for attribute length error.
    pub fn attribute_length_error(attr_data: &[u8]) -> Self {
        Self::with_data(
            ErrorCode::UpdateMessageError,
            UpdateErrorSubcode::AttributeLengthError as u8,
            attr_data.to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_values() {
        assert_eq!(ErrorCode::MessageHeaderError as u8, 1);
        assert_eq!(ErrorCode::OpenMessageError as u8, 2);
        assert_eq!(ErrorCode::UpdateMessageError as u8, 3);
        assert_eq!(ErrorCode::HoldTimerExpired as u8, 4);
        assert_eq!(ErrorCode::FiniteStateMachineError as u8, 5);
        assert_eq!(ErrorCode::Cease as u8, 6);
    }

    #[test]
    fn test_notification_error_new() {
        let err = NotificationError::new(ErrorCode::Cease, 2);
        assert_eq!(err.code, ErrorCode::Cease);
        assert_eq!(err.subcode, 2);
        assert!(err.data.is_empty());
    }

    #[test]
    fn test_notification_error_with_data() {
        let err = NotificationError::with_data(ErrorCode::OpenMessageError, 1, vec![0, 4]);
        assert_eq!(err.code, ErrorCode::OpenMessageError);
        assert_eq!(err.subcode, 1);
        assert_eq!(err.data, vec![0, 4]);
    }

    #[test]
    fn test_hold_timer_expired() {
        let err = NotificationError::hold_timer_expired();
        assert_eq!(err.code, ErrorCode::HoldTimerExpired);
        assert_eq!(err.subcode, 0);
    }

    #[test]
    fn test_cease() {
        let err = NotificationError::cease();
        assert_eq!(err.code, ErrorCode::Cease);
        assert_eq!(err.subcode, CeaseSubcode::AdministrativeShutdown as u8);
    }

    #[test]
    fn test_unsupported_version() {
        let err = NotificationError::unsupported_version(4);
        assert_eq!(err.code, ErrorCode::OpenMessageError);
        assert_eq!(err.subcode, OpenErrorSubcode::UnsupportedVersionNumber as u8);
        assert_eq!(err.data, vec![0, 4]);
    }
}
