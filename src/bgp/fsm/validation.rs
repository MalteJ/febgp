use std::net::Ipv4Addr;
use std::time::Duration;

use super::error::NotificationError;
use crate::bgp::message::{Capability, OpenMessage};

/// Configuration for OPEN message validation.
///
/// The `hold_time` field is included for future use in hold time validation
/// (checking if peer's hold time is acceptable to us). Currently only the
/// peer's hold time is validated against RFC minimums.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Expected peer ASN. If 0, any ASN is accepted.
    pub peer_asn: u32,
    /// Local hold time for negotiation (for future validation).
    pub hold_time: u16,
}

/// Validate an OPEN message per RFC 4271 Section 6.2.
///
/// Returns Ok(()) if valid, or Err with appropriate NOTIFICATION error.
pub fn validate_open(open: &OpenMessage, config: &ValidationConfig) -> Result<(), NotificationError> {
    // 1. Version MUST be 4
    if open.version != 4 {
        return Err(NotificationError::unsupported_version(4));
    }

    // 2. Hold Time validation: must be 0 or >= 3 seconds
    if open.hold_time != 0 && open.hold_time < 3 {
        return Err(NotificationError::unacceptable_hold_time());
    }

    // 3. BGP Identifier validation
    // Must be valid IPv4 address (not 0.0.0.0, not 255.255.255.255)
    if open.router_id == Ipv4Addr::new(0, 0, 0, 0)
        || open.router_id == Ipv4Addr::new(255, 255, 255, 255)
    {
        return Err(NotificationError::bad_bgp_identifier());
    }

    // 4. AS number validation (if configured)
    if config.peer_asn != 0 {
        let peer_asn = get_peer_asn(open);
        if peer_asn != config.peer_asn {
            return Err(NotificationError::bad_peer_as());
        }
    }

    Ok(())
}

/// Extract the peer's ASN from an OPEN message.
/// Prefers 4-octet AS capability (RFC 6793) over the 2-byte header field.
pub fn get_peer_asn(open: &OpenMessage) -> u32 {
    // Check for 4-octet AS capability first
    for cap in &open.capabilities {
        if let Capability::FourOctetAs { asn } = cap {
            return *asn;
        }
    }
    // Fall back to 2-byte ASN from header
    open.asn as u32
}

/// Negotiate hold time by taking the minimum of local and peer values.
/// Per RFC 4271 Section 4.2, if either is 0, hold timer is disabled.
pub fn negotiate_hold_time(local_hold_time: u16, peer_hold_time: u16) -> Duration {
    if local_hold_time == 0 || peer_hold_time == 0 {
        Duration::ZERO // Hold timer disabled
    } else {
        Duration::from_secs(std::cmp::min(local_hold_time, peer_hold_time) as u64)
    }
}

/// Calculate keepalive timer interval from hold time.
/// Per RFC 4271, keepalive interval is HoldTime / 3.
pub fn keepalive_time(hold_time: Duration) -> Duration {
    if hold_time.is_zero() {
        Duration::ZERO
    } else {
        Duration::from_secs(hold_time.as_secs() / 3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ValidationConfig {
        ValidationConfig {
            peer_asn: 65002,
            hold_time: 90,
        }
    }

    fn valid_open() -> OpenMessage {
        OpenMessage::new(65002, 90, Ipv4Addr::new(2, 2, 2, 2))
    }

    #[test]
    fn test_validate_open_valid() {
        let result = validate_open(&valid_open(), &default_config());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_open_rejects_bad_version() {
        let mut open = valid_open();
        open.version = 3;

        let result = validate_open(&open, &default_config());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, super::super::error::ErrorCode::OpenMessageError);
        assert_eq!(
            err.subcode,
            super::super::error::OpenErrorSubcode::UnsupportedVersionNumber as u8
        );
        assert_eq!(err.data, vec![0, 4]); // Supported version
    }

    #[test]
    fn test_validate_open_rejects_hold_time_one() {
        let mut open = valid_open();
        open.hold_time = 1;

        let result = validate_open(&open, &default_config());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.subcode,
            super::super::error::OpenErrorSubcode::UnacceptableHoldTime as u8
        );
    }

    #[test]
    fn test_validate_open_rejects_hold_time_two() {
        let mut open = valid_open();
        open.hold_time = 2;

        let result = validate_open(&open, &default_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_open_accepts_hold_time_zero() {
        let mut open = valid_open();
        open.hold_time = 0; // Disables hold timer - valid per RFC

        let result = validate_open(&open, &default_config());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_open_accepts_hold_time_three() {
        let mut open = valid_open();
        open.hold_time = 3; // Minimum valid non-zero

        let result = validate_open(&open, &default_config());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_open_rejects_zero_router_id() {
        let mut open = valid_open();
        open.router_id = Ipv4Addr::new(0, 0, 0, 0);

        let result = validate_open(&open, &default_config());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.subcode,
            super::super::error::OpenErrorSubcode::BadBgpIdentifier as u8
        );
    }

    #[test]
    fn test_validate_open_rejects_broadcast_router_id() {
        let mut open = valid_open();
        open.router_id = Ipv4Addr::new(255, 255, 255, 255);

        let result = validate_open(&open, &default_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_open_rejects_wrong_asn() {
        let open = OpenMessage::new(65003, 90, Ipv4Addr::new(2, 2, 2, 2));
        let config = default_config(); // Expects 65002

        let result = validate_open(&open, &config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.subcode,
            super::super::error::OpenErrorSubcode::BadPeerAs as u8
        );
    }

    #[test]
    fn test_validate_open_accepts_any_asn_when_zero() {
        let open = OpenMessage::new(65003, 90, Ipv4Addr::new(2, 2, 2, 2));
        let config = ValidationConfig {
            peer_asn: 0, // Accept any
            hold_time: 90,
        };

        let result = validate_open(&open, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_peer_asn_from_capability() {
        let open = OpenMessage::new(4200000001, 90, Ipv4Addr::new(2, 2, 2, 2));
        // OpenMessage::new adds FourOctetAs capability with real ASN

        let asn = get_peer_asn(&open);
        assert_eq!(asn, 4200000001);
    }

    #[test]
    fn test_get_peer_asn_from_header() {
        let open = OpenMessage {
            version: 4,
            asn: 65001,
            hold_time: 90,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            capabilities: vec![], // No 4-octet AS capability
        };

        let asn = get_peer_asn(&open);
        assert_eq!(asn, 65001);
    }

    #[test]
    fn test_negotiate_hold_time_takes_minimum() {
        assert_eq!(negotiate_hold_time(90, 60), Duration::from_secs(60));
        assert_eq!(negotiate_hold_time(60, 90), Duration::from_secs(60));
        assert_eq!(negotiate_hold_time(90, 90), Duration::from_secs(90));
    }

    #[test]
    fn test_negotiate_hold_time_zero_disables() {
        assert_eq!(negotiate_hold_time(0, 90), Duration::ZERO);
        assert_eq!(negotiate_hold_time(90, 0), Duration::ZERO);
        assert_eq!(negotiate_hold_time(0, 0), Duration::ZERO);
    }

    #[test]
    fn test_keepalive_time_is_one_third() {
        assert_eq!(keepalive_time(Duration::from_secs(90)), Duration::from_secs(30));
        assert_eq!(keepalive_time(Duration::from_secs(60)), Duration::from_secs(20));
        assert_eq!(keepalive_time(Duration::from_secs(30)), Duration::from_secs(10));
    }

    #[test]
    fn test_keepalive_time_zero_when_disabled() {
        assert_eq!(keepalive_time(Duration::ZERO), Duration::ZERO);
    }
}
