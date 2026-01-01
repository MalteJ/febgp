# BGP FSM Implementation Status

This document tracks the implementation status of the BGP Finite State Machine per RFC 4271.

## Design Decisions

- **Connection Mode**: Active only (initiates outgoing connections)
- **Passive Mode**: Not implemented - no listening for incoming connections, no collision detection
- **UPDATE Handling**: Passed as raw bytes to RIB layer (parsing not yet implemented)

## Implemented Features

### FSM States (RFC 4271 Section 8.2.2)

| State | Status | Notes |
|-------|--------|-------|
| Idle | Implemented | Initial state, waits for Start event |
| Connect | Implemented | TCP connection in progress |
| Active | Implemented | Waiting for connection retry |
| OpenSent | Implemented | OPEN sent, awaiting peer OPEN |
| OpenConfirm | Implemented | OPEN exchanged, awaiting KEEPALIVE |
| Established | Implemented | Session up, exchanging routes |

### FSM Events (RFC 4271 Section 8.1.2)

| Event | Status | Notes |
|-------|--------|-------|
| ManualStart (1) | Implemented | Start session via command |
| ManualStop (2) | Implemented | Stop session via command |
| AutomaticStart (3) | Not used | Could be used for auto-restart |
| AutomaticStop (8) | Not used | For deconfiguration |
| ConnectRetryTimer_Expires (9) | Implemented | Retries TCP connection |
| HoldTimer_Expires (10) | Implemented | Sends NOTIFICATION, resets session |
| KeepaliveTimer_Expires (11) | Implemented | Sends KEEPALIVE |
| DelayOpenTimer_Expires (12) | Not implemented | For delayed OPEN (not used) |
| IdleHoldTimer_Expires (13) | Not implemented | For peer oscillation damping |
| TcpConnection_Valid (14) | Implemented | As TcpCrAcked |
| Tcp_CR_Acked (15) | Implemented | TCP connection succeeded |
| TcpConnectionConfirmed (16) | Not implemented | For passive mode |
| TcpConnectionFails (18) | Implemented | TCP error handling |
| BGPOpen (19) | Implemented | OPEN message received |
| BGPHeaderErr (21) | Not implemented | Header validation in transport |
| BGPOpenMsgErr (22) | Implemented | OPEN validation errors |
| NotifMsgVerErr (24) | Not implemented | NOTIFICATION with version error |
| NotifMsg (25) | Implemented | NOTIFICATION received |
| KeepAliveMsg (26) | Implemented | KEEPALIVE received |
| UpdateMsg (27) | Implemented | UPDATE received (raw bytes) |
| UpdateMsgErr (28) | Not implemented | UPDATE validation not done |

### Timers

| Timer | Status | Default | Notes |
|-------|--------|---------|-------|
| ConnectRetryTimer | Implemented | 30s | Time between connection attempts |
| HoldTimer | Implemented | 9s (negotiated) | Dead peer detection |
| KeepaliveTimer | Implemented | hold_time/3 | KEEPALIVE interval |
| DelayOpenTimer | Not implemented | - | For delayed OPEN feature |
| IdleHoldTimer | Not implemented | - | For peer oscillation damping |

Both `hold_time` and `connect_retry_time` are configurable in the TOML config file.

### OPEN Message Validation (RFC 4271 Section 6.2)

| Check | Status | Error Subcode |
|-------|--------|---------------|
| Version = 4 | Implemented | UnsupportedVersionNumber (1) |
| Peer ASN matches | Implemented | BadPeerAs (2) |
| Valid Router ID | Implemented | BadBgpIdentifier (3) |
| Optional params | Not validated | UnsupportedOptionalParameter (4) |
| Hold time >= 3 or 0 | Implemented | UnacceptableHoldTime (6) |
| Capabilities | Not validated | UnsupportedCapability (7) |

### NOTIFICATION Error Codes (RFC 4271 Section 4.5)

| Code | Name | Status |
|------|------|--------|
| 1 | Message Header Error | Subcodes defined, not generated |
| 2 | OPEN Message Error | Implemented |
| 3 | UPDATE Message Error | Subcodes defined, not generated |
| 4 | Hold Timer Expired | Implemented |
| 5 | Finite State Machine Error | Implemented |
| 6 | Cease | Implemented (AdministrativeShutdown only) |

### Capabilities (RFC 5492)

| Capability | Status | Notes |
|------------|--------|-------|
| Multiprotocol (1) | Advertised | IPv4/IPv6 unicast |
| 4-octet AS (65) | Implemented | RFC 6793 |
| Route Refresh | Not implemented | RFC 2918 |
| Graceful Restart | Not implemented | RFC 4724 |

## RIB and Best Path Selection

### Current Implementation

The RIB supports multiple routes per prefix with AS path length based best path selection:
- Routes are stored in a `Vec<RouteEntry>` with peer tracking
- Multiple routes per prefix are kept (one per peer)
- Best path selection based on AS path length (shorter wins)
- ECMP: Equal AS path length routes are all marked as best

### AS Path Length Selection

Per RFC 4271 Section 9.1.2.2, shorter AS paths are preferred:

| Feature | Status | Notes |
|---------|--------|-------|
| AS path length comparison | Implemented | Shorter path wins |
| AS_SET counting | Not implemented | AS_SET counts as 1 |

Integration test: `test_febgp_aspath_selection`

### ECMP (Equal-Cost Multi-Path)

When multiple paths have equal AS path length, all are kept and marked as best:

| Feature | Status | Notes |
|---------|--------|-------|
| Multiple paths per prefix | Implemented | One route per peer per prefix |
| Best path marking | Implemented | All shortest paths marked as best |

Integration test: `test_febgp_ecmp`

### Out of Scope (for now)

The following RFC 4271 Section 9.1.2 decision criteria are not planned for initial implementation:

| Criterion | RFC Section | Notes |
|-----------|-------------|-------|
| LOCAL_PREF | 9.1.2 | eBGP only, no local preference |
| ORIGIN type | 9.1.2.2.c | IGP < EGP < INCOMPLETE |
| MED comparison | 9.1.2.2.d | Multi-exit discriminator |
| eBGP vs iBGP | 9.1.2.2.e | eBGP only, not applicable |
| IGP cost | 9.1.2.2.f | No IGP integration |
| Route age | 9.1.2.2.g | Oldest route preferred |
| Router ID | 9.1.2.2.h | Lowest router ID wins |
| Peer IP | 9.1.2.2.i | Lowest peer IP wins |

## Not Implemented Features

### Passive Mode / Connection Collision
- No listening socket for incoming connections
- No collision detection (RFC 4271 Section 6.8)
- Decision: Simplifies implementation for BGP unnumbered use case

### Peer Oscillation Damping
- IdleHoldTimer not implemented
- No exponential backoff on repeated failures
- Future enhancement for production stability

### UPDATE Message Validation
- UPDATE messages passed as raw bytes
- No path attribute validation
- No NLRI validation
- Error subcodes defined but not generated

### Advanced NOTIFICATION Handling
- Cease subcodes mostly unused:
  - MaximumNumberOfPrefixesReached (prefix limits)
  - PeerDeconfigured (dynamic config)
  - AdministrativeReset (graceful restart)
  - ConnectionRejected (passive mode)
  - ConnectionCollisionResolution (passive mode)
  - OutOfResources (resource limits)

## Test Coverage

- 116 unit tests covering:
  - FSM state transitions
  - OPEN message validation
  - Hold time negotiation
  - Timer behavior
  - Session establishment
  - Error handling
  - Message serialization/deserialization
