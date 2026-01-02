//! Peer Manager for dynamic BGP peer management.
//!
//! This module provides the PeerManager actor which handles:
//! - Dynamic addition and removal of BGP peers at runtime
//! - Tracking peer sessions with stable peer IDs
//! - Coordinating with RibActor for route cleanup on peer removal

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, watch, RwLock};

use crate::api::server::{DaemonState, NeighborState};
use crate::bgp::{SessionCommand, SessionState};
use crate::config::PeerConfig;
use crate::error::PeerManagerError;
use crate::rib::RibHandle;

/// Unique peer ID generator.
static NEXT_PEER_ID: AtomicU32 = AtomicU32::new(1);

/// Generate a new unique peer ID.
fn generate_peer_id() -> u32 {
    NEXT_PEER_ID.fetch_add(1, Ordering::SeqCst)
}

/// Information about a managed peer.
#[derive(Debug)]
pub struct PeerInfo {
    pub id: u32,
    pub config: PeerConfig,
    pub peer_idx: usize,
    /// Command sender for the session. None if session not yet spawned.
    pub cmd_tx: Option<mpsc::Sender<SessionCommand>>,
}

/// Commands sent to the PeerManager.
pub enum PeerManagerCommand {
    /// Add a new peer dynamically.
    AddPeer {
        config: PeerConfig,
        response: oneshot::Sender<Result<u32, PeerManagerError>>,
    },
    /// Remove a peer by ID.
    RemovePeer {
        peer_id: u32,
        response: oneshot::Sender<Result<(), PeerManagerError>>,
    },
    /// Get all managed peers.
    GetPeers {
        response: oneshot::Sender<Vec<(u32, PeerConfig)>>,
    },
    /// Register a peer that was started at daemon startup (for integration with existing peers).
    RegisterStartupPeer {
        peer_idx: usize,
        config: PeerConfig,
        cmd_tx: mpsc::Sender<SessionCommand>,
    },
}

/// The PeerManager actor.
pub struct PeerManager {
    /// Map from peer ID to peer info.
    peers: HashMap<u32, PeerInfo>,
    /// Map from peer_idx to peer_id (for looking up ID from neighbor index).
    idx_to_id: HashMap<usize, u32>,
    /// Command receiver.
    command_rx: mpsc::Receiver<PeerManagerCommand>,
    /// Shared daemon state.
    state: Arc<RwLock<DaemonState>>,
    /// RIB handle for route cleanup.
    rib_handle: RibHandle,
    /// Shutdown signal receiver (reserved for future use).
    #[allow(dead_code)]
    shutdown_rx: watch::Receiver<bool>,
    /// Local ASN for new sessions (reserved for session spawning).
    #[allow(dead_code)]
    local_asn: u32,
    /// Router ID for new sessions (reserved for session spawning).
    #[allow(dead_code)]
    router_id: Ipv4Addr,
    /// Prefixes to announce to new peers (reserved for session spawning).
    #[allow(dead_code)]
    prefixes: Vec<String>,
    /// Hold time for new sessions (reserved for session spawning).
    #[allow(dead_code)]
    hold_time: u16,
    /// Connect retry time for new sessions (reserved for session spawning).
    #[allow(dead_code)]
    connect_retry_time: u64,
    /// IPv4 unicast capability (reserved for session spawning).
    #[allow(dead_code)]
    ipv4_unicast: bool,
    /// IPv6 unicast capability (reserved for session spawning).
    #[allow(dead_code)]
    ipv6_unicast: bool,
    /// Next peer index to assign.
    next_peer_idx: usize,
}

/// Configuration for creating a PeerManager.
pub struct PeerManagerConfig {
    pub state: Arc<RwLock<DaemonState>>,
    pub rib_handle: RibHandle,
    pub shutdown_rx: watch::Receiver<bool>,
    pub local_asn: u32,
    pub router_id: Ipv4Addr,
    pub prefixes: Vec<String>,
    pub hold_time: u16,
    pub connect_retry_time: u64,
    pub ipv4_unicast: bool,
    pub ipv6_unicast: bool,
    pub initial_peer_count: usize,
}

impl PeerManager {
    /// Create a new PeerManager.
    pub fn new(
        command_rx: mpsc::Receiver<PeerManagerCommand>,
        config: PeerManagerConfig,
    ) -> Self {
        Self {
            peers: HashMap::new(),
            idx_to_id: HashMap::new(),
            command_rx,
            state: config.state,
            rib_handle: config.rib_handle,
            shutdown_rx: config.shutdown_rx,
            local_asn: config.local_asn,
            router_id: config.router_id,
            prefixes: config.prefixes,
            hold_time: config.hold_time,
            connect_retry_time: config.connect_retry_time,
            ipv4_unicast: config.ipv4_unicast,
            ipv6_unicast: config.ipv6_unicast,
            next_peer_idx: config.initial_peer_count,
        }
    }

    /// Run the PeerManager event loop.
    pub async fn run(mut self) {
        while let Some(cmd) = self.command_rx.recv().await {
            match cmd {
                PeerManagerCommand::AddPeer { config, response } => {
                    let result = self.handle_add_peer(config).await;
                    // Response channel closed means requester gave up - not an error
                    drop(response.send(result));
                }
                PeerManagerCommand::RemovePeer { peer_id, response } => {
                    let result = self.handle_remove_peer(peer_id).await;
                    drop(response.send(result));
                }
                PeerManagerCommand::GetPeers { response } => {
                    let peers: Vec<_> = self
                        .peers
                        .iter()
                        .map(|(id, info)| (*id, info.config.clone()))
                        .collect();
                    drop(response.send(peers));
                }
                PeerManagerCommand::RegisterStartupPeer {
                    peer_idx,
                    config,
                    cmd_tx,
                } => {
                    let peer_id = generate_peer_id();
                    let info = PeerInfo {
                        id: peer_id,
                        config,
                        peer_idx,
                        cmd_tx: Some(cmd_tx),
                    };
                    self.peers.insert(peer_id, info);
                    self.idx_to_id.insert(peer_idx, peer_id);
                    tracing::debug!(peer_id = peer_id, peer_idx = peer_idx, "Registered startup peer");
                }
            }
        }
    }

    /// Handle adding a new peer.
    async fn handle_add_peer(&mut self, config: PeerConfig) -> Result<u32, PeerManagerError> {
        // Validate the peer config
        if config.interface.is_empty() {
            return Err(PeerManagerError::InvalidConfig(
                "interface is required".to_string(),
            ));
        }

        // Check for duplicate peer on same interface
        for info in self.peers.values() {
            if info.config.interface == config.interface {
                if config.address.is_none() && info.config.address.is_none() {
                    return Err(PeerManagerError::PeerExists {
                        interface: config.interface,
                    });
                }
                if let (Some(addr1), Some(addr2)) = (&config.address, &info.config.address) {
                    if addr1 == addr2 {
                        return Err(PeerManagerError::PeerExistsWithAddress {
                            address: addr1.clone(),
                            interface: config.interface,
                        });
                    }
                }
            }
        }

        let peer_id = generate_peer_id();
        let peer_idx = self.next_peer_idx;
        self.next_peer_idx += 1;

        // Add neighbor state to DaemonState
        {
            let mut s = self.state.write().await;
            s.neighbors.push(NeighborState {
                address: config.address.clone().unwrap_or_default(),
                interface: config.interface.clone(),
                remote_asn: config.remote_asn,
                state: SessionState::Idle,
                uptime_secs: 0,
                prefixes_received: 0,
            });
        }

        // Store peer info (no session spawned yet - cmd_tx is None)
        let info = PeerInfo {
            id: peer_id,
            config: config.clone(),
            peer_idx,
            cmd_tx: None, // Session spawning not yet implemented for dynamic peers
        };
        self.peers.insert(peer_id, info);
        self.idx_to_id.insert(peer_idx, peer_id);

        tracing::info!(
            peer_id = peer_id,
            interface = %config.interface,
            address = ?config.address,
            "Added new peer dynamically (session spawning not yet implemented)"
        );

        Ok(peer_id)
    }

    /// Handle removing a peer.
    async fn handle_remove_peer(&mut self, peer_id: u32) -> Result<(), PeerManagerError> {
        let info = match self.peers.remove(&peer_id) {
            Some(info) => info,
            None => return Err(PeerManagerError::PeerNotFound(peer_id)),
        };

        self.idx_to_id.remove(&info.peer_idx);

        // Send stop command to the session if it exists
        if let Some(cmd_tx) = &info.cmd_tx {
            if let Err(e) = cmd_tx.send(SessionCommand::Stop).await {
                tracing::warn!(peer_id = peer_id, error = %e, "Failed to send stop command to peer");
            }
        }

        // Remove routes from this peer
        let removed = self.rib_handle.remove_peer_routes(info.peer_idx).await;
        if removed > 0 {
            tracing::info!(
                peer_id = peer_id,
                routes_removed = removed,
                "Removed {} routes from peer",
                removed
            );
        }

        // Update DaemonState - mark as removed (we don't remove from the Vec to preserve indices)
        // In a full implementation, we'd need a more sophisticated approach
        {
            let mut s = self.state.write().await;
            if let Some(neighbor) = s.neighbors.get_mut(info.peer_idx) {
                neighbor.state = SessionState::Idle;
                neighbor.prefixes_received = 0;
                neighbor.uptime_secs = 0;
            }
        }

        tracing::info!(
            peer_id = peer_id,
            interface = %info.config.interface,
            "Removed peer"
        );

        Ok(())
    }
}

/// Handle for sending commands to the PeerManager.
#[derive(Clone)]
pub struct PeerManagerHandle {
    sender: mpsc::Sender<PeerManagerCommand>,
}

impl PeerManagerHandle {
    /// Create a new PeerManagerHandle.
    pub fn new(sender: mpsc::Sender<PeerManagerCommand>) -> Self {
        Self { sender }
    }

    /// Add a new peer.
    pub async fn add_peer(&self, config: PeerConfig) -> Result<u32, PeerManagerError> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(PeerManagerCommand::AddPeer {
                config,
                response: tx,
            })
            .await
            .is_ok()
        {
            rx.await.unwrap_or_else(|_| {
                Err(PeerManagerError::InvalidConfig("channel closed".to_string()))
            })
        } else {
            Err(PeerManagerError::InvalidConfig(
                "failed to send command".to_string(),
            ))
        }
    }

    /// Remove a peer by ID.
    pub async fn remove_peer(&self, peer_id: u32) -> Result<(), PeerManagerError> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(PeerManagerCommand::RemovePeer {
                peer_id,
                response: tx,
            })
            .await
            .is_ok()
        {
            rx.await.unwrap_or_else(|_| {
                Err(PeerManagerError::InvalidConfig("channel closed".to_string()))
            })
        } else {
            Err(PeerManagerError::InvalidConfig(
                "failed to send command".to_string(),
            ))
        }
    }

    /// Get all managed peers.
    pub async fn get_peers(&self) -> Vec<(u32, PeerConfig)> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(PeerManagerCommand::GetPeers { response: tx })
            .await
            .is_ok()
        {
            rx.await.unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Register a peer that was started at daemon startup.
    pub async fn register_startup_peer(
        &self,
        peer_idx: usize,
        config: PeerConfig,
        cmd_tx: mpsc::Sender<SessionCommand>,
    ) {
        let _ = self
            .sender
            .send(PeerManagerCommand::RegisterStartupPeer {
                peer_idx,
                config,
                cmd_tx,
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::{RibActor, RibCommand, RibHandle};

    /// Create test fixtures for PeerManager tests.
    async fn create_test_fixtures() -> (PeerManagerHandle, Arc<RwLock<DaemonState>>) {
        // Create RIB
        let (rib_tx, rib_rx) = mpsc::channel::<RibCommand>(32);
        let (rib_actor, event_tx) = RibActor::new(rib_rx, false, None, None).unwrap();
        let rib_handle = RibHandle::new(rib_tx, event_tx);
        tokio::spawn(rib_actor.run());

        // Create DaemonState
        let state = Arc::new(RwLock::new(DaemonState::new(
            65000,
            "1.1.1.1".to_string(),
            rib_handle.clone(),
        )));

        // Create shutdown channel
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        // Create PeerManager
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let config = PeerManagerConfig {
            state: state.clone(),
            rib_handle,
            shutdown_rx,
            local_asn: 65000,
            router_id: "1.1.1.1".parse().unwrap(),
            prefixes: vec![],
            hold_time: 90,
            connect_retry_time: 30,
            ipv4_unicast: true,
            ipv6_unicast: true,
            initial_peer_count: 0,
        };

        let peer_manager = PeerManager::new(cmd_rx, config);
        tokio::spawn(peer_manager.run());

        let handle = PeerManagerHandle::new(cmd_tx);
        (handle, state)
    }

    #[tokio::test]
    async fn test_add_peer_success() {
        let (handle, state) = create_test_fixtures().await;

        let config = PeerConfig {
            interface: "eth0".to_string(),
            address: Some("192.168.1.1".to_string()),
            remote_asn: Some(65001),
            session_mode: Default::default(),
        };

        let result = handle.add_peer(config).await;
        assert!(result.is_ok());
        let peer_id = result.unwrap();
        assert!(peer_id > 0);

        // Verify peer was added to state
        let s = state.read().await;
        assert_eq!(s.neighbors.len(), 1);
        assert_eq!(s.neighbors[0].address, "192.168.1.1");
        assert_eq!(s.neighbors[0].interface, "eth0");
        assert_eq!(s.neighbors[0].remote_asn, Some(65001));
    }

    #[tokio::test]
    async fn test_add_peer_missing_interface() {
        let (handle, _state) = create_test_fixtures().await;

        let config = PeerConfig {
            interface: "".to_string(),
            address: Some("192.168.1.1".to_string()),
            remote_asn: Some(65001),
            session_mode: Default::default(),
        };

        let result = handle.add_peer(config).await;
        assert!(matches!(result, Err(PeerManagerError::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn test_add_peer_duplicate_neighbor_discovery() {
        let (handle, _state) = create_test_fixtures().await;

        // Add first peer with neighbor discovery (no address)
        let config1 = PeerConfig {
            interface: "eth0".to_string(),
            address: None,
            remote_asn: None,
            session_mode: Default::default(),
        };
        let result1 = handle.add_peer(config1).await;
        assert!(result1.is_ok());

        // Try to add second peer on same interface with neighbor discovery
        let config2 = PeerConfig {
            interface: "eth0".to_string(),
            address: None,
            remote_asn: None,
            session_mode: Default::default(),
        };
        let result2 = handle.add_peer(config2).await;
        assert!(matches!(result2, Err(PeerManagerError::PeerExists { .. })));
    }

    #[tokio::test]
    async fn test_add_peer_duplicate_address() {
        let (handle, _state) = create_test_fixtures().await;

        // Add first peer
        let config1 = PeerConfig {
            interface: "eth0".to_string(),
            address: Some("192.168.1.1".to_string()),
            remote_asn: Some(65001),
            session_mode: Default::default(),
        };
        let result1 = handle.add_peer(config1).await;
        assert!(result1.is_ok());

        // Try to add second peer with same address on same interface
        let config2 = PeerConfig {
            interface: "eth0".to_string(),
            address: Some("192.168.1.1".to_string()),
            remote_asn: Some(65002),
            session_mode: Default::default(),
        };
        let result2 = handle.add_peer(config2).await;
        assert!(matches!(
            result2,
            Err(PeerManagerError::PeerExistsWithAddress { .. })
        ));
    }

    #[tokio::test]
    async fn test_add_peer_different_addresses_same_interface() {
        let (handle, state) = create_test_fixtures().await;

        // Add first peer
        let config1 = PeerConfig {
            interface: "eth0".to_string(),
            address: Some("192.168.1.1".to_string()),
            remote_asn: Some(65001),
            session_mode: Default::default(),
        };
        let result1 = handle.add_peer(config1).await;
        assert!(result1.is_ok());

        // Add second peer with different address on same interface - should succeed
        let config2 = PeerConfig {
            interface: "eth0".to_string(),
            address: Some("192.168.1.2".to_string()),
            remote_asn: Some(65002),
            session_mode: Default::default(),
        };
        let result2 = handle.add_peer(config2).await;
        assert!(result2.is_ok());

        // Verify both peers are in state
        let s = state.read().await;
        assert_eq!(s.neighbors.len(), 2);
    }

    #[tokio::test]
    async fn test_remove_peer_success() {
        let (handle, state) = create_test_fixtures().await;

        // Add a peer
        let config = PeerConfig {
            interface: "eth0".to_string(),
            address: Some("192.168.1.1".to_string()),
            remote_asn: Some(65001),
            session_mode: Default::default(),
        };
        let peer_id = handle.add_peer(config).await.unwrap();

        // Verify peer was added
        {
            let s = state.read().await;
            assert_eq!(s.neighbors.len(), 1);
        }

        // Remove the peer
        let result = handle.remove_peer(peer_id).await;
        assert!(result.is_ok());

        // Verify peer state was reset
        let s = state.read().await;
        assert_eq!(s.neighbors[0].state, SessionState::Idle);
        assert_eq!(s.neighbors[0].prefixes_received, 0);
    }

    #[tokio::test]
    async fn test_remove_peer_not_found() {
        let (handle, _state) = create_test_fixtures().await;

        let result = handle.remove_peer(99999).await;
        assert!(matches!(result, Err(PeerManagerError::PeerNotFound(99999))));
    }

    #[tokio::test]
    async fn test_get_peers() {
        let (handle, _state) = create_test_fixtures().await;

        // Add multiple peers
        let config1 = PeerConfig {
            interface: "eth0".to_string(),
            address: Some("192.168.1.1".to_string()),
            remote_asn: Some(65001),
            session_mode: Default::default(),
        };
        let config2 = PeerConfig {
            interface: "eth1".to_string(),
            address: Some("192.168.2.1".to_string()),
            remote_asn: Some(65002),
            session_mode: Default::default(),
        };

        let _ = handle.add_peer(config1.clone()).await.unwrap();
        let _ = handle.add_peer(config2.clone()).await.unwrap();

        // Get peers
        let peers = handle.get_peers().await;
        assert_eq!(peers.len(), 2);

        // Verify peers data
        let interfaces: Vec<_> = peers.iter().map(|(_, c)| c.interface.clone()).collect();
        assert!(interfaces.contains(&"eth0".to_string()));
        assert!(interfaces.contains(&"eth1".to_string()));
    }

    #[tokio::test]
    async fn test_register_startup_peer() {
        let (handle, _state) = create_test_fixtures().await;

        let (cmd_tx, _cmd_rx) = mpsc::channel::<SessionCommand>(16);

        let config = PeerConfig {
            interface: "eth0".to_string(),
            address: Some("192.168.1.1".to_string()),
            remote_asn: Some(65001),
            session_mode: Default::default(),
        };

        // Register a startup peer
        handle.register_startup_peer(0, config.clone(), cmd_tx).await;

        // Give time for the async registration
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Get peers and verify the startup peer is registered
        let peers = handle.get_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].1.interface, "eth0");
    }
}
