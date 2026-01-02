//! Error types for FeBGP.
//!
//! This module provides unified error types using thiserror for consistent
//! error handling throughout the codebase.

use std::io;
use thiserror::Error;

/// Top-level error type for FeBGP operations.
#[derive(Error, Debug)]
pub enum FebgpError {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Transport layer error.
    #[error("transport error: {0}")]
    Transport(#[from] crate::bgp::transport::TransportError),

    /// RIB error.
    #[error("RIB error: {0}")]
    Rib(#[from] RibError),

    /// Peer manager error.
    #[error("peer manager error: {0}")]
    PeerManager(#[from] PeerManagerError),

    /// Netlink error.
    #[error("netlink error: {0}")]
    Netlink(#[from] NetlinkError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Errors that can occur in the RIB.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RibError {
    /// Invalid prefix format.
    #[error("invalid prefix: {0}")]
    InvalidPrefix(String),

    /// Route not found.
    #[error("route not found: {0}")]
    RouteNotFound(String),

    /// Route already exists.
    #[error("route already exists: {0}")]
    DuplicateRoute(String),

    /// Channel communication error.
    #[error("channel error: {0}")]
    ChannelError(String),
}

/// Errors that can occur in the peer manager.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PeerManagerError {
    /// Peer already exists.
    #[error("peer already exists on interface {interface}")]
    PeerExists { interface: String },

    /// Peer already exists with specific address.
    #[error("peer already exists with address {address} on interface {interface}")]
    PeerExistsWithAddress { address: String, interface: String },

    /// Peer not found.
    #[error("peer not found: {0}")]
    PeerNotFound(u32),

    /// Invalid peer configuration.
    #[error("invalid peer configuration: {0}")]
    InvalidConfig(String),
}

/// Errors that can occur in netlink operations.
#[derive(Error, Debug)]
pub enum NetlinkError {
    /// Failed to create netlink connection.
    #[error("failed to create netlink connection: {0}")]
    ConnectionFailed(#[source] io::Error),

    /// Failed to add route.
    #[error("failed to add route to {prefix}: {message}")]
    AddRouteFailed { prefix: String, message: String },

    /// Failed to remove route.
    #[error("failed to remove route for {prefix}: {message}")]
    RemoveRouteFailed { prefix: String, message: String },

    /// Failed to parse address.
    #[error("failed to parse address: {0}")]
    InvalidAddress(String),

    /// Failed to parse prefix.
    #[error("failed to parse prefix: {0}")]
    InvalidPrefix(String),

    /// Netlink protocol error.
    #[error("netlink error: {0}")]
    Protocol(String),
}
