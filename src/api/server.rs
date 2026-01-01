use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

use super::proto::{Empty, Neighbor, Route, RoutesResponse, StatusResponse};
use super::FebgpService;
use crate::bgp::SessionState;

/// Shared daemon state accessible by gRPC handlers
pub struct DaemonState {
    pub asn: u32,
    pub router_id: String,
    pub neighbors: Vec<NeighborState>,
    pub routes: Vec<RouteEntry>,
}

pub struct NeighborState {
    pub address: String,
    pub interface: String,
    /// None = not yet learned (BGP unnumbered auto-detection)
    pub remote_asn: Option<u32>,
    pub state: SessionState,
    pub uptime_secs: u64,
    pub prefixes_received: u64,
}

pub struct RouteEntry {
    pub prefix: String,
    pub next_hop: String,
    pub as_path: String,
    pub as_path_len: usize, // For efficient comparison
    pub origin: String,
    pub peer_idx: usize, // Which peer this route came from
    pub best: bool,
}

impl DaemonState {
    pub fn new(asn: u32, router_id: String) -> Self {
        Self {
            asn,
            router_id,
            neighbors: Vec::new(),
            routes: Vec::new(),
        }
    }
}

/// gRPC service implementation
pub struct FebgpServiceImpl {
    state: Arc<RwLock<DaemonState>>,
}

impl FebgpServiceImpl {
    pub fn new(state: Arc<RwLock<DaemonState>>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl FebgpService for FebgpServiceImpl {
    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<StatusResponse>, Status> {
        let state = self.state.read().await;

        let neighbors = state
            .neighbors
            .iter()
            .map(|n| Neighbor {
                address: n.address.clone(),
                interface: n.interface.clone(),
                remote_asn: n.remote_asn.unwrap_or(0), // 0 = not yet learned
                state: format!("{:?}", n.state),
                uptime_secs: n.uptime_secs,
                prefixes_received: n.prefixes_received,
            })
            .collect();

        Ok(Response::new(StatusResponse {
            asn: state.asn,
            router_id: state.router_id.clone(),
            neighbors,
        }))
    }

    async fn get_routes(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<RoutesResponse>, Status> {
        let state = self.state.read().await;

        let routes = state
            .routes
            .iter()
            .map(|r| Route {
                prefix: r.prefix.clone(),
                next_hop: r.next_hop.clone(),
                as_path: r.as_path.clone(),
                origin: r.origin.clone(),
                best: r.best,
            })
            .collect();

        Ok(Response::new(RoutesResponse { routes }))
    }
}
