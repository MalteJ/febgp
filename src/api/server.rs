use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};
use tonic::{Request, Response, Status};

use super::proto::{
    route_update::UpdateType, AddPeerRequest, AddPeerResponse, AddRouteRequest, AddRouteResponse,
    Empty, Neighbor, RemovePeerRequest, RemovePeerResponse, Route, RouteUpdate, RoutesResponse,
    StatusResponse, WithdrawRouteRequest, WithdrawRouteResponse,
};
use super::FebgpService;
use crate::bgp::SessionState;
use crate::config::PeerConfig;
use crate::peer_manager::PeerManagerHandle;
use crate::rib::{ApiRoute, RibHandle, RouteEvent};

/// Shared daemon state accessible by gRPC handlers
pub struct DaemonState {
    pub asn: u32,
    pub router_id: String,
    pub neighbors: Vec<NeighborState>,
    pub rib_handle: RibHandle,
    pub peer_manager: Option<PeerManagerHandle>,
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

impl DaemonState {
    pub fn new(asn: u32, router_id: String, rib_handle: RibHandle) -> Self {
        Self {
            asn,
            router_id,
            neighbors: Vec::new(),
            rib_handle,
            peer_manager: None,
        }
    }

    /// Set the peer manager handle.
    pub fn set_peer_manager(&mut self, handle: PeerManagerHandle) {
        self.peer_manager = Some(handle);
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
        // Clone the handle so we can drop the lock before awaiting
        let rib_handle = {
            let state = self.state.read().await;
            state.rib_handle.clone()
        };

        let routes = rib_handle
            .get_routes()
            .await
            .iter()
            .map(|r| Route {
                prefix: r.prefix.clone(),
                next_hop: r.next_hop.clone(),
                as_path: r.as_path.clone(),
                origin: r.origin.clone(),
                best: r.best,
                peer_id: r.peer_idx as u32,
            })
            .collect();

        Ok(Response::new(RoutesResponse { routes }))
    }

    type SubscribeRoutesStream =
        Pin<Box<dyn Stream<Item = Result<RouteUpdate, Status>> + Send + 'static>>;

    async fn subscribe_routes(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::SubscribeRoutesStream>, Status> {
        // Clone the handle so we can drop the lock before subscribing
        let rib_handle = {
            let state = self.state.read().await;
            state.rib_handle.clone()
        };

        // Subscribe to route events
        let rx = rib_handle.subscribe_updates();

        // Convert broadcast receiver to a stream of RouteUpdate messages
        let stream = BroadcastStream::new(rx).filter_map(|result| {
            match result {
                Ok(event) => {
                    let update = match event {
                        RouteEvent::Added(entry) => RouteUpdate {
                            update_type: UpdateType::Added.into(),
                            route: Some(Route {
                                prefix: entry.prefix,
                                next_hop: entry.next_hop,
                                as_path: entry.as_path,
                                origin: entry.origin,
                                best: entry.best,
                                peer_id: entry.peer_idx as u32,
                            }),
                        },
                        RouteEvent::Withdrawn {
                            prefix,
                            next_hop,
                            peer_idx,
                        } => RouteUpdate {
                            update_type: UpdateType::Withdrawn.into(),
                            route: Some(Route {
                                prefix,
                                next_hop,
                                as_path: String::new(),
                                origin: String::new(),
                                best: false,
                                peer_id: peer_idx as u32,
                            }),
                        },
                        RouteEvent::BestChanged(entry) => RouteUpdate {
                            update_type: UpdateType::Added.into(),
                            route: Some(Route {
                                prefix: entry.prefix,
                                next_hop: entry.next_hop,
                                as_path: entry.as_path,
                                origin: entry.origin,
                                best: entry.best,
                                peer_id: entry.peer_idx as u32,
                            }),
                        },
                    };
                    Some(Ok(update))
                }
                Err(_) => {
                    // Lagged - we missed some events, but continue
                    None
                }
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn add_route(
        &self,
        request: Request<AddRouteRequest>,
    ) -> Result<Response<AddRouteResponse>, Status> {
        let req = request.into_inner();

        // Validate prefix
        if req.prefix.is_empty() {
            return Ok(Response::new(AddRouteResponse {
                success: false,
                error: "Prefix is required".to_string(),
            }));
        }

        // Clone the handle so we can drop the lock before awaiting
        let rib_handle = {
            let state = self.state.read().await;
            state.rib_handle.clone()
        };

        let route = ApiRoute {
            prefix: req.prefix,
            next_hop: if req.next_hop.is_empty() { None } else { Some(req.next_hop) },
            as_path: req.as_path,
        };

        match rib_handle.add_api_route(route).await {
            Ok(()) => Ok(Response::new(AddRouteResponse {
                success: true,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(AddRouteResponse {
                success: false,
                error: e,
            })),
        }
    }

    async fn withdraw_route(
        &self,
        request: Request<WithdrawRouteRequest>,
    ) -> Result<Response<WithdrawRouteResponse>, Status> {
        let req = request.into_inner();

        if req.prefix.is_empty() {
            return Ok(Response::new(WithdrawRouteResponse {
                success: false,
                error: "Prefix is required".to_string(),
            }));
        }

        // Clone the handle so we can drop the lock before awaiting
        let rib_handle = {
            let state = self.state.read().await;
            state.rib_handle.clone()
        };

        match rib_handle.withdraw_api_route(req.prefix).await {
            Ok(()) => Ok(Response::new(WithdrawRouteResponse {
                success: true,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(WithdrawRouteResponse {
                success: false,
                error: e,
            })),
        }
    }

    async fn add_peer(
        &self,
        request: Request<AddPeerRequest>,
    ) -> Result<Response<AddPeerResponse>, Status> {
        let req = request.into_inner();

        // Validate interface
        if req.interface.is_empty() {
            return Ok(Response::new(AddPeerResponse {
                success: false,
                error: "Interface is required".to_string(),
                peer_id: 0,
            }));
        }

        // Get peer manager handle
        let peer_manager = {
            let state = self.state.read().await;
            state.peer_manager.clone()
        };

        let Some(pm) = peer_manager else {
            return Ok(Response::new(AddPeerResponse {
                success: false,
                error: "Peer manager not available".to_string(),
                peer_id: 0,
            }));
        };

        // Create peer config
        let config = PeerConfig {
            interface: req.interface,
            address: if req.address.is_empty() { None } else { Some(req.address) },
            remote_asn: if req.remote_asn == 0 { None } else { Some(req.remote_asn) },
        };

        match pm.add_peer(config).await {
            Ok(peer_id) => Ok(Response::new(AddPeerResponse {
                success: true,
                error: String::new(),
                peer_id,
            })),
            Err(e) => Ok(Response::new(AddPeerResponse {
                success: false,
                error: e,
                peer_id: 0,
            })),
        }
    }

    async fn remove_peer(
        &self,
        request: Request<RemovePeerRequest>,
    ) -> Result<Response<RemovePeerResponse>, Status> {
        let req = request.into_inner();

        // Get peer manager handle
        let peer_manager = {
            let state = self.state.read().await;
            state.peer_manager.clone()
        };

        let Some(pm) = peer_manager else {
            return Ok(Response::new(RemovePeerResponse {
                success: false,
                error: "Peer manager not available".to_string(),
            }));
        };

        match pm.remove_peer(req.peer_id).await {
            Ok(()) => Ok(Response::new(RemovePeerResponse {
                success: true,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(RemovePeerResponse {
                success: false,
                error: e,
            })),
        }
    }
}
