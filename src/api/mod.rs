pub mod server;
pub mod client;

// Include generated protobuf code
pub mod proto {
    tonic::include_proto!("febgp");
}

pub use proto::febgp_service_client::FebgpServiceClient;
pub use proto::febgp_service_server::{FebgpService, FebgpServiceServer};

/// Default gRPC port for FeBGP
pub const DEFAULT_GRPC_PORT: u16 = 50051;

/// Default gRPC address
pub fn default_grpc_addr() -> String {
    format!("127.0.0.1:{}", DEFAULT_GRPC_PORT)
}
