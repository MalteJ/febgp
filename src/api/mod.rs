pub mod client;
pub mod server;

// Include generated protobuf code
pub mod proto {
    tonic::include_proto!("febgp");
}

pub use proto::febgp_service_client::FebgpServiceClient;
pub use proto::febgp_service_server::{FebgpService, FebgpServiceServer};

/// Default configuration file path
pub const DEFAULT_CONFIG_PATH: &str = "/etc/febgp/config.toml";

/// Default gRPC socket path
pub const DEFAULT_SOCKET_PATH: &str = "/var/lib/febgp/grpc.sock";
