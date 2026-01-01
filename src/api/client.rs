use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use super::proto::Empty;
use super::FebgpServiceClient;

/// Connect to the FeBGP daemon via Unix socket
async fn connect_unix(socket_path: &str) -> Result<Channel, Box<dyn std::error::Error>> {
    let socket_path = socket_path.to_string();

    // For Unix sockets, the URI doesn't matter but must be valid
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = socket_path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;

    Ok(channel)
}

/// Connect to the FeBGP daemon and get status
pub async fn get_status(socket_path: &str) -> Result<super::proto::StatusResponse, Box<dyn std::error::Error>> {
    let channel = connect_unix(socket_path).await?;
    let mut client = FebgpServiceClient::new(channel);
    let response = client.get_status(Empty {}).await?;
    Ok(response.into_inner())
}

/// Connect to the FeBGP daemon and get routes
pub async fn get_routes(socket_path: &str) -> Result<super::proto::RoutesResponse, Box<dyn std::error::Error>> {
    let channel = connect_unix(socket_path).await?;
    let mut client = FebgpServiceClient::new(channel);
    let response = client.get_routes(Empty {}).await?;
    Ok(response.into_inner())
}
