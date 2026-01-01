use super::proto::Empty;
use super::FebgpServiceClient;

/// Connect to the FeBGP daemon and get status
pub async fn get_status(addr: &str) -> Result<super::proto::StatusResponse, Box<dyn std::error::Error>> {
    let mut client = FebgpServiceClient::connect(format!("http://{}", addr)).await?;
    let response = client.get_status(Empty {}).await?;
    Ok(response.into_inner())
}

/// Connect to the FeBGP daemon and get routes
pub async fn get_routes(addr: &str) -> Result<super::proto::RoutesResponse, Box<dyn std::error::Error>> {
    let mut client = FebgpServiceClient::connect(format!("http://{}", addr)).await?;
    let response = client.get_routes(Empty {}).await?;
    Ok(response.into_inner())
}
