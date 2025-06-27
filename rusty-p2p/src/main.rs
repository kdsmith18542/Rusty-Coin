use rusty_p2p::network::P2PNetwork;
use env_logger::{Builder, Target};
use log::LevelFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Builder::new()
        .filter_level(LevelFilter::Info)
        .target(Target::Stdout)
        .init();

    let mut network = P2PNetwork::new().await?;

    network.start().await?;

    Ok(())
}