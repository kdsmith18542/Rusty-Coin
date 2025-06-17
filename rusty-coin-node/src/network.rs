//! P2P networking for Rusty Coin using libp2p.

use libp2p::{
    futures::StreamExt,
    identity,
    swarm::{Swarm, SwarmEvent, NetworkBehaviour},
    PeerId,
    ping::{Ping, PingConfig, PingEvent},
    tcp::TokioTcpConfig,
    noise::{NoiseAuthenticated, X25519Spec},
    yamux::YamuxConfig,
    mplex::MplexConfig,
    core::{upgrade, transport::Transport}
};
use std::error::Error;

/// Our network behaviour. It detects peers and ping them.
#[derive(NetworkBehaviour)]
struct RustyCoinBehaviour {
    ping: Ping,
}

pub async fn start_p2p_node() -> Result<(), Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {local_peer_id:?}");

    let transport = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseAuthenticated::xx(&local_key).unwrap())
        .multiplex(YamuxConfig::default())
        .boxed();

    let behaviour = RustyCoinBehaviour {
        ping: Ping::new(PingConfig::new().with_keep_alive(true)),
    };

    let mut swarm = Swarm::new(transport, behaviour, local_peer_id);
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    println!("Node listening on {:?}", swarm.external_addresses());

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Listening on {address:?}");
            }
            SwarmEvent::Behaviour(PingEvent { peer, result }) => {
                match result {
                    Ok(rtt) => println!("Ping to {peer} successful: {rtt:?}"),
                    Err(e) => println!("Ping to {peer} failed: {e:?}"),
                }
            }
            _ => {}
        }
    }
}