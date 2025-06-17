//! P2P networking for Rusty Coin using libp2p.

use libp2p::{futures::StreamExt, identity, PeerId, Swarm, TransportExt, swarm::SwarmEvent};
use libp2p_mplex::MplexConfig;
use libp2p_noise::{NoiseAuthenticated, X25519Spec};
use libp2p_ping::{Ping, PingEvent};
use libp2p_tcp::TokioTcpConfig;
use libp2p_yamux::YamuxConfig;
use libp2p_swarm::derive::NetworkBehaviour;

/// Our network behaviour. It detects peers and ping them.
#[derive(NetworkBehaviour)]
#[libp2p(event = "RustyCoinBehaviourEvent")]
pub struct RustyCoinBehaviour {
    ping: Ping,
}

#[derive(Debug)]
pub enum RustyCoinBehaviourEvent {
    Ping(PingEvent),
}

impl From<PingEvent> for RustyCoinBehaviourEvent {
    fn from(event: PingEvent) -> Self {
        RustyCoinBehaviourEvent::Ping(event)
    }
}

pub async fn start_p2p_node() -> Result<(), Box<dyn std::error::Error>> {
    // Create a random PeerId
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Create a `Swarm` that establishes connections to the network.
    let transport = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(NoiseAuthenticated::xx(&local_key)?)
        .multiplex(MplexConfig::new())
        .multiplex(YamuxConfig::new())
        .boxed();

    let behaviour = RustyCoinBehaviour { ping: Ping::new() };

    let mut swarm = Swarm::new(transport, behaviour, local_peer_id, libp2p::swarm::Config::default());

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {:?}", address),
            SwarmEvent::Behaviour(event) => println!("Behaviour event: {:?}", event),
            _ => {}
        }
    }
} 