use libp2p_core::{
    muxing::StreamMuxerBox,
    transport::{dummy::DummyTransport, Transport},
};
use libp2p_identity::Keypair;
use libp2p_swarm::{self as swarm, Config, Swarm};
use rpp_p2p::{EmptyConnectionHandler, NetworkBehaviour};

#[derive(NetworkBehaviour, Default)]
struct EmptyBehaviour;

#[test]
fn derive_uses_empty_connection_handler() {
    fn assert_handler_type(
        _: <EmptyBehaviour as swarm::NetworkBehaviour>::ConnectionHandler,
    ) {
    }

    assert_handler_type(EmptyConnectionHandler::default());
}

#[test]
fn swarm_accepts_empty_behaviour() {
    let behaviour = EmptyBehaviour::default();
    let local_peer_id = Keypair::generate_ed25519().public().to_peer_id();

    let transport = DummyTransport::<(libp2p_identity::PeerId, StreamMuxerBox)>::new().boxed();

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        Config::with_tokio_executor(),
    );

    assert_eq!(swarm.network_info().num_peers(), 0);
    let _ = swarm.network_info().connection_counters();
}
