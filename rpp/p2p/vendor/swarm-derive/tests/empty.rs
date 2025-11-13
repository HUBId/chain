#[derive(libp2p_swarm_derive::NetworkBehaviour)]
struct EmptyBehaviour;

#[test]
fn empty_behaviour_uses_empty_handler() {
    use libp2p_swarm::derive_prelude::EmptyConnectionHandler;

    let handler: <EmptyBehaviour as libp2p_swarm::NetworkBehaviour>::ConnectionHandler =
        EmptyConnectionHandler;
    let _: EmptyConnectionHandler = handler;
}
