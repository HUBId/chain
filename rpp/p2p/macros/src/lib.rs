//! Procedural macro re-exports for the RPP P2P stack.

extern crate proc_macro;

/// Derive macro for [`libp2p_swarm::NetworkBehaviour`].
#[proc_macro_derive(NetworkBehaviour, attributes(behaviour))]
pub fn network_behaviour(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    rpp_libp2p_swarm_derive::NetworkBehaviour(input)
}
