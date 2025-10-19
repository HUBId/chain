//! Builder utilities for composing libp2p swarms with a TCP transport and
//! custom security and multiplexing upgrades.

use std::marker::PhantomData;

mod phase;
mod select_muxer;
mod select_security;

pub use phase::BehaviourError;

/// Build a [`Swarm`](crate::Swarm) by combining an identity, a TCP transport,
/// and a [`NetworkBehaviour`](crate::NetworkBehaviour).
///
/// ```
/// # use libp2p_swarm::builder::SwarmBuilder;
/// # use libp2p_swarm::NetworkBehaviour;
/// #
/// #[derive(NetworkBehaviour)]
/// #[behaviour(prelude = "libp2p_swarm::derive_prelude")]
/// struct MyBehaviour;
///
/// let swarm = SwarmBuilder::with_new_identity()
///     .with_tokio()
///     .with_tcp(
///         Default::default(),
///         libp2p_noise::Config::new,
///         libp2p_yamux::Config::default,
///     )?
///     .with_behaviour(|_| MyBehaviour)?
///     .with_swarm_config(|cfg| cfg)
///     .build();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct SwarmBuilder<Provider, Phase> {
    keypair: libp2p_identity::Keypair,
    phantom: PhantomData<Provider>,
    phase: Phase,
}

#[cfg(test)]
mod tests {
    #[test]
    fn builder_is_send() {
        fn assert_send<T: Send>(_t: T) {}

        let builder = crate::builder::SwarmBuilder::with_new_identity();
        assert_send(builder);
    }
}
