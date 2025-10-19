//! Builder utilities for composing libp2p swarms.
//!
//! # Feature matrix
//!
//! The builder follows a type-state machine where each helper method is only
//! available when the required runtime and transport features are enabled. The
//! table below summarises the relevant feature guards for the currently
//! supported transports:
//!
//! | Helper | Required features |
//! | ------ | ----------------- |
//! | [`SwarmBuilder::with_tokio`] | `tokio` (on non-`wasm32` targets) |
//! | [`SwarmBuilder::with_tcp`] | `tokio` + `tcp` + the security/multiplexer features passed to the helper |
//! | [`SwarmBuilder::with_quic`], [`SwarmBuilder::with_quic_config`] | `tokio` + `quic` (on non-`wasm32` targets) |
//! | TCP + QUIC combinations | Enable both `tcp` and `quic` in addition to `tokio` |
//!
//! Other extension helpers (DNS, relay, metrics, etc.) remain gated within
//! their respective modules and can be combined on top of the TCP and QUIC
//! transports when the matching feature flags are enabled.

use std::marker::PhantomData;

mod phase;
mod select_muxer;
mod select_security;

pub use phase::{BehaviourError, TransportError};

/// Build a [`Swarm`](libp2p_swarm::Swarm) by combining an identity, a set of
/// [`Transport`](libp2p_core::Transport)s and a
/// [`NetworkBehaviour`](libp2p_swarm::NetworkBehaviour).
///
/// ```
/// # use libp2p::{swarm::NetworkBehaviour, SwarmBuilder};
/// # use libp2p::core::transport::dummy::DummyTransport;
/// # use libp2p::core::muxing::StreamMuxerBox;
/// # use libp2p::identity::PeerId;
/// # use std::error::Error;
/// #
/// # #[cfg(all(
/// #     not(target_arch = "wasm32"),
/// #     feature = "tokio",
/// #     feature = "tcp",
/// #     feature = "tls",
/// #     feature = "noise",
/// #     feature = "quic",
/// #     feature = "dns",
/// #     feature = "relay",
/// # ))]
/// # fn build_swarm() -> Result<(), Box<dyn Error>> {
/// #     #[derive(NetworkBehaviour)]
/// #     #[behaviour(prelude = "libp2p_swarm::derive_prelude")]
/// #     struct MyBehaviour {
/// #         relay: libp2p_relay::client::Behaviour,
/// #     }
///
/// let swarm = SwarmBuilder::with_new_identity()
///     .with_tokio()
///     .with_tcp(
///         Default::default(),
///         (libp2p_tls::Config::new, libp2p_noise::Config::new),
///         libp2p_yamux::Config::default,
///     )?
///     .with_quic()
///     .with_other_transport(|_key| DummyTransport::<(PeerId, StreamMuxerBox)>::new())?
///     .with_dns()?
///     .with_relay_client(
///         (libp2p_tls::Config::new, libp2p_noise::Config::new),
///         libp2p_yamux::Config::default,
///     )?
///     .with_behaviour(|_key, relay| MyBehaviour { relay })?
///     .with_swarm_config(|cfg| {
///         // Edit cfg here.
///         cfg
///     })
///     .build();
/// #
/// #     Ok(())
/// # }
/// ```
pub struct SwarmBuilder<Provider, Phase> {
    keypair: libp2p_identity::Keypair,
    phantom: PhantomData<Provider>,
    phase: Phase,
}

#[cfg(test)]
mod tests {
    use crate::SwarmBuilder;

    #[test]
    #[cfg(all(
        feature = "tokio",
        feature = "tcp",
        feature = "noise",
        feature = "yamux",
    ))]
    fn tcp_noise_yamux() {
        let _ = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                Default::default(),
                libp2p_noise::Config::new,
                libp2p_yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| libp2p_swarm::dummy::Behaviour)
            .unwrap()
            .build();
    }

    #[test]
    #[cfg(all(feature = "tokio", feature = "quic"))]
    fn quic() {
        let _ = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_quic()
            .with_behaviour(|_| libp2p_swarm::dummy::Behaviour)
            .unwrap()
            .build();
    }

    #[test]
    #[cfg(all(feature = "tokio", feature = "quic"))]
    fn quic_config() {
        let _ = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_quic_config(|config| config)
            .with_behaviour(|_| libp2p_swarm::dummy::Behaviour)
            .unwrap()
            .build();
    }

    #[test]
    #[cfg(all(
        feature = "tokio",
        feature = "tcp",
        feature = "noise",
        feature = "yamux",
        feature = "quic",
    ))]
    fn tcp_quic_stack() {
        let _ = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                Default::default(),
                libp2p_noise::Config::new,
                libp2p_yamux::Config::default,
            )
            .unwrap()
            .with_quic()
            .with_behaviour(|_| libp2p_swarm::dummy::Behaviour)
            .unwrap()
            .build();
    }
}
