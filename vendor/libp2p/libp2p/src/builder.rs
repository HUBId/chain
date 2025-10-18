use std::marker::PhantomData;

mod phase;
mod select_muxer;
mod select_security;

#[cfg(all(not(target_arch = "wasm32"), feature = "websocket"))]
pub use phase::WebsocketError;
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
/// #     feature = "websocket",
/// # ))]
/// # async fn build_swarm() -> Result<(), Box<dyn Error>> {
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
///     .with_websocket(
///         (libp2p_tls::Config::new, libp2p_noise::Config::new),
///         libp2p_yamux::Config::default,
///     )
///     .await?
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

