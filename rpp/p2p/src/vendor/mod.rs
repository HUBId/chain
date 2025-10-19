//! Local re-exports of vendored libp2p crates.
//!
//! The actual source code is stored in `rpp/p2p/vendor/` and mirrors the
//! upstream `rust-libp2p` repository. The modules defined here provide stable
//! paths for the rest of the crate to access the libp2p APIs.
//!
//! # Feature flags
//!
//! * `noise` – enables the [`libp2p-noise`](https://github.com/libp2p/rust-libp2p)
//!   security handshake primitives.
//! * `tcp` – pulls in the vendored TCP transport from
//!   [`libp2p-tcp`](https://github.com/libp2p/rust-libp2p).
//! * `yamux` – exposes the [`libp2p-yamux`](https://github.com/libp2p/rust-libp2p)
//!   stream multiplexer.
//! * `quic` – wires up the QUIC transport via the vendored
//!   [`libp2p-quic`](https://github.com/libp2p/rust-libp2p) crate.
//! * `memory-transport` – re-exports the in-memory transport utilities from
//!   `libp2p-core` for testing and simulations.

use libp2p as libp2p_main;

/// Core libp2p primitives.
pub use libp2p_core as core;

/// Swarm management and behaviour composition utilities.
pub use libp2p_swarm as swarm;

/// Identity handling helpers (PeerId, keys, etc.).
pub use libp2p_identity as identity;

/// Gossipsub pubsub protocol implementation.
#[cfg(feature = "gossipsub")]
pub use libp2p_gossipsub as gossipsub;

/// Identify protocol implementation.
#[cfg(feature = "identify")]
pub use libp2p_identify as identify;

/// Ping protocol implementation.
#[cfg(feature = "ping")]
pub use libp2p_ping as ping;

/// Request-response protocol implementation.
#[cfg(feature = "request-response")]
pub use libp2p_request_response as request_response;

/// Noise security handshake primitives.
#[cfg(feature = "noise")]
pub use libp2p_noise as noise;

/// TCP transport implementation.
#[cfg(feature = "tcp")]
pub use libp2p_tcp as tcp;

/// Yamux stream multiplexer implementation.
#[cfg(feature = "yamux")]
pub use libp2p_yamux as yamux;

/// QUIC transport implementation.
#[cfg(feature = "quic")]
pub use libp2p_quic as quic;

/// In-memory transport helpers useful for tests and simulations.
#[cfg(feature = "memory-transport")]
pub mod memory_transport {
    pub use crate::vendor::core::transport::memory::*;
}

/// Multiaddr helper utilities vendored alongside `libp2p-core`.
pub mod multiaddr {
    pub use crate::vendor::core::multiaddr::*;
}

pub use crate::vendor::core::multihash;
pub use crate::vendor::core::Multiaddr;
pub use crate::vendor::identity::PeerId;
pub use crate::vendor::swarm::Swarm;
pub use libp2p_main::SwarmBuilder;
