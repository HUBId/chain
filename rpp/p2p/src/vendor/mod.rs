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

/// Core libp2p primitives.
pub mod core {
    pub use libp2p::core::*;
    pub use libp2p::multihash;
}

/// Swarm management and behaviour composition utilities.
pub mod swarm {
    pub use libp2p::swarm::*;
}

/// Identity handling helpers (PeerId, keys, etc.).
pub mod identity {
    pub use libp2p::identity::*;
}

/// Gossipsub pubsub protocol implementation.
#[cfg(feature = "gossipsub")]
pub mod gossipsub {
    pub use libp2p_gossipsub::*;
}

/// Identify protocol implementation.
#[cfg(feature = "identify")]
pub mod identify {
    pub use libp2p_identify::*;
}

/// Ping protocol implementation.
#[cfg(feature = "ping")]
pub mod ping {
    pub use libp2p_ping::*;
}

/// Request-response protocol implementation.
#[cfg(feature = "request-response")]
pub mod request_response {
    pub use libp2p_request_response::*;
}

/// Noise security handshake primitives.
#[cfg(feature = "noise")]
pub mod noise {
    pub use libp2p::noise::*;
}

/// TCP transport implementation.
#[cfg(feature = "tcp")]
pub mod tcp {
    pub use libp2p::tcp::*;
}

/// Yamux stream multiplexer implementation.
#[cfg(feature = "yamux")]
pub mod yamux {
    pub use libp2p::yamux::*;
}

/// QUIC transport implementation.
#[cfg(feature = "quic")]
pub mod quic {
    pub use libp2p::quic::*;
}

/// In-memory transport helpers useful for tests and simulations.
#[cfg(feature = "memory-transport")]
pub mod memory_transport {
    pub use libp2p::core::transport::memory::*;
}

pub use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};
