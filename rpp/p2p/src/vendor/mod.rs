//! Local re-exports of vendored libp2p crates.
//!
//! The actual source code is stored in `rpp/p2p/vendor/` and mirrors the
//! upstream `rust-libp2p` repository. The modules defined here provide stable
//! paths for the rest of the crate to access the libp2p APIs.

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
pub mod noise {
    pub use libp2p::noise::*;
}

/// TCP transport implementation.
pub mod tcp {
    pub use libp2p::tcp::*;
}

/// Yamux stream multiplexer implementation.
pub mod yamux {
    pub use libp2p::yamux::*;
}

pub use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};
