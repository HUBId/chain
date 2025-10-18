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
pub mod gossipsub {
    pub use libp2p::gossipsub::*;
}

/// Identify protocol implementation.
pub mod identify {
    pub use libp2p::identify::*;
}

/// Ping protocol implementation.
pub mod ping {
    pub use libp2p::ping::*;
}

/// Request-response protocol implementation.
pub mod request_response {
    pub use libp2p::request_response::*;
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
