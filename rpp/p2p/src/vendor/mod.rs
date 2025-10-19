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

/// Noise security handshake primitives.
#[cfg(feature = "noise")]
pub use libp2p_noise as noise;

/// Plaintext security handshake primitives.
#[cfg(feature = "plaintext")]
pub use libp2p_plaintext as plaintext;

/// TCP transport implementation.
#[cfg(feature = "tcp")]
pub use libp2p_tcp as tcp;

/// Yamux stream multiplexer implementation with RPP defaults.
#[cfg(feature = "yamux")]
pub mod yamux;

/// QUIC transport implementation.
#[cfg(feature = "quic")]
pub use libp2p_quic as quic;

pub mod protocols {
    /// Request-response protocol implementation tailored for RPP.
    #[cfg(feature = "request-response")]
    pub use libp2p_request_response as request_response;
}

/// Multiaddr helper utilities vendored alongside `libp2p-core`.
pub mod multiaddr {
    pub use crate::vendor::core::multiaddr::*;

    use crate::vendor::core::multiaddr::{
        Error as MultiaddrError, Multiaddr as CoreMultiaddr, Protocol as CoreProtocol,
    };
    use std::result::Result as StdResult;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum StaticMultiaddrError {
        #[error("invalid multiaddr: {0}")]
        Parse(#[from] MultiaddrError),
        #[error("unsupported protocol `{0}` in static multiaddr")]
        Unsupported(String),
    }

    fn ensure_supported(addr: &CoreMultiaddr) -> StdResult<(), StaticMultiaddrError> {
        for protocol in addr.iter() {
            match protocol {
                CoreProtocol::Ip4(_)
                | CoreProtocol::Ip6(_)
                | CoreProtocol::Tcp(_)
                | CoreProtocol::Udp(_)
                | CoreProtocol::Quic
                | CoreProtocol::QuicV1
                | CoreProtocol::P2p(_) => {}
                other => return Err(StaticMultiaddrError::Unsupported(other.to_string())),
            }
        }
        Ok(())
    }

    pub fn parse_static(value: &str) -> StdResult<CoreMultiaddr, StaticMultiaddrError> {
        let addr: CoreMultiaddr = value.parse()?;
        ensure_supported(&addr)?;
        Ok(addr)
    }

    pub fn format_static(addr: &CoreMultiaddr) -> StdResult<String, StaticMultiaddrError> {
        ensure_supported(addr)?;
        Ok(addr.to_string())
    }

    pub fn deserialize_static_addrs<I, S>(
        values: I,
    ) -> StdResult<Vec<CoreMultiaddr>, StaticMultiaddrError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        values
            .into_iter()
            .map(|value| parse_static(value.as_ref()))
            .collect()
    }

    pub fn serialize_static_addrs(
        addrs: &[CoreMultiaddr],
    ) -> StdResult<Vec<String>, StaticMultiaddrError> {
        addrs.iter().map(format_static).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::vendor::identity::PeerId;
        use std::str::FromStr;

        #[test]
        fn accepts_basic_ip_transport() {
            let peer_id = PeerId::from_str("12D3KooWJqD9iXy2qxY8pYtBXf3y1Y9qsKf8GugHgdGXQTd7")
                .expect("peer id");
            let input = format!("/ip4/127.0.0.1/tcp/30333/p2p/{}", peer_id);
            let addr = parse_static(&input).expect("parse");
            assert_eq!(format_static(&addr).expect("format"), input);
        }

        #[test]
        fn rejects_dns_protocols() {
            let err =
                parse_static("/dns4/example.com/tcp/30333").expect_err("dns should be rejected");
            assert!(matches!(err, StaticMultiaddrError::Unsupported(_)));
        }

        #[test]
        fn roundtrips_serialization() {
            let peers = [
                PeerId::from_str("12D3KooWJqD9iXy2qxY8pYtBXf3y1Y9qsKf8GugHgdGXQTd7").expect("peer"),
                PeerId::from_str("12D3KooWQBo7c9Z2wrE5m7vt1W3avDy2tYx1s9pQnoC6R6kq").expect("peer"),
            ];
            let addrs = vec![
                Multiaddr::empty()
                    .with(CoreProtocol::Ip6("::1".parse().unwrap()))
                    .with(CoreProtocol::Tcp(1234))
                    .with(CoreProtocol::P2p(peers[0].clone())),
                Multiaddr::empty()
                    .with(CoreProtocol::Ip4("10.0.0.1".parse().unwrap()))
                    .with(CoreProtocol::QuicV1)
                    .with(CoreProtocol::P2p(peers[1].clone())),
            ];
            let serialized = serialize_static_addrs(&addrs).expect("serialize");
            let restored = deserialize_static_addrs(&serialized).expect("deserialize");
            assert_eq!(restored, addrs);
        }
    }
}

pub use crate::vendor::core::multihash;
pub use crate::vendor::core::Multiaddr;
pub use crate::vendor::identity::PeerId;
pub use crate::vendor::swarm::builder::SwarmBuilder;
pub use crate::vendor::swarm::Swarm;
