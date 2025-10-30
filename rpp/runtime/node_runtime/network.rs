use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libp2p::{identity::ParseError as PeerIdParseError, Multiaddr};
use log::warn;
use rpp_p2p::vendor::PeerId;
use rpp_p2p::{
    AllowlistedPeer, GossipStateError, GossipStateStore, HandshakePayload, IdentityError, Network,
    NetworkError, NodeIdentity, NullSnapshotProvider, Peerstore, PeerstoreConfig, PeerstoreError,
    ReputationHeuristics, TierLevel,
};
use std::str::FromStr;
use thiserror::Error;

use super::node::IdentityProfile;
use crate::config::{FeatureGates, P2pAllowlistEntry, P2pConfig};

/// Resolved libp2p networking configuration used by the runtime.
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    listen_addr: Multiaddr,
    bootstrap_peers: Vec<Multiaddr>,
    heartbeat_interval: Duration,
    gossip_enabled: bool,
    allowlist: Vec<AllowlistedPeer>,
    blocklist: Vec<PeerId>,
    gossip_rate_limit_per_sec: u64,
    replay_window_size: usize,
    reputation_heuristics: ReputationHeuristics,
}

impl NetworkConfig {
    /// Builds a [`NetworkConfig`] from the user-provided [`P2pConfig`].
    pub fn from_config(config: &P2pConfig) -> Result<Self, NetworkSetupError> {
        let listen_addr = config.listen_addr.parse::<Multiaddr>().map_err(|source| {
            NetworkSetupError::InvalidMultiaddr {
                addr: config.listen_addr.clone(),
                source,
            }
        })?;
        let mut bootstrap_peers = Vec::with_capacity(config.bootstrap_peers.len());
        for addr in &config.bootstrap_peers {
            let multiaddr = addr.parse::<Multiaddr>().map_err(|source| {
                NetworkSetupError::InvalidMultiaddr {
                    addr: addr.clone(),
                    source,
                }
            })?;
            bootstrap_peers.push(multiaddr);
        }
        let heartbeat_interval = Duration::from_millis(config.heartbeat_interval_ms.max(1));
        let allowlist = Self::parse_allowlist(&config.allowlist)?;
        let blocklist = Self::parse_blocklist(&config.blocklist)?;
        Ok(Self {
            listen_addr,
            bootstrap_peers,
            heartbeat_interval,
            gossip_enabled: config.gossip_enabled,
            allowlist,
            blocklist,
            gossip_rate_limit_per_sec: config.gossip_rate_limit_per_sec,
            replay_window_size: config.replay_window_size,
            reputation_heuristics: config.reputation_heuristics(),
        })
    }

    fn parse_allowlist(
        entries: &[P2pAllowlistEntry],
    ) -> Result<Vec<AllowlistedPeer>, NetworkSetupError> {
        let mut allowlist = Vec::with_capacity(entries.len());
        for entry in entries {
            let peer = PeerId::from_str(&entry.peer_id).map_err(|source| {
                NetworkSetupError::InvalidPeerId {
                    peer_id: entry.peer_id.clone(),
                    source,
                }
            })?;
            allowlist.push(AllowlistedPeer {
                peer,
                tier: entry.tier,
            });
        }
        Ok(allowlist)
    }

    fn parse_blocklist(entries: &[String]) -> Result<Vec<PeerId>, NetworkSetupError> {
        let mut blocklist = Vec::with_capacity(entries.len());
        for peer in entries {
            let parsed =
                PeerId::from_str(peer).map_err(|source| NetworkSetupError::InvalidPeerId {
                    peer_id: peer.clone(),
                    source,
                })?;
            blocklist.push(parsed);
        }
        Ok(blocklist)
    }

    /// Returns the listen address for the libp2p swarm.
    pub fn listen_addr(&self) -> &Multiaddr {
        &self.listen_addr
    }

    /// Returns bootstrap peers that should be dialled on start-up.
    pub fn bootstrap_peers(&self) -> &[Multiaddr] {
        &self.bootstrap_peers
    }

    /// Interval used to emit heartbeat events.
    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    /// Whether gossip propagation is enabled for this node.
    pub fn gossip_enabled(&self) -> bool {
        self.gossip_enabled
    }

    pub fn allowlist(&self) -> &[AllowlistedPeer] {
        &self.allowlist
    }

    pub fn blocklist(&self) -> &[PeerId] {
        &self.blocklist
    }

    pub fn gossip_rate_limit_per_sec(&self) -> u64 {
        self.gossip_rate_limit_per_sec
    }

    pub fn replay_window_size(&self) -> usize {
        self.replay_window_size
    }

    pub fn reputation_heuristics(&self) -> ReputationHeuristics {
        self.reputation_heuristics
    }
}

/// Helper struct bundling libp2p primitives required by the node runtime.
pub struct NetworkResources {
    network: Network,
    identity: Arc<NodeIdentity>,
}

impl NetworkResources {
    /// Initialises the libp2p networking stack from the resolved configuration.
    pub fn initialise(
        identity_path: &Path,
        config: &NetworkConfig,
        p2p_config: &P2pConfig,
        identity_profile: Option<IdentityProfile>,
        feature_gates: FeatureGates,
    ) -> Result<Self, NetworkSetupError> {
        let identity = Arc::new(NodeIdentity::load_or_generate(identity_path)?);
        let peerstore_config = PeerstoreConfig::persistent(&p2p_config.peerstore_path)
            .with_allowlist(config.allowlist().to_vec())
            .with_blocklist(config.blocklist().to_vec());
        let peerstore = Arc::new(Peerstore::open(peerstore_config)?);
        let gossip_state = if let Some(path) = p2p_config.gossip_path.as_ref() {
            Some(Arc::new(GossipStateStore::open(path)?))
        } else {
            None
        };
        let node_label = identity.peer_id().to_base58();
        let (handshake, profile) = if let Some(profile) = identity_profile {
            let features = profile.feature_gates.advertise();
            (
                HandshakePayload::new(
                    profile.zsi_id.clone(),
                    Some(profile.vrf_public_key.clone()),
                    Some(profile.vrf_proof.clone()),
                    profile.tier,
                )
                .with_features(features),
                Some(profile),
            )
        } else {
            (
                HandshakePayload::new(node_label, None, None, TierLevel::Tl0)
                    .with_features(feature_gates.advertise()),
                None,
            )
        };
        let handshake_snapshot = handshake.clone();
        let mut network = Network::new(
            identity.clone(),
            peerstore.clone(),
            handshake,
            gossip_state,
            config.gossip_rate_limit_per_sec(),
            config.replay_window_size(),
            config.reputation_heuristics(),
            Some(Arc::new(NullSnapshotProvider::default())),
        )?;
        if let Some(profile) = profile {
            network.update_identity(
                profile.zsi_id,
                profile.tier,
                profile.vrf_public_key,
                profile.vrf_proof,
                profile.feature_gates.advertise(),
            )?;
        }
        let signed_handshake = handshake_snapshot
            .signed(&identity.clone_keypair())
            .map_err(|err| {
                NetworkSetupError::Network(NetworkError::Handshake(format!(
                    "failed to sign local handshake: {err}"
                )))
            })?;
        peerstore.record_handshake(identity.peer_id(), &signed_handshake)?;
        network.listen_on(config.listen_addr().clone())?;
        for addr in config.bootstrap_peers() {
            if let Err(err) = network.dial(addr.clone()) {
                warn!(target: "network", "failed to dial bootstrap peer {addr}: {err}");
            }
        }
        Ok(Self { network, identity })
    }

    /// Consumes the resources and returns ownership of the network and identity.
    pub fn into_parts(self) -> (Network, Arc<NodeIdentity>) {
        (self.network, self.identity)
    }
}

/// Errors that can arise while setting up the libp2p networking stack.
#[derive(Debug, Error)]
pub enum NetworkSetupError {
    #[error("invalid multiaddr {addr}: {source}")]
    InvalidMultiaddr {
        addr: String,
        #[source]
        source: libp2p::multiaddr::Error,
    },
    #[error("invalid peer id {peer_id}: {source}")]
    InvalidPeerId {
        peer_id: String,
        #[source]
        source: PeerIdParseError,
    },
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("peerstore error: {0}")]
    Peerstore(#[from] PeerstoreError),
    #[error("gossip state error: {0}")]
    GossipState(#[from] GossipStateError),
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
}

#[cfg(test)]
mod tests_prop;
