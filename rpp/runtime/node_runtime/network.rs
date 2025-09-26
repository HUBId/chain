use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libp2p::Multiaddr;
use log::warn;
use rpp_p2p::{
    GossipStateError, GossipStateStore, HandshakePayload, IdentityError, Network, NetworkError,
    NodeIdentity, Peerstore, PeerstoreConfig, PeerstoreError, TierLevel,
};
use thiserror::Error;

use super::node::IdentityProfile;
use crate::config::P2pConfig;

/// Resolved libp2p networking configuration used by the runtime.
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    listen_addr: Multiaddr,
    bootstrap_peers: Vec<Multiaddr>,
    heartbeat_interval: Duration,
    gossip_enabled: bool,
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
        Ok(Self {
            listen_addr,
            bootstrap_peers,
            heartbeat_interval,
            gossip_enabled: config.gossip_enabled,
        })
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
    ) -> Result<Self, NetworkSetupError> {
        let identity = Arc::new(NodeIdentity::load_or_generate(identity_path)?);
        let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::persistent(
            &p2p_config.peerstore_path,
        ))?);
        let gossip_state = if let Some(path) = p2p_config.gossip_path.as_ref() {
            Some(Arc::new(GossipStateStore::open(path)?))
        } else {
            None
        };
        let node_label = identity.peer_id().to_base58();
        let (handshake, profile) = if let Some(profile) = identity_profile {
            (
                HandshakePayload::new(
                    profile.zsi_id.clone(),
                    Some(profile.vrf_proof.clone()),
                    profile.tier,
                ),
                Some(profile),
            )
        } else {
            (
                HandshakePayload::new(node_label, None, TierLevel::Tl0),
                None,
            )
        };
        let mut network = Network::new(identity.clone(), peerstore, handshake, gossip_state)?;
        if let Some(profile) = profile {
            network.update_identity(profile.zsi_id, profile.tier, profile.vrf_proof)?;
        }
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
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("peerstore error: {0}")]
    Peerstore(#[from] PeerstoreError),
    #[error("gossip state error: {0}")]
    GossipState(#[from] GossipStateError),
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
}
