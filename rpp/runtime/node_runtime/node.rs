use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use libp2p::PeerId;
use log::{debug, info, warn};
use parking_lot::RwLock;
use rpp_p2p::{
    GossipTopic, HandshakePayload, MetaTelemetry, NetworkError, NetworkEvent, NodeIdentity,
    TierLevel,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time;

use crate::config::{NodeConfig, P2pConfig, TelemetryConfig};
use crate::node::NetworkIdentityProfile;
use crate::runtime::telemetry::{TelemetryHandle, TelemetrySnapshot};

use super::network::{NetworkConfig, NetworkResources, NetworkSetupError};

/// Commands issued to the node runtime.
#[derive(Debug)]
enum NodeCommand {
    Publish {
        topic: GossipTopic,
        data: Vec<u8>,
        response: oneshot::Sender<Result<(), NodeError>>,
    },
    UpdateIdentity {
        profile: IdentityProfile,
        response: oneshot::Sender<Result<(), NodeError>>,
    },
    Shutdown,
}

/// In-memory metrics that are periodically forwarded to the telemetry worker.
#[derive(Clone, Debug, Default)]
pub struct NodeMetrics {
    pub block_height: u64,
    pub block_hash: String,
    pub transaction_count: usize,
    pub reputation_score: f64,
}

/// Summary of peer activity that is emitted via heartbeat and meta telemetry events.
#[derive(Clone, Debug)]
pub struct PeerTelemetry {
    pub peer: PeerId,
    pub version: String,
    pub latency_ms: u64,
    pub last_seen: SystemTime,
}

/// Aggregate telemetry information for all known peers.
#[derive(Clone, Debug)]
pub struct MetaTelemetryReport {
    pub local_peer_id: PeerId,
    pub peer_count: usize,
    pub peers: Vec<PeerTelemetry>,
}

/// Periodic heartbeat message emitted by the node runtime.
#[derive(Clone, Debug)]
pub struct Heartbeat {
    pub peer_count: usize,
    pub block_height: u64,
    pub block_hash: String,
    pub transaction_count: usize,
    pub reputation_score: f64,
}

/// Public configuration wrapper used by the node runtime.
#[derive(Clone, Debug)]
pub struct NodeRuntimeConfig {
    pub identity_path: PathBuf,
    pub p2p: P2pConfig,
    pub telemetry: TelemetryConfig,
    pub identity: Option<IdentityProfile>,
}

impl From<&NodeConfig> for NodeRuntimeConfig {
    fn from(config: &NodeConfig) -> Self {
        Self {
            identity_path: config.p2p_key_path.clone(),
            p2p: config.p2p.clone(),
            telemetry: config.rollout.telemetry.clone(),
            identity: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct IdentityProfile {
    pub zsi_id: String,
    pub tier: TierLevel,
    pub vrf_proof: Vec<u8>,
}

impl From<NetworkIdentityProfile> for IdentityProfile {
    fn from(profile: NetworkIdentityProfile) -> Self {
        Self {
            zsi_id: profile.zsi_id,
            tier: profile.tier,
            vrf_proof: profile.vrf_proof,
        }
    }
}

/// Events emitted by the node runtime for consumption by higher layers.
#[derive(Clone, Debug)]
pub enum NodeEvent {
    Gossip {
        peer: PeerId,
        topic: GossipTopic,
        data: Vec<u8>,
    },
    PeerConnected {
        peer: PeerId,
        payload: HandshakePayload,
    },
    PeerDisconnected {
        peer: PeerId,
    },
    Heartbeat(Heartbeat),
    MetaTelemetry(MetaTelemetryReport),
}

/// Errors raised by the node runtime.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("network setup error: {0}")]
    NetworkSetup(#[from] NetworkSetupError),
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
    #[error("command channel closed")]
    CommandChannelClosed,
    #[error("gossip propagation disabled")]
    GossipDisabled,
}

/// Node runtime internals responsible for coordinating networking and telemetry.
pub struct NodeInner {
    network: rpp_p2p::Network,
    identity: Arc<NodeIdentity>,
    commands: mpsc::Receiver<NodeCommand>,
    events: broadcast::Sender<NodeEvent>,
    metrics: Arc<RwLock<NodeMetrics>>,
    telemetry: TelemetryHandle,
    connected_peers: HashSet<PeerId>,
    known_versions: HashMap<PeerId, String>,
    meta_telemetry: MetaTelemetry,
    heartbeat_interval: Duration,
    gossip_enabled: bool,
}

impl NodeInner {
    /// Builds a new [`NodeInner`] alongside its corresponding [`NodeHandle`].
    pub fn new(config: NodeRuntimeConfig) -> Result<(Self, NodeHandle), NodeError> {
        let network_config = NetworkConfig::from_config(&config.p2p)?;
        let telemetry = TelemetryHandle::spawn(config.telemetry.clone());
        let resources = NetworkResources::initialise(
            &config.identity_path,
            &network_config,
            &config.p2p,
            config.identity.clone(),
        )?;
        let (network, identity) = resources.into_parts();
        let (command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, _) = broadcast::channel(256);
        let metrics = Arc::new(RwLock::new(NodeMetrics::default()));
        let handle = NodeHandle {
            commands: command_tx.clone(),
            metrics: metrics.clone(),
            events: event_tx.clone(),
            local_peer_id: identity.peer_id(),
        };
        let inner = Self {
            network,
            identity,
            commands: command_rx,
            events: event_tx,
            metrics,
            telemetry,
            connected_peers: HashSet::new(),
            known_versions: HashMap::new(),
            meta_telemetry: MetaTelemetry::new(),
            heartbeat_interval: network_config.heartbeat_interval(),
            gossip_enabled: network_config.gossip_enabled(),
        };
        Ok((inner, handle))
    }

    /// Main async loop that drives network events and periodic telemetry.
    pub async fn run(mut self) -> Result<(), NodeError> {
        let mut heartbeat = time::interval(self.heartbeat_interval);
        loop {
            tokio::select! {
                Some(command) = self.commands.recv() => {
                    if self.handle_command(command).await? {
                        break;
                    }
                }
                event = self.network.next_event() => {
                    let event = event?;
                    self.handle_network_event(event);
                }
                _ = heartbeat.tick() => {
                    self.emit_heartbeat().await;
                }
            }
        }
        let _ = self.telemetry.shutdown().await;
        Ok(())
    }

    async fn handle_command(&mut self, command: NodeCommand) -> Result<bool, NodeError> {
        match command {
            NodeCommand::Publish {
                topic,
                data,
                response,
            } => {
                let result = if self.gossip_enabled {
                    self.network
                        .publish(topic, data)
                        .map(|_| ())
                        .map_err(NodeError::from)
                } else {
                    Err(NodeError::GossipDisabled)
                };
                let _ = response.send(result);
                Ok(false)
            }
            NodeCommand::UpdateIdentity { profile, response } => {
                let result = self
                    .network
                    .update_identity(profile.zsi_id, profile.tier, profile.vrf_proof)
                    .map_err(NodeError::from);
                let _ = response.send(result);
                Ok(false)
            }
            NodeCommand::Shutdown => Ok(true),
        }
    }

    fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::NewListenAddr(addr) => {
                info!(target: "node", "listening on {addr}");
            }
            NetworkEvent::HandshakeCompleted { peer, payload } => {
                info!(target: "node", "peer connected: {peer}");
                self.connected_peers.insert(peer);
                self.known_versions.insert(peer, payload.zsi_id.clone());
                self.meta_telemetry
                    .record(peer, payload.zsi_id.clone(), Duration::from_millis(0));
                let _ = self.events.send(NodeEvent::PeerConnected { peer, payload });
            }
            NetworkEvent::PeerDisconnected { peer } => {
                info!(target: "node", "peer disconnected: {peer}");
                self.connected_peers.remove(&peer);
                self.known_versions.remove(&peer);
                let _ = self.events.send(NodeEvent::PeerDisconnected { peer });
            }
            NetworkEvent::GossipMessage { peer, topic, data } => {
                if self.gossip_enabled {
                    if let Some(version) = self.known_versions.get(&peer) {
                        self.meta_telemetry
                            .record(peer, version.clone(), Duration::from_millis(0));
                    }
                    let _ = self.events.send(NodeEvent::Gossip { peer, topic, data });
                }
            }
            NetworkEvent::ReputationUpdated {
                peer,
                tier,
                score,
                label,
            } => {
                debug!(
                    target: "node",
                    "reputation updated for {peer}: tier={tier:?} score={score} label={label}"
                );
            }
            NetworkEvent::PeerBanned { peer, until } => {
                warn!(target: "node", "peer {peer} banned until {until:?}");
            }
            NetworkEvent::AdmissionRejected {
                peer,
                topic,
                reason,
            } => {
                warn!(
                    target: "node",
                    "peer {peer} rejected on topic {topic:?}: {reason}"
                );
            }
        }
    }

    async fn emit_heartbeat(&self) {
        let metrics = self.metrics.read().clone();
        let peer_count = self.connected_peers.len();
        let heartbeat = Heartbeat {
            peer_count,
            block_height: metrics.block_height,
            block_hash: metrics.block_hash.clone(),
            transaction_count: metrics.transaction_count,
            reputation_score: metrics.reputation_score,
        };
        let _ = self.events.send(NodeEvent::Heartbeat(heartbeat));

        let meta = self.build_meta_report(peer_count);
        let _ = self.events.send(NodeEvent::MetaTelemetry(meta.clone()));

        let snapshot = TelemetrySnapshot {
            block_height: metrics.block_height,
            block_hash: metrics.block_hash,
            transaction_count: metrics.transaction_count,
            peer_count,
            node_id: self.identity.peer_id().to_base58(),
            reputation_score: metrics.reputation_score,
            timestamp: SystemTime::now(),
        };
        if let Err(err) = self.telemetry.send(snapshot).await {
            warn!(target: "telemetry", "failed to enqueue telemetry snapshot: {err}");
        }
    }

    fn build_meta_report(&self, peer_count: usize) -> MetaTelemetryReport {
        let mut peers = Vec::new();
        for peer in &self.connected_peers {
            if let Some(event) = self.meta_telemetry.latest(peer) {
                peers.push(PeerTelemetry {
                    peer: event.peer,
                    version: event.version.clone(),
                    latency_ms: event.latency.as_millis() as u64,
                    last_seen: event.received_at,
                });
            }
        }
        MetaTelemetryReport {
            local_peer_id: self.identity.peer_id(),
            peer_count,
            peers,
        }
    }
}

/// Handle used to interact with the asynchronous node runtime.
#[derive(Clone)]
pub struct NodeHandle {
    commands: mpsc::Sender<NodeCommand>,
    metrics: Arc<RwLock<NodeMetrics>>,
    events: broadcast::Sender<NodeEvent>,
    local_peer_id: PeerId,
}

impl NodeHandle {
    /// Returns a broadcast receiver for node events.
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.events.subscribe()
    }

    /// Updates the metrics that will be forwarded to telemetry.
    pub fn update_metrics(&self, metrics: NodeMetrics) {
        *self.metrics.write() = metrics;
    }

    /// Publishes a gossip message via the libp2p network.
    pub async fn publish_gossip(&self, topic: GossipTopic, data: Vec<u8>) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::Publish {
                topic,
                data,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        let result = rx.await.map_err(|_| NodeError::CommandChannelClosed)?;
        result
    }

    /// Updates the handshake identity used for peer admission and gossip permissions.
    pub async fn update_identity(&self, profile: IdentityProfile) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::UpdateIdentity {
                profile,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        rx.await.map_err(|_| NodeError::CommandChannelClosed)?
    }

    /// Signals the runtime to shut down.
    pub async fn shutdown(&self) -> Result<(), NodeError> {
        self.commands
            .send(NodeCommand::Shutdown)
            .await
            .map_err(|_| NodeError::CommandChannelClosed)
    }

    /// Returns the local libp2p peer identifier.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;
    use tempfile::tempdir;
    use tokio::task::{self, LocalSet};
    use tokio::time::timeout;

    fn test_config(
        identity_path: PathBuf,
        listen: String,
        bootstrap: Vec<String>,
    ) -> NodeRuntimeConfig {
        let mut p2p = P2pConfig::default();
        p2p.listen_addr = listen;
        p2p.bootstrap_peers = bootstrap;
        p2p.heartbeat_interval_ms = 200;
        p2p.gossip_enabled = true;
        NodeRuntimeConfig {
            identity_path,
            p2p,
            telemetry: TelemetryConfig {
                enabled: false,
                endpoint: None,
                auth_token: None,
                timeout_ms: 50,
                retry_max: 0,
                sample_interval_secs: 1,
            },
            identity: None,
        }
    }

    fn random_listen_addr() -> (String, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind random port");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        (format!("/ip4/127.0.0.1/tcp/{port}"), port)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nodes_exchange_gossip() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let dir_one = tempdir().expect("tempdir");
                let dir_two = tempdir().expect("tempdir");
                let (addr_one, _) = random_listen_addr();
                let (addr_two, _) = random_listen_addr();

                let config_one = test_config(
                    dir_one.path().join("node1.key"),
                    addr_one.clone(),
                    Vec::new(),
                );
                let config_two = test_config(
                    dir_two.path().join("node2.key"),
                    addr_two.clone(),
                    vec![addr_one.clone()],
                );

                let (node_one, handle_one) = NodeInner::new(config_one).expect("node1");
                let (node_two, handle_two) = NodeInner::new(config_two).expect("node2");
                let mut events_two = handle_two.subscribe();

                let task_one = task::spawn_local(async move {
                    node_one.run().await.expect("run node1");
                });
                let task_two = task::spawn_local(async move {
                    node_two.run().await.expect("run node2");
                });

                wait_for_peer_connected(&mut events_two).await;

                handle_one
                    .publish_gossip(GossipTopic::Blocks, b"hello".to_vec())
                    .await
                    .expect("publish");

                let received = timeout(StdDuration::from_secs(5), async {
                    loop {
                        match events_two.recv().await {
                            Ok(NodeEvent::Gossip { topic, data, .. }) => {
                                if topic == GossipTopic::Blocks && data == b"hello".to_vec() {
                                    break;
                                }
                            }
                            Ok(_) => continue,
                            Err(err) => panic!("event channel closed: {err}"),
                        }
                    }
                })
                .await;
                assert!(received.is_ok(), "gossip message not received");

                handle_one.shutdown().await.expect("shutdown1");
                handle_two.shutdown().await.expect("shutdown2");
                let _ = task_one.await;
                let _ = task_two.await;
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn disconnect_produces_event() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let dir_one = tempdir().expect("tempdir");
                let dir_two = tempdir().expect("tempdir");
                let (addr_one, _) = random_listen_addr();
                let (addr_two, _) = random_listen_addr();

                let config_one = test_config(
                    dir_one.path().join("node1.key"),
                    addr_one.clone(),
                    Vec::new(),
                );
                let config_two = test_config(
                    dir_two.path().join("node2.key"),
                    addr_two.clone(),
                    vec![addr_one.clone()],
                );

                let (node_one, handle_one) = NodeInner::new(config_one).expect("node1");
                let (node_two, handle_two) = NodeInner::new(config_two).expect("node2");
                let mut events_two = handle_two.subscribe();

                let task_one = task::spawn_local(async move {
                    node_one.run().await.expect("run node1");
                });
                let task_two = task::spawn_local(async move {
                    node_two.run().await.expect("run node2");
                });

                wait_for_peer_connected(&mut events_two).await;
                handle_one.shutdown().await.expect("shutdown1");

                let disconnected = timeout(StdDuration::from_secs(5), async {
                    loop {
                        match events_two.recv().await {
                            Ok(NodeEvent::PeerDisconnected { .. }) => break,
                            Ok(_) => continue,
                            Err(err) => panic!("event channel closed: {err}"),
                        }
                    }
                })
                .await;
                assert!(disconnected.is_ok(), "disconnect event not observed");

                handle_two.shutdown().await.expect("shutdown2");
                let _ = task_one.await;
                let _ = task_two.await;
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn heartbeat_emits_events_and_telemetry() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let dir = tempdir().expect("tempdir");
                let (addr, _) = random_listen_addr();
                let config = test_config(dir.path().join("node.key"), addr, Vec::new());
                let (node, handle) = NodeInner::new(config).expect("node");
                let mut events = handle.subscribe();

                handle.update_metrics(NodeMetrics {
                    block_height: 12,
                    block_hash: "0xabc".into(),
                    transaction_count: 4,
                    reputation_score: 0.9,
                });

                let task = task::spawn_local(async move {
                    node.run().await.expect("run node");
                });

                let heartbeat = timeout(StdDuration::from_secs(5), async {
                    loop {
                        match events.recv().await {
                            Ok(NodeEvent::Heartbeat(hb)) => break hb,
                            Ok(_) => continue,
                            Err(err) => panic!("event channel closed: {err}"),
                        }
                    }
                })
                .await
                .expect("heartbeat event");
                assert_eq!(heartbeat.block_height, 12);
                assert_eq!(heartbeat.peer_count, 0);

                let meta = timeout(StdDuration::from_secs(5), async {
                    loop {
                        match events.recv().await {
                            Ok(NodeEvent::MetaTelemetry(report)) => break report,
                            Ok(_) => continue,
                            Err(err) => panic!("event channel closed: {err}"),
                        }
                    }
                })
                .await
                .expect("meta telemetry");
                assert_eq!(meta.peer_count, 0);

                handle.shutdown().await.expect("shutdown");
                let _ = task.await;
            })
            .await;
    }

    async fn wait_for_peer_connected(events: &mut broadcast::Receiver<NodeEvent>) {
        timeout(StdDuration::from_secs(5), async {
            loop {
                match events.recv().await {
                    Ok(NodeEvent::PeerConnected { .. }) => break,
                    Ok(_) => continue,
                    Err(err) => panic!("event channel closed: {err}"),
                }
            }
        })
        .await
        .expect("peer connected");
    }
}
