use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use rpp_p2p::vendor::core::transport::memory::MemoryTransport;
use rpp_p2p::vendor::core::upgrade::Version;
use rpp_p2p::vendor::core::Transport;
use rpp_p2p::vendor::gossipsub::{
    self, Behaviour as GossipsubBehaviour, ConfigBuilder, IdentTopic, MessageAuthenticity,
};
use rpp_p2p::vendor::identify;
use rpp_p2p::vendor::identity;
use rpp_p2p::vendor::identity::ed25519;
use rpp_p2p::vendor::multiaddr::Protocol;
use rpp_p2p::vendor::ping;
use rpp_p2p::vendor::plaintext;
use rpp_p2p::vendor::swarm::dial_opts::DialOpts;
use rpp_p2p::vendor::swarm::{ExternalEventHandle, Swarm, SwarmEvent};
use rpp_p2p::vendor::Multiaddr;
use rpp_p2p::vendor::PeerId;
use rpp_p2p::NetworkBehaviour;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::metrics::collector::{MeshAction, SimEvent};
use sha2::{Digest, Sha256};

static NEXT_MEMORY_PORT: AtomicU64 = AtomicU64::new(1);
static STATIC_KEY_SEED: OnceLock<Option<String>> = OnceLock::new();

fn node_keypair(node_index: usize) -> identity::Keypair {
    match STATIC_KEY_SEED.get_or_init(|| std::env::var("RPP_SIM_STATIC_KEY_SEED").ok()) {
        Some(seed) => {
            let mut hasher = Sha256::new();
            hasher.update(seed.as_bytes());
            hasher.update(node_index.to_le_bytes());
            let digest = hasher.finalize();
            let mut secret_bytes = [0u8; 32];
            secret_bytes.copy_from_slice(&digest[..32]);
            let secret = ed25519::SecretKey::try_from_bytes(secret_bytes)
                .expect("hashed seed provides valid ed25519 secret key");
            let keypair = ed25519::Keypair::from(secret);
            identity::Keypair::from(keypair)
        }
        None => identity::Keypair::generate_ed25519(),
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "SimBehaviourEvent")]
struct SimBehaviour {
    gossipsub: GossipsubBehaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

enum SimBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Ping,
    Identify,
}

impl From<gossipsub::Event> for SimBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        SimBehaviourEvent::Gossipsub(event)
    }
}

impl From<ping::Event> for SimBehaviourEvent {
    fn from(_: ping::Event) -> Self {
        SimBehaviourEvent::Ping
    }
}

impl From<identify::Event> for SimBehaviourEvent {
    fn from(_: identify::Event) -> Self {
        SimBehaviourEvent::Identify
    }
}

#[derive(Debug)]
enum NodeCommand {
    Dial { peer_id: PeerId, addr: Multiaddr },
    Publish { data: Vec<u8> },
    Disconnect { peer_id: PeerId },
    Shutdown,
}

#[derive(Clone)]
pub struct NodeHandle {
    pub peer_id: PeerId,
    listen_addr: Multiaddr,
    command_tx: mpsc::Sender<NodeCommand>,
}

impl NodeHandle {
    pub fn listen_addr(&self) -> &Multiaddr {
        &self.listen_addr
    }

    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> Result<()> {
        self.command_tx
            .send(NodeCommand::Dial { peer_id, addr })
            .await
            .context("node command channel closed")
    }

    pub async fn publish(&self, data: Vec<u8>) -> Result<()> {
        self.command_tx
            .send(NodeCommand::Publish { data })
            .await
            .context("node command channel closed")
    }

    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        self.command_tx
            .send(NodeCommand::Disconnect { peer_id })
            .await
            .context("node command channel closed")
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.command_tx
            .send(NodeCommand::Shutdown)
            .await
            .context("node command channel closed")
    }
}

pub struct Node {
    pub handle: NodeHandle,
    pub events: mpsc::UnboundedReceiver<SimEvent>,
    pub external_events: ExternalEventHandle<SimBehaviourEvent>,
}

pub fn spawn_node(node_index: usize, topic: IdentTopic) -> Result<Node> {
    let keypair = node_keypair(node_index);
    let peer_id = PeerId::from(keypair.public());

    let transport = MemoryTransport::new()
        .upgrade(Version::V1)
        .authenticate(plaintext::Config::new(&keypair))
        .multiplex(rpp_p2p::vendor::yamux::Config::for_swarm(
            rpp_p2p::vendor::yamux::allow_all(),
        ))
        .boxed();

    let gossipsub_config = ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .heartbeat_interval(std::time::Duration::from_millis(700))
        .mesh_n_low(4)
        .mesh_n(6)
        .mesh_n_high(8)
        .build()
        .context("failed to build gossipsub config")?;

    let gossipsub = GossipsubBehaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|err| anyhow!("failed to create gossipsub behaviour: {err}"))?;

    let behaviour = SimBehaviour {
        gossipsub,
        ping: ping::Behaviour::new(ping::Config::new()),
        identify: identify::Behaviour::new(identify::Config::new(
            "rpp-sim/0.1".into(),
            keypair.public(),
        )),
    };

    let (mut swarm, external_events) = Swarm::new_with_external_event_channel(
        transport,
        behaviour,
        peer_id,
        rpp_p2p::vendor::swarm::Config::with_tokio_executor(),
    );
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic)
        .map_err(|err| anyhow!("failed to subscribe to simulation topic: {err}"))?;

    let listen_port = NEXT_MEMORY_PORT.fetch_add(1, Ordering::Relaxed);
    let listen_addr = Multiaddr::from(Protocol::Memory(listen_port));
    Swarm::listen_on(&mut swarm, listen_addr.clone()).context("failed to listen")?;

    let (command_tx, mut command_rx) = mpsc::channel(32);
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut seen_messages = HashSet::new();
    let task_topic = topic.clone();
    let local_peer = peer_id;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                command = command_rx.recv() => {
                    match command {
                        Some(NodeCommand::Dial { peer_id: target_peer, addr }) => {
                            let dial_opts = DialOpts::peer_id(target_peer)
                                .addresses(vec![addr])
                                .build();
                            if let Err(err) = Swarm::dial(&mut swarm, dial_opts) {
                                warn!(target = "rpp::sim::node", peer = %target_peer, "dial error: {err:?}");
                            }
                        }
                        Some(NodeCommand::Publish { data }) => {
                            match swarm
                                .behaviour_mut()
                                .gossipsub
                                .publish(task_topic.clone(), data)
                            {
                                Ok(message_id) => {
                                    let _ = event_tx.send(SimEvent::Publish {
                                        peer_id: local_peer,
                                        message_id: message_id.to_string(),
                                        timestamp: Instant::now(),
                                    });
                                }
                                Err(err) => {
                                    warn!(target = "rpp::sim::node", "publish error: {err:?}");
                                }
                            }
                        }
                        Some(NodeCommand::Disconnect { peer_id: target }) => {
                            if let Err(err) = Swarm::disconnect_peer_id(&mut swarm, target) {
                                warn!(
                                    target = "rpp::sim::node",
                                    peer = %target,
                                    "disconnect error: {err:?}"
                                );
                            }
                        }
                        Some(NodeCommand::Shutdown) => break,
                        None => break,
                    }
                }
                swarm_event = swarm.select_next_some() => {
                    match swarm_event {
                        SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(event)) => {
                            handle_gossipsub_event(
                                &mut seen_messages,
                                event,
                                &event_tx,
                                local_peer,
                            );
                        }
                        SwarmEvent::Behaviour(SimBehaviourEvent::Ping) => {}
                        SwarmEvent::Behaviour(SimBehaviourEvent::Identify) => {}
                        _ => {}
                    }
                }
            }
        }
    });

    Ok(Node {
        handle: NodeHandle {
            peer_id: local_peer,
            listen_addr,
            command_tx,
        },
        events: event_rx,
        external_events,
    })
}

fn handle_gossipsub_event(
    seen_messages: &mut HashSet<String>,
    event: gossipsub::Event,
    event_tx: &mpsc::UnboundedSender<SimEvent>,
    local_peer: PeerId,
) {
    match event {
        gossipsub::Event::Message {
            propagation_source,
            message_id,
            ..
        } => {
            let id = message_id.to_string();
            let is_new = seen_messages.insert(id.clone());
            let _ = event_tx.send(SimEvent::Receive {
                peer_id: local_peer,
                propagation_source,
                message_id: id,
                timestamp: Instant::now(),
                duplicate: !is_new,
            });
        }
        gossipsub::Event::Subscribed { peer_id, topic } => {
            let _ = event_tx.send(SimEvent::MeshChange {
                peer_id: local_peer,
                peer: peer_id,
                topic: topic.to_string(),
                action: MeshAction::Subscribe,
                timestamp: Instant::now(),
            });
        }
        gossipsub::Event::Unsubscribed { peer_id, topic } => {
            let _ = event_tx.send(SimEvent::MeshChange {
                peer_id: local_peer,
                peer: peer_id,
                topic: topic.to_string(),
                action: MeshAction::Unsubscribe,
                timestamp: Instant::now(),
            });
        }
        gossipsub::Event::GossipsubNotSupported { peer_id } => {
            debug!(target = "rpp::sim::node", %peer_id, "peer does not support gossipsub");
        }
    }
}
