use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use parking_lot::{Mutex, RwLock};
use thiserror::Error;

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
use crate::vendor::gossipsub::MessageId;
#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
use crate::vendor::gossipsub::{self, AdmissionHooks, TopicMeshConfig};
#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
use crate::vendor::identity::Keypair;
#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
use crate::vendor::ping::PingEventCallback;
#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
use crate::vendor::protocols::request_response::{self, ProtocolSupport};
#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
use crate::vendor::swarm::builder::SwarmBuilder;
#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
use crate::vendor::swarm::{ExternalEventHandle, SwarmEvent};
use crate::vendor::{identify, ping, Swarm};
#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response",
    feature = "tcp",
    feature = "noise",
    feature = "yamux"
))]
use crate::vendor::{noise, tcp, yamux};
use crate::vendor::{Multiaddr, PeerId};
#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
use crate::NetworkBehaviour;

use crate::admission::{
    AdmissionControl, AdmissionError, ReputationBroadcast, ReputationEvent, ReputationOutcome,
};
use crate::handshake::{HandshakeCodec, HandshakePayload, TelemetryMetadata, HANDSHAKE_PROTOCOL};
use crate::identity::NodeIdentity;
use crate::peerstore::{Peerstore, PeerstoreError};
use crate::persistence::GossipStateStore;
use crate::security::{RateLimiter, ReplayProtector};
use crate::tier::TierLevel;
use crate::topics::GossipTopic;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("swarm error: {0}")]
    Swarm(String),
    #[error("noise key signing failed: {0}")]
    Noise(String),
    #[error("peerstore error: {0}")]
    Peerstore(#[from] PeerstoreError),
    #[error("admission denied: {0}")]
    Admission(#[from] AdmissionError),
    #[error("gossipsub error: {0}")]
    Gossipsub(String),
    #[error("persistence error: {0}")]
    Persistence(String),
    #[error("handshake error: {0}")]
    Handshake(String),
    #[error("transport support disabled (enable tcp + noise + yamux features)")]
    TransportDisabled,
}

#[cfg(not(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
)))]
pub type MessageId = ();

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "RppBehaviourEvent")]
struct RppBehaviour {
    request_response: request_response::Behaviour<HandshakeCodec>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
}

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
#[derive(Debug)]
enum RppBehaviourEvent {
    RequestResponse(request_response::Event<HandshakePayload, HandshakePayload>),
    Identify(identify::Event),
    Ping(ping::Event),
    Gossipsub(gossipsub::Event),
    Network(NetworkEvent),
}

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
impl From<request_response::Event<HandshakePayload, HandshakePayload>> for RppBehaviourEvent {
    fn from(event: request_response::Event<HandshakePayload, HandshakePayload>) -> Self {
        RppBehaviourEvent::RequestResponse(event)
    }
}

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
impl From<identify::Event> for RppBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        RppBehaviourEvent::Identify(event)
    }
}

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
impl From<ping::Event> for RppBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        RppBehaviourEvent::Ping(event)
    }
}

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
impl From<gossipsub::Event> for RppBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        RppBehaviourEvent::Gossipsub(event)
    }
}

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
impl RppBehaviour {
    fn new(identity: &Keypair) -> Result<Self, NetworkError> {
        let protocols = std::iter::once((HANDSHAKE_PROTOCOL.to_string(), ProtocolSupport::Full));
        let cfg = request_response::Config::default();
        let request_response =
            request_response::Behaviour::with_codec(HandshakeCodec::default(), protocols, cfg);

        let identify =
            identify::Behaviour::new(identify::Config::new("rpp/0.1.0".into(), identity.public()));

        let ping = ping::Behaviour::new(ping::Config::new());
        let gossipsub = Self::build_gossipsub(identity)?;

        Ok(Self {
            request_response,
            identify,
            ping,
            gossipsub,
        })
    }

    fn build_gossipsub(identity: &Keypair) -> Result<gossipsub::Behaviour, NetworkError> {
        let mut config_builder = gossipsub::ConfigBuilder::default();
        config_builder
            .validation_mode(gossipsub::ValidationMode::Permissive)
            .heartbeat_interval(Duration::from_millis(900))
            .heartbeat_initial_delay(Duration::from_millis(300))
            .mesh_n(8)
            .mesh_n_low(6)
            .mesh_n_high(12)
            .retain_scores(6)
            .gossip_lazy(8)
            .fanout_ttl(Duration::from_secs(45))
            .duplicate_cache_time(Duration::from_secs(30))
            .max_transmit_size(1024 * 256)
            .message_id_fn(|message| {
                let digest = blake3::hash(&message.data);
                MessageId::from(digest.to_hex().to_string())
            });

        for topic in GossipTopic::all() {
            let ident = topic.ident();
            let mesh_config = match topic {
                GossipTopic::Blocks | GossipTopic::Votes => TopicMeshConfig {
                    mesh_n: 10,
                    mesh_n_low: 8,
                    mesh_n_high: 16,
                    mesh_outbound_min: 4,
                },
                GossipTopic::Proofs => TopicMeshConfig {
                    mesh_n: 8,
                    mesh_n_low: 6,
                    mesh_n_high: 12,
                    mesh_outbound_min: 3,
                },
                GossipTopic::Snapshots | GossipTopic::Meta => TopicMeshConfig {
                    mesh_n: 6,
                    mesh_n_low: 4,
                    mesh_n_high: 10,
                    mesh_outbound_min: 2,
                },
            };
            config_builder.set_topic_config(ident.hash(), mesh_config);
        }

        let config = config_builder
            .build()
            .map_err(|err| NetworkError::Gossipsub(format!("config error: {err:?}")))?;

        let mut behaviour = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(identity.clone()),
            config,
        )
        .map_err(|err| NetworkError::Gossipsub(format!("initialise gossipsub: {err}")))?;

        let params = build_peer_score_params();
        let thresholds = build_peer_score_thresholds();
        behaviour
            .with_peer_score(params, thresholds)
            .map_err(|err| NetworkError::Gossipsub(format!("peer score: {err}")))?;

        Ok(behaviour)
    }
}

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
fn build_peer_score_params() -> gossipsub::PeerScoreParams {
    let mut params = gossipsub::PeerScoreParams::default();
    params.topic_score_cap = 150.0;
    params.app_specific_weight = 1.0;
    params.decay_interval = Duration::from_secs(12);
    params.decay_to_zero = 0.05;
    params.retain_score = Duration::from_secs(600);
    params.behaviour_penalty_weight = -2.5;
    params.behaviour_penalty_threshold = 1.0;
    params.behaviour_penalty_decay = gossipsub::score_parameter_decay(Duration::from_secs(90));

    let mut topic_params = std::collections::HashMap::new();
    for topic in GossipTopic::all() {
        let mut config = gossipsub::TopicScoreParams::default();
        config.topic_weight = match topic {
            GossipTopic::Blocks | GossipTopic::Votes => 1.6,
            GossipTopic::Proofs => 1.2,
            GossipTopic::Snapshots => 1.0,
            GossipTopic::Meta => 0.4,
        };
        config.time_in_mesh_cap = 900.0;
        config.first_message_deliveries_cap = 500.0;
        config.mesh_failure_penalty_weight = -0.7;
        topic_params.insert(topic.ident().hash(), config);
    }
    params.topics = topic_params;
    params
}

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
fn build_peer_score_thresholds() -> gossipsub::PeerScoreThresholds {
    gossipsub::PeerScoreThresholds {
        gossip_threshold: -5.0,
        publish_threshold: -15.0,
        graylist_threshold: -30.0,
        accept_px_threshold: 20.0,
        opportunistic_graft_threshold: 3.0,
    }
}

const PING_FAILURE_REPUTATION_THRESHOLD: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PingFailureReason {
    Timeout,
    Unsupported,
    Other(String),
}

impl fmt::Display for PingFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PingFailureReason::Timeout => f.write_str("timeout"),
            PingFailureReason::Unsupported => f.write_str("unsupported"),
            PingFailureReason::Other(reason) => f.write_str(reason),
        }
    }
}

impl From<&ping::Failure> for PingFailureReason {
    fn from(value: &ping::Failure) -> Self {
        match value {
            ping::Failure::Timeout => PingFailureReason::Timeout,
            ping::Failure::Unsupported => PingFailureReason::Unsupported,
            ping::Failure::Other { error } => PingFailureReason::Other(error.to_string()),
        }
    }
}

#[derive(Debug)]
pub enum NetworkEvent {
    NewListenAddr(Multiaddr),
    HandshakeCompleted {
        peer: PeerId,
        payload: HandshakePayload,
    },
    GossipMessage {
        peer: PeerId,
        topic: GossipTopic,
        data: Vec<u8>,
    },
    PeerDisconnected {
        peer: PeerId,
    },
    PingSuccess {
        peer: PeerId,
        rtt: Duration,
    },
    PingFailure {
        peer: PeerId,
        reason: PingFailureReason,
        consecutive_failures: u32,
    },
    ReputationUpdated {
        peer: PeerId,
        tier: TierLevel,
        score: f64,
        label: String,
    },
    PeerBanned {
        peer: PeerId,
        until: SystemTime,
    },
    AdmissionRejected {
        peer: PeerId,
        topic: GossipTopic,
        reason: AdmissionError,
    },
    ReputationOutcome(ReputationOutcome),
}

struct PingReporter {
    peerstore: Arc<Peerstore>,
    events: Arc<ExternalEventHandle<RppBehaviourEvent>>,
}

impl PingReporter {
    fn new(peerstore: Arc<Peerstore>, events: Arc<ExternalEventHandle<RppBehaviourEvent>>) -> Self {
        Self { peerstore, events }
    }

    fn dispatch(&self, event: NetworkEvent) {
        if let Err(err) = self.events.push(RppBehaviourEvent::Network(event)) {
            tracing::warn!(target: "telemetry.ping", error = %err, "ping_event_dispatch_failed");
        }
    }
}

impl PingEventCallback for PingReporter {
    fn on_ping_event(
        &self,
        peer: &PeerId,
        _connection: &ConnectionId,
        result: &Result<Duration, ping::Failure>,
    ) {
        match result {
            Ok(rtt) => {
                if let Err(err) = self.peerstore.record_ping_success(peer.clone(), *rtt) {
                    tracing::debug!(target: "telemetry.ping", %peer, error = %err, "record_ping_success_failed");
                }
                self.dispatch(NetworkEvent::PingSuccess {
                    peer: peer.clone(),
                    rtt: *rtt,
                });
            }
            Err(failure) => {
                let peer_id = peer.clone();
                let failures = match self.peerstore.record_ping_failure(peer_id.clone()) {
                    Ok(count) => count,
                    Err(err) => {
                        tracing::debug!(
                            target: "telemetry.ping",
                            %peer,
                            error = %err,
                            "record_ping_failure_failed"
                        );
                        0
                    }
                };
                let reason = PingFailureReason::from(failure);
                self.dispatch(NetworkEvent::PingFailure {
                    peer: peer_id,
                    reason,
                    consecutive_failures: failures,
                });
            }
        }
    }
}

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
pub struct Network {
    swarm: Swarm<RppBehaviour>,
    events_handle: Arc<ExternalEventHandle<RppBehaviourEvent>>,
    peerstore: Arc<Peerstore>,
    admission: Arc<AdmissionControl>,
    handshake: Arc<RwLock<HandshakePayload>>,
    identity: Arc<NodeIdentity>,
    gossip_state: Option<Arc<GossipStateStore>>,
    replay: ReplayProtector,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

#[cfg(not(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
)))]
#[derive(Default)]
pub struct Network;

#[cfg(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
impl Network {
    fn default_handshake_metadata() -> TelemetryMetadata {
        TelemetryMetadata::with_agent(format!("rpp-p2p/{}", env!("CARGO_PKG_VERSION")))
    }

    #[cfg(all(feature = "tcp", feature = "noise", feature = "yamux"))]
    pub fn new(
        identity: Arc<NodeIdentity>,
        peerstore: Arc<Peerstore>,
        handshake: HandshakePayload,
        gossip_state: Option<Arc<GossipStateStore>>,
    ) -> Result<Self, NetworkError> {
        let handshake = {
            let mut payload = handshake;
            if payload.telemetry.is_none() {
                payload.telemetry = Some(Self::default_handshake_metadata());
            }
            payload
        };
        let handshake_state = Arc::new(RwLock::new(handshake));
        let local_key = identity.clone_keypair();
        let event_handle_slot: Arc<Mutex<Option<Arc<ExternalEventHandle<RppBehaviourEvent>>>>> =
            Arc::new(Mutex::new(None));

        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(Duration::from_secs(1), 128)));
        let inbound_permit = {
            let limiter = rate_limiter.clone();
            yamux::allow(move |peer: &PeerId| limiter.lock().allow(peer.clone()))
        };

        let builder = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                {
                    let identity_for_payload = identity.clone();
                    let handshake_for_payload = handshake_state.clone();
                    let peerstore_for_payload = peerstore.clone();
                    let event_slot = event_handle_slot.clone();
                    move |keypair: &Keypair| -> Result<noise::NoiseAuthenticated, noise::Error> {
                        let local_identity = identity_for_payload.clone();
                        let handshake_state = handshake_for_payload.clone();
                        let peerstore = peerstore_for_payload.clone();
                        let event_slot = event_slot.clone();
                        noise::NoiseAuthenticated::xx(keypair)?
                            .with_handshake_payload(move || {
                                let keypair = local_identity.clone_keypair();
                                let payload = handshake_state.read().clone();
                                let signed = payload.signed(&keypair).map_err(|err| {
                                    noise::HandshakeHookError::new(format!(
                                        "sign handshake payload: {err}"
                                    ))
                                })?;
                                serde_json::to_vec(&signed).map_err(|err| {
                                    noise::HandshakeHookError::new(format!(
                                        "encode handshake payload: {err}"
                                    ))
                                })
                            })
                            .on_handshake_payload(move |public_key, bytes| {
                                let peer_id = PeerId::from(public_key.clone());
                                let handshake: HandshakePayload = serde_json::from_slice(bytes)
                                    .map_err(|err| {
                                        tracing::warn!(
                                            target: "telemetry.handshake",
                                            %peer_id,
                                            error = %err,
                                            "handshake_failure"
                                        );
                                        noise::HandshakeHookError::new(format!(
                                            "decode handshake payload: {err}"
                                        ))
                                    })?;

                                if let Err(err) =
                                    peerstore.record_public_key(peer_id, public_key.clone())
                                {
                                    tracing::warn!(
                                        target: "telemetry.handshake",
                                        %peer_id,
                                        error = %err,
                                        "handshake_failure"
                                    );
                                    return Err(noise::HandshakeHookError::new(format!(
                                        "record public key: {err}"
                                    )));
                                }
                                if let Err(err) = peerstore.record_handshake(peer_id, &handshake) {
                                    tracing::warn!(
                                        target: "telemetry.handshake",
                                        %peer_id,
                                        error = %err,
                                        "handshake_failure"
                                    );
                                    return Err(noise::HandshakeHookError::new(format!(
                                        "record handshake: {err}"
                                    )));
                                }

                                let agent = handshake
                                    .telemetry
                                    .as_ref()
                                    .and_then(|meta| meta.tags.get("agent"))
                                    .cloned()
                                    .unwrap_or_else(|| "unknown".to_string());

                                tracing::info!(
                                    target: "telemetry.handshake",
                                    %peer_id,
                                    zsi = %handshake.zsi_id,
                                    tier = ?handshake.tier,
                                    agent = %agent,
                                    "handshake_success"
                                );

                                if let Some(handle) = event_slot.lock().clone() {
                                    if let Err(err) = handle.push(RppBehaviourEvent::Network(
                                        NetworkEvent::HandshakeCompleted {
                                            peer: peer_id,
                                            payload: handshake.clone(),
                                        },
                                    )) {
                                        tracing::warn!(
                                            target: "telemetry.handshake",
                                            %peer_id,
                                            error = %err,
                                            "handshake_dispatch_failed"
                                        );
                                    }
                                }

                                Ok(())
                            })
                    }
                },
                yamux::Config::for_swarm(inbound_permit.clone()),
            )
            .map_err(|err| NetworkError::Noise(err.to_string()))?
            .with_behaviour(|keypair| {
                RppBehaviour::new(keypair)
                    .map_err(|err| Box::<dyn std::error::Error + Send + Sync>::from(err))
            })
            .map_err(|err| NetworkError::Gossipsub(err.to_string()))?;
        let (swarm, raw_events_handle) = builder.build_with_external_event_handle();
        let events_handle = Arc::new(raw_events_handle);
        *event_handle_slot.lock() = Some(events_handle.clone());

        let admission = Arc::new(AdmissionControl::new(
            peerstore.clone(),
            identity.metadata().clone(),
        ));
        let mut network = Self {
            swarm,
            events_handle,
            peerstore,
            admission,
            handshake: handshake_state,
            identity,
            gossip_state,
            replay: ReplayProtector::with_capacity(1024),
            rate_limiter,
        };
        let push_event: Arc<dyn Fn(NetworkEvent) + Send + Sync> = {
            let handle = network.events_handle.clone();
            Arc::new(move |event: NetworkEvent| {
                if let Err(err) = handle.push(RppBehaviourEvent::Network(event)) {
                    tracing::warn!(
                        target: "telemetry.admission",
                        error = %err,
                        "admission_hook_event_push_failed"
                    );
                }
            })
        };
        let emit_outcome: Arc<dyn Fn(ReputationOutcome) + Send + Sync> = {
            let push_event = Arc::clone(&push_event);
            Arc::new(move |outcome: ReputationOutcome| {
                if let Err(err) = push_event(NetworkEvent::ReputationOutcome(outcome)) {
                    tracing::warn!(
                        target: "telemetry.admission",
                        error = %err,
                        "reputation_outcome_dispatch_failed"
                    );
                }
            })
        };
        let remote_publish_hook: Arc<dyn Fn(&PeerId, &gossipsub::TopicHash) -> bool + Send + Sync> = {
            let admission = Arc::clone(&network.admission);
            let push_event = Arc::clone(&push_event);
            let emit_outcome = Arc::clone(&emit_outcome);
            Arc::new(move |peer, topic_hash| {
                let Some(topic) = GossipTopic::from_hash(topic_hash) else {
                    return true;
                };
                match admission.can_remote_publish(peer, topic) {
                    Ok(_) => true,
                    Err(reason) => {
                        let peer_id = peer.clone();
                        (*push_event)(NetworkEvent::AdmissionRejected {
                            peer: peer_id.clone(),
                            topic,
                            reason: reason.clone(),
                        });
                        match admission.record_event(
                            peer_id,
                            ReputationEvent::ManualPenalty {
                                amount: 0.8,
                                reason: "unauthorised_publish".into(),
                            },
                        ) {
                            Ok(outcome) => (*emit_outcome)(outcome),
                            Err(err) => tracing::warn!(
                                target: "telemetry.admission",
                                error = %err,
                                "publish_penalty_failed"
                            ),
                        }
                        false
                    }
                }
            })
        };
        let remote_subscribe_hook: Arc<
            dyn Fn(&PeerId, &gossipsub::TopicHash) -> bool + Send + Sync,
        > = {
            let admission = Arc::clone(&network.admission);
            let push_event = Arc::clone(&push_event);
            let emit_outcome = Arc::clone(&emit_outcome);
            Arc::new(move |peer, topic_hash| {
                let Some(topic) = GossipTopic::from_hash(topic_hash) else {
                    return true;
                };
                match admission.can_remote_subscribe(peer, topic) {
                    Ok(_) => true,
                    Err(reason) => {
                        let peer_id = peer.clone();
                        (*push_event)(NetworkEvent::AdmissionRejected {
                            peer: peer_id.clone(),
                            topic,
                            reason: reason.clone(),
                        });
                        match admission.record_event(
                            peer_id,
                            ReputationEvent::ManualPenalty {
                                amount: 0.5,
                                reason: "unauthorised_subscribe".into(),
                            },
                        ) {
                            Ok(outcome) => (*emit_outcome)(outcome),
                            Err(err) => tracing::warn!(
                                target: "telemetry.admission",
                                error = %err,
                                "subscribe_penalty_failed"
                            ),
                        }
                        false
                    }
                }
            })
        };
        let mut hooks = AdmissionHooks::default();
        hooks.can_publish_remote = Some(remote_publish_hook);
        hooks.can_subscribe_remote = Some(remote_subscribe_hook);
        network
            .swarm
            .behaviour_mut()
            .gossipsub
            .set_admission_hooks(hooks);
        let ping_callback: Arc<dyn PingEventCallback> = Arc::new(PingReporter::new(
            network.peerstore.clone(),
            network.events_handle.clone(),
        ));
        network
            .swarm
            .behaviour_mut()
            .ping
            .set_event_callback(Some(ping_callback));
        network.bootstrap_subscriptions()?;
        network.bootstrap_known_peers();
        Ok(network)
    }

    #[cfg(not(all(feature = "tcp", feature = "noise", feature = "yamux")))]
    #[allow(unused_variables)]
    pub fn new(
        identity: Arc<NodeIdentity>,
        peerstore: Arc<Peerstore>,
        handshake: HandshakePayload,
        gossip_state: Option<Arc<GossipStateStore>>,
    ) -> Result<Self, NetworkError> {
        Err(NetworkError::TransportDisabled)
    }

    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<(), NetworkError> {
        self.swarm
            .listen_on(addr)
            .map_err(|err| NetworkError::Swarm(err.to_string()))?;
        Ok(())
    }

    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), NetworkError> {
        self.swarm
            .dial(addr)
            .map_err(|err| NetworkError::Swarm(err.to_string()))?;
        Ok(())
    }

    pub fn update_identity(
        &mut self,
        zsi_id: String,
        tier: TierLevel,
        vrf_public_key: Vec<u8>,
        vrf_proof: Vec<u8>,
    ) -> Result<(), NetworkError> {
        {
            let mut guard = self.handshake.write();
            let telemetry = guard
                .telemetry
                .clone()
                .or_else(|| Some(Self::default_handshake_metadata()));
            *guard = HandshakePayload::new(zsi_id, Some(vrf_public_key), Some(vrf_proof), tier)
                .with_telemetry(telemetry.unwrap());
        }
        let signed = self.sign_handshake()?;
        let peer_id = self.local_peer_id();
        self.peerstore.record_handshake(peer_id, &signed)?;
        Ok(())
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub fn publish(
        &mut self,
        topic: GossipTopic,
        data: impl Into<Vec<u8>>,
    ) -> Result<MessageId, NetworkError> {
        self.admission
            .can_publish_local(self.handshake.tier, topic)?;
        let payload = data.into();
        if let Some(state) = &self.gossip_state {
            let digest = blake3::hash(&payload);
            if let Err(err) = state.record_message(topic, self.local_peer_id(), digest) {
                return Err(NetworkError::Persistence(err.to_string()));
            }
            self.replay.observe(digest);
        }
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.ident(), payload)
            .map_err(|err| NetworkError::Gossipsub(format!("publish error: {err:?}")))
    }

    pub fn apply_reputation_event(
        &mut self,
        peer: PeerId,
        event: ReputationEvent,
    ) -> Result<(), NetworkError> {
        let outcome = self.admission.record_event(peer, event)?;
        self.enqueue_outcome(outcome, true)
    }

    pub fn apply_reputation_broadcast(
        &mut self,
        broadcast: ReputationBroadcast,
    ) -> Result<(), NetworkError> {
        let peer = broadcast
            .peer_id()
            .map_err(|err| NetworkError::Peerstore(PeerstoreError::Encoding(err)))?;
        let ReputationBroadcast {
            peer: _,
            event,
            reputation,
            tier: _,
            banned_until,
            label,
        } = broadcast;

        let mut outcome = self.admission.record_event(peer.clone(), event.clone())?;
        outcome.event = event;
        let mut snapshot = self.peerstore.set_reputation(peer.clone(), reputation)?;

        if let Some(millis) = banned_until {
            let until = UNIX_EPOCH + Duration::from_millis(millis);
            let needs_update = snapshot
                .banned_until
                .map(|current| current < until)
                .unwrap_or(true);
            if needs_update {
                snapshot = self.peerstore.ban_peer_until(peer.clone(), until)?;
            }
        }

        outcome.snapshot = snapshot;
        outcome.label = label;
        self.enqueue_outcome(outcome, false)
    }

    fn sign_handshake(&self) -> Result<HandshakePayload, NetworkError> {
        let keypair = self.identity.clone_keypair();
        self.handshake
            .read()
            .clone()
            .signed(&keypair)
            .map_err(|err| NetworkError::Handshake(format!("signing failed: {err}")))
    }

    pub async fn next_event(&mut self) -> Result<NetworkEvent, NetworkError> {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    return Ok(NetworkEvent::NewListenAddr(address));
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    let addr = endpoint.get_remote_address().clone();
                    if let Err(err) = self.peerstore.record_address(peer_id, addr.clone()) {
                        tracing::warn!(?peer_id, ?addr, ?err, "failed to record peer address");
                    }
                }
                SwarmEvent::Behaviour(RppBehaviourEvent::RequestResponse(event)) => {
                    if let Some(evt) = self.handle_request_response(event)? {
                        return Ok(evt);
                    }
                }
                SwarmEvent::Behaviour(RppBehaviourEvent::Gossipsub(event)) => {
                    if let Some(evt) = self.handle_gossipsub_event(event)? {
                        return Ok(evt);
                    }
                }
                SwarmEvent::Behaviour(RppBehaviourEvent::Identify(event)) => {
                    self.handle_identify_event(event);
                }
                SwarmEvent::Behaviour(RppBehaviourEvent::Ping(_)) => {}
                SwarmEvent::Behaviour(RppBehaviourEvent::Network(event)) => match event {
                    NetworkEvent::ReputationOutcome(outcome) => {
                        self.enqueue_outcome(outcome, true)?;
                    }
                    NetworkEvent::PingSuccess { peer, rtt } => {
                        tracing::debug!(
                            target: "telemetry.ping",
                            %peer,
                            latency_ms = rtt.as_millis(),
                            "ping_success_event"
                        );
                        return Ok(NetworkEvent::PingSuccess { peer, rtt });
                    }
                    NetworkEvent::PingFailure {
                        peer,
                        reason,
                        consecutive_failures,
                    } => {
                        tracing::debug!(
                            target: "telemetry.ping",
                            %peer,
                            %reason,
                            failures = consecutive_failures,
                            "ping_failure_event"
                        );
                        if consecutive_failures == PING_FAILURE_REPUTATION_THRESHOLD
                            && !matches!(reason, PingFailureReason::Unsupported)
                        {
                            if let Err(err) = self.penalise_peer(
                                peer.clone(),
                                ReputationEvent::ManualPenalty {
                                    amount: 0.2,
                                    reason: "ping_failure".into(),
                                },
                            ) {
                                tracing::warn!(
                                    target: "telemetry.ping",
                                    %peer,
                                    error = %err,
                                    "ping_penalty_failed"
                                );
                            }
                        }
                        return Ok(NetworkEvent::PingFailure {
                            peer,
                            reason,
                            consecutive_failures,
                        });
                    }
                    other => return Ok(other),
                },
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    return Ok(NetworkEvent::PeerDisconnected { peer: peer_id });
                }
                SwarmEvent::Dialing { .. } => {}
                other => {
                    tracing::trace!(?other, "swarm event ignored");
                }
            }
        }
    }

    fn handle_request_response(
        &mut self,
        event: request_response::Event<HandshakePayload, HandshakePayload>,
    ) -> Result<Option<NetworkEvent>, NetworkError> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    self.peerstore.record_handshake(peer, &request)?;
                    let payload = self.sign_handshake()?;
                    self.swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, payload)
                        .map_err(|err| {
                            NetworkError::Swarm(format!("handshake response error: {err:?}"))
                        })?;
                    Ok(None)
                }
                request_response::Message::Response { response, .. } => {
                    self.peerstore.record_handshake(peer, &response)?;
                    Ok(None)
                }
            },
            request_response::Event::ResponseSent { .. } => Ok(None),
            request_response::Event::OutboundFailure { peer, error, .. } => {
                tracing::warn!(?peer, ?error, "outbound handshake failed");
                Ok(None)
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                tracing::warn!(?peer, ?error, "inbound handshake failed");
                Ok(None)
            }
        }
    }

    fn handle_identify_event(&mut self, event: identify::Event) {
        match event {
            identify::Event::Received { peer_id, info, .. }
            | identify::Event::Pushed { peer_id, info, .. } => {
                if let Err(err) = self.peerstore.record_public_key(peer_id, info.public_key) {
                    tracing::debug!(?peer_id, ?err, "failed to record identify info");
                }
            }
            identify::Event::Sent { .. } => {}
            identify::Event::Error { peer_id, error, .. } => {
                tracing::debug!(?peer_id, ?error, "identify exchange error");
            }
        }
    }

    fn handle_gossipsub_event(
        &mut self,
        event: gossipsub::Event,
    ) -> Result<Option<NetworkEvent>, NetworkError> {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            } => {
                if let Some(topic) = GossipTopic::from_hash(&message.topic) {
                    let digest = blake3::hash(&message.data);
                    if !self.replay.observe(digest) {
                        tracing::warn!(?propagation_source, ?topic, "replayed gossip detected");
                        self.penalise_peer(
                            propagation_source,
                            ReputationEvent::ManualPenalty {
                                amount: 1.0,
                                reason: "gossip_replay".into(),
                            },
                        )?;
                        return Ok(None);
                    }
                    if !self.rate_limiter.lock().allow(propagation_source) {
                        tracing::warn!(
                            ?propagation_source,
                            ?topic,
                            "peer exceeded gossip rate limit"
                        );
                        self.penalise_peer(
                            propagation_source,
                            ReputationEvent::ManualPenalty {
                                amount: 0.5,
                                reason: "gossip_rate_limit".into(),
                            },
                        )?;
                        return Ok(None);
                    }
                    match self
                        .admission
                        .can_remote_publish(&propagation_source, topic)
                    {
                        Ok(_) => {
                            let outcome = self.admission.record_event(
                                propagation_source,
                                ReputationEvent::GossipSuccess { topic },
                            )?;
                            self.enqueue_outcome(outcome, true)?;
                            if let Some(score) = self
                                .swarm
                                .behaviour()
                                .gossipsub
                                .peer_score(&propagation_source)
                            {
                                let mesh_peers = self
                                    .swarm
                                    .behaviour()
                                    .gossipsub
                                    .mesh_peers(&message.topic)
                                    .count();
                                tracing::debug!(
                                    target: "telemetry.gossip",
                                    peer = ?propagation_source,
                                    topic = %topic,
                                    score,
                                    mesh_peers,
                                    "gossip_message_accepted"
                                );
                            }
                            if let Some(state) = &self.gossip_state {
                                if let Err(err) =
                                    state.record_message(topic, propagation_source, digest)
                                {
                                    tracing::warn!(
                                        ?topic,
                                        ?err,
                                        "failed to persist gossip message"
                                    );
                                }
                            }
                            return Ok(Some(NetworkEvent::GossipMessage {
                                peer: propagation_source,
                                topic,
                                data: message.data,
                            }));
                        }
                        Err(err) => {
                            self.enqueue_rejection(propagation_source, topic, err.clone())?;
                            self.penalise_peer(
                                propagation_source,
                                ReputationEvent::ManualPenalty {
                                    amount: 0.8,
                                    reason: "unauthorised_publish".into(),
                                },
                            )?;
                            self.swarm
                                .behaviour_mut()
                                .gossipsub
                                .blacklist_peer(&propagation_source);
                        }
                    }
                }
                Ok(None)
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                if let Some(gossip_topic) = GossipTopic::from_hash(&topic) {
                    if let Some(state) = &self.gossip_state {
                        if let Err(err) = state.record_subscription(gossip_topic) {
                            tracing::warn!(?gossip_topic, ?err, "failed to record subscription");
                        }
                    }
                    if let Some(score) = self.swarm.behaviour().gossipsub.peer_score(&peer_id) {
                        let mesh_size = self.swarm.behaviour().gossipsub.mesh_peers(&topic).count();
                        tracing::debug!(
                            target: "telemetry.gossip",
                            peer = ?peer_id,
                            topic = %gossip_topic,
                            score,
                            mesh_size,
                            "peer_subscribed"
                        );
                    }
                    if let Err(err) = self.admission.can_remote_subscribe(&peer_id, gossip_topic) {
                        self.enqueue_rejection(peer_id, gossip_topic, err.clone())?;
                        self.penalise_peer(
                            peer_id,
                            ReputationEvent::ManualPenalty {
                                amount: 0.5,
                                reason: "unauthorised_subscribe".into(),
                            },
                        )?;
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .blacklist_peer(&peer_id);
                    }
                }
                Ok(None)
            }
            gossipsub::Event::Unsubscribed { topic, .. } => {
                if let Some(state) = &self.gossip_state {
                    if let Some(gossip_topic) = GossipTopic::from_hash(&topic) {
                        if let Err(err) = state.record_unsubscribe(gossip_topic) {
                            tracing::warn!(?gossip_topic, ?err, "failed to record unsubscribe");
                        }
                    }
                }
                Ok(None)
            }
            gossipsub::Event::GossipsubNotSupported { .. } => Ok(None),
            gossipsub::Event::SlowPeer { .. } => Ok(None),
        }
    }

    fn bootstrap_subscriptions(&mut self) -> Result<(), NetworkError> {
        let mut subscribed = false;
        if let Some(state) = &self.gossip_state {
            self.replay.preload(state.recent_digests());
            let stored_subscriptions = state.subscriptions();
            let peers: Vec<PeerId> = GossipTopic::all()
                .into_iter()
                .flat_map(|topic| state.peers_for(topic))
                .collect();
            for topic in stored_subscriptions {
                if self.try_subscribe(topic).is_ok() {
                    subscribed = true;
                }
            }
            for peer in peers {
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .add_explicit_peer(&peer);
            }
        }
        if !subscribed {
            for topic in GossipTopic::all() {
                let _ = self.try_subscribe(topic);
            }
        }
        Ok(())
    }

    fn publish_reputation_broadcast(&mut self, outcome: &ReputationOutcome) {
        let broadcast = ReputationBroadcast::new(outcome);
        let peer = broadcast.peer.clone();
        match serde_json::to_vec(&broadcast) {
            Ok(bytes) => {
                if let Err(err) = self.publish(GossipTopic::Meta, bytes) {
                    tracing::warn!(
                        target: "telemetry.admission",
                        %peer,
                        error = %err,
                        "reputation_broadcast_failed"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    target: "telemetry.admission",
                    %peer,
                    error = %err,
                    "reputation_broadcast_encode_failed"
                );
            }
        }
    }

    fn bootstrap_known_peers(&mut self) {
        let local = self.local_peer_id();
        for record in self.peerstore.known_peers() {
            if record.peer_id == local {
                continue;
            }
            self.swarm
                .behaviour_mut()
                .gossipsub
                .add_explicit_peer(&record.peer_id);
            for addr in record.addresses {
                if let Err(err) = self.swarm.dial(addr.clone()) {
                    tracing::debug!(?record.peer_id, ?addr, ?err, "failed to dial stored peer");
                }
            }
        }
    }

    fn try_subscribe(&mut self, topic: GossipTopic) -> Result<(), NetworkError> {
        if self
            .admission
            .can_subscribe_local(self.handshake.tier, topic)
            .is_err()
        {
            return Ok(());
        }
        let ident = topic.ident();
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&ident)
            .map_err(|err| {
                NetworkError::Gossipsub(format!("failed to subscribe to {topic:?}: {err}"))
            })?;
        if let Some(state) = &self.gossip_state {
            if let Err(err) = state.record_subscription(topic) {
                tracing::warn!(?topic, ?err, "failed to persist subscription");
            }
        }
        Ok(())
    }

    fn penalise_peer(&mut self, peer: PeerId, event: ReputationEvent) -> Result<(), NetworkError> {
        let outcome = self.admission.record_event(peer, event)?;
        self.enqueue_outcome(outcome, true)
    }

    fn enqueue_outcome(
        &mut self,
        outcome: ReputationOutcome,
        propagate: bool,
    ) -> Result<(), NetworkError> {
        if propagate {
            self.publish_reputation_broadcast(&outcome);
        }
        let snapshot = outcome.snapshot.clone();
        self.push_network_event(NetworkEvent::ReputationUpdated {
            peer: snapshot.peer_id,
            tier: snapshot.tier,
            score: snapshot.reputation,
            label: outcome.label.clone(),
        })?;
        if let Some(until) = snapshot.banned_until {
            self.push_network_event(NetworkEvent::PeerBanned {
                peer: snapshot.peer_id,
                until,
            })?;
            self.swarm
                .behaviour_mut()
                .gossipsub
                .blacklist_peer(&snapshot.peer_id);
        }
        Ok(())
    }

    fn enqueue_rejection(
        &mut self,
        peer: PeerId,
        topic: GossipTopic,
        reason: AdmissionError,
    ) -> Result<(), NetworkError> {
        self.push_network_event(NetworkEvent::AdmissionRejected {
            peer,
            topic,
            reason,
        })
    }

    fn push_network_event(&mut self, event: NetworkEvent) -> Result<(), NetworkError> {
        self.events_handle
            .push(RppBehaviourEvent::Network(event))
            .map_err(|err| NetworkError::Swarm(err.to_string()))
    }
}

#[cfg(not(all(
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
)))]
impl Network {
    pub fn new(
        _identity: Arc<NodeIdentity>,
        _peerstore: Arc<Peerstore>,
        _handshake: HandshakePayload,
        _gossip_state: Option<Arc<GossipStateStore>>,
    ) -> Result<Self, NetworkError> {
        Err(NetworkError::TransportDisabled)
    }

    pub fn listen_on(&mut self, _addr: Multiaddr) -> Result<(), NetworkError> {
        Err(NetworkError::TransportDisabled)
    }

    pub fn dial(&mut self, _addr: Multiaddr) -> Result<(), NetworkError> {
        Err(NetworkError::TransportDisabled)
    }

    pub fn update_identity(
        &mut self,
        _zsi_id: String,
        _tier: TierLevel,
        _vrf_public_key: Vec<u8>,
        _vrf_proof: Vec<u8>,
    ) -> Result<(), NetworkError> {
        Err(NetworkError::TransportDisabled)
    }

    pub fn local_peer_id(&self) -> PeerId {
        panic!("libp2p network behaviour disabled")
    }

    pub fn publish(
        &mut self,
        _topic: GossipTopic,
        _data: impl Into<Vec<u8>>,
    ) -> Result<MessageId, NetworkError> {
        Err(NetworkError::TransportDisabled)
    }

    pub fn apply_reputation_event(
        &mut self,
        _peer: PeerId,
        _event: ReputationEvent,
    ) -> Result<(), NetworkError> {
        Err(NetworkError::TransportDisabled)
    }

    pub async fn next_event(&mut self) -> Result<NetworkEvent, NetworkError> {
        Err(NetworkError::TransportDisabled)
    }
}

#[cfg(all(
    test,
    feature = "gossipsub",
    feature = "identify",
    feature = "ping",
    feature = "request-response"
))]
mod tests {
    use super::*;
    use crate::handshake::{HandshakePayload, VRF_HANDSHAKE_CONTEXT};
    use crate::peerstore::PeerstoreConfig;
    use crate::persistence::GossipStateStore;
    use crate::vendor::identity;
    use rand::rngs::OsRng;
    use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
    use std::time::Duration as StdDuration;
    use tempfile::tempdir;
    use tokio::time::timeout;

    fn temp_identity(path: &std::path::Path) -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::load_or_generate(path).expect("identity"))
    }

    fn template_handshake(zsi: &str, tier: TierLevel) -> HandshakePayload {
        let mut rng = OsRng;
        let secret = MiniSecretKey::generate_with(&mut rng);
        let keypair = secret.expand_to_keypair(ExpansionMode::Uniform);
        let public = keypair.public.to_bytes().to_vec();
        let template = HandshakePayload::new(zsi.to_string(), Some(public.clone()), None, tier);
        let proof = keypair
            .sign_simple(VRF_HANDSHAKE_CONTEXT, &template.vrf_message())
            .to_bytes()
            .to_vec();
        HandshakePayload::new(zsi.to_string(), Some(public), Some(proof), tier)
    }

    fn signed_remote_handshake(
        keypair: &identity::Keypair,
        zsi: &str,
        tier: TierLevel,
    ) -> HandshakePayload {
        let mut rng = OsRng;
        let secret = MiniSecretKey::generate_with(&mut rng);
        let sr = secret.expand_to_keypair(ExpansionMode::Uniform);
        let public = sr.public.to_bytes().to_vec();
        let template = HandshakePayload::new(zsi.to_string(), Some(public.clone()), None, tier);
        let proof = sr
            .sign_simple(VRF_HANDSHAKE_CONTEXT, &template.vrf_message())
            .to_bytes()
            .to_vec();
        let template = HandshakePayload::new(zsi.to_string(), Some(public), Some(proof), tier);
        template.signed(keypair).expect("handshake")
    }

    async fn init_network(dir: &tempfile::TempDir, name: &str, tier: TierLevel) -> Network {
        let key_path = dir.path().join(format!("{name}.key"));
        let identity = temp_identity(&key_path);
        let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
        Network::new(identity, peerstore, template_handshake(name, tier), None).expect("network")
    }

    #[test]
    fn rehydrates_mesh_from_persistence() {
        let dir = tempdir().expect("tmp");
        let gossip_path = dir.path().join("gossip.json");
        let store = Arc::new(GossipStateStore::open(&gossip_path).expect("gossip"));
        store
            .record_subscription(GossipTopic::Blocks)
            .expect("subscription");
        let mesh_peer = PeerId::random();
        store
            .record_message(GossipTopic::Blocks, mesh_peer, blake3::hash(b"payload"))
            .expect("message");

        let key_path = dir.path().join("node.key");
        let identity = temp_identity(&key_path);
        let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
        let mut network = Network::new(
            identity,
            peerstore,
            template_handshake("node", TierLevel::Tl3),
            Some(store.clone()),
        )
        .expect("network");

        let subscribed: Vec<_> = network
            .swarm
            .behaviour()
            .gossipsub
            .topics()
            .into_iter()
            .filter_map(|hash| GossipTopic::from_hash(&hash))
            .collect();
        assert!(subscribed.contains(&GossipTopic::Blocks));
        assert!(!store.recent_digests().is_empty());
        assert!(
            !network.replay.observe(blake3::hash(b"payload")),
            "preloaded digests should be recognised"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gossipsub_mesh_updates_reputation() {
        let dir = tempdir().expect("tmp");
        let mut network_a = init_network(&dir, "a", TierLevel::Tl3).await;
        let mut network_b = init_network(&dir, "b", TierLevel::Tl3).await;

        network_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");

        let listen_addr = loop {
            match timeout(StdDuration::from_secs(10), network_a.next_event()).await {
                Ok(Ok(NetworkEvent::NewListenAddr(addr))) => break addr,
                Ok(_) => continue,
                other => panic!("unexpected listen event: {other:?}"),
            }
        };

        network_b.dial(listen_addr.clone()).expect("dial");

        let mut got_a = false;
        let mut got_b = false;
        for _ in 0..40 {
            if !got_a {
                if let Ok(Ok(event)) =
                    timeout(StdDuration::from_millis(250), network_a.next_event()).await
                {
                    if let NetworkEvent::HandshakeCompleted { .. } = event {
                        got_a = true;
                    }
                }
            }
            if !got_b {
                if let Ok(Ok(event)) =
                    timeout(StdDuration::from_millis(250), network_b.next_event()).await
                {
                    if let NetworkEvent::HandshakeCompleted { .. } = event {
                        got_b = true;
                    }
                }
            }
            if got_a && got_b {
                break;
            }
        }
        assert!(got_a && got_b, "handshake exchange timed out");

        let mut publish_ok = false;
        for _ in 0..10 {
            match network_a.publish(GossipTopic::Blocks, b"block".to_vec()) {
                Ok(_) => {
                    publish_ok = true;
                    break;
                }
                Err(NetworkError::Gossipsub(msg)) if msg.contains("InsufficientPeers") => {
                    let _ = timeout(StdDuration::from_millis(200), network_a.next_event()).await;
                    let _ = timeout(StdDuration::from_millis(200), network_b.next_event()).await;
                }
                Err(err) => panic!("unexpected publish error: {err:?}"),
            }
        }
        assert!(publish_ok, "publish did not succeed due to missing peers");

        let mut got_message = false;
        let mut got_reputation = false;

        timeout(StdDuration::from_secs(20), async {
            while !(got_message && got_reputation) {
                if let Ok(Ok(event)) =
                    timeout(StdDuration::from_millis(250), network_a.next_event()).await
                {
                    if let NetworkEvent::ReputationUpdated { peer, .. } = event {
                        if peer == network_b.local_peer_id() {
                            got_reputation = true;
                        }
                    }
                }
                if let Ok(Ok(event)) =
                    timeout(StdDuration::from_millis(250), network_b.next_event()).await
                {
                    match event {
                        NetworkEvent::GossipMessage { peer, topic, data } => {
                            assert_eq!(topic, GossipTopic::Blocks);
                            assert_eq!(data, b"block");
                            assert_eq!(peer, network_a.local_peer_id());
                            got_message = true;
                        }
                        NetworkEvent::ReputationUpdated { peer, score, .. } => {
                            if peer == network_a.local_peer_id() && score > 0.0 {
                                got_reputation = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        })
        .await
        .expect("gossip exchange timed out");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tier_gating_blocks_low_tier_peers() {
        let dir = tempdir().expect("tmp");
        let mut low = init_network(&dir, "low", TierLevel::Tl0).await;
        let mut mid = init_network(&dir, "mid", TierLevel::Tl1).await;
        let mut high = init_network(&dir, "high", TierLevel::Tl3).await;

        assert!(matches!(
            low.publish(GossipTopic::Proofs, b"proof".to_vec()),
            Err(NetworkError::Admission(
                AdmissionError::TierInsufficient { .. }
            ))
        ));

        assert!(matches!(
            mid.publish(GossipTopic::Votes, b"vote".to_vec()),
            Err(NetworkError::Admission(
                AdmissionError::TierInsufficient { .. }
            ))
        ));

        match high.publish(GossipTopic::Votes, b"vote".to_vec()) {
            Ok(_) => {}
            Err(NetworkError::Gossipsub(msg)) => {
                assert!(msg.contains("InsufficientPeers"), "unexpected error: {msg}");
            }
            Err(err) => panic!("unexpected publish error: {err:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reputation_slash_triggers_ban() {
        let dir = tempdir().expect("tmp");
        let mut network = init_network(&dir, "node", TierLevel::Tl3).await;
        let keypair = identity::Keypair::generate_ed25519();
        let peer = PeerId::from(keypair.public());
        let handshake = signed_remote_handshake(&keypair, "peer", TierLevel::Tl3);

        network
            .peerstore
            .record_handshake(peer, &handshake)
            .expect("handshake");

        network
            .apply_reputation_event(
                peer,
                ReputationEvent::Slash {
                    severity: 1.0,
                    reason: "slash_test".into(),
                },
            )
            .expect("slash");

        let mut saw_ban = false;
        let mut saw_update = false;

        timeout(StdDuration::from_secs(5), async {
            while !(saw_ban && saw_update) {
                match network.next_event().await.expect("event") {
                    NetworkEvent::PeerBanned { peer: banned, .. } => {
                        assert_eq!(banned, peer);
                        saw_ban = true;
                    }
                    NetworkEvent::ReputationUpdated { peer: updated, .. } => {
                        if updated == peer {
                            saw_update = true;
                        }
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("ban events");
    }
}
