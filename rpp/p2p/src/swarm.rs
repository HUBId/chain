use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::StreamExt;

use crate::vendor::gossipsub::{self, MessageId};
use crate::vendor::identity::Keypair;
use crate::vendor::request_response::{self, ProtocolSupport};
use crate::vendor::swarm::builder::SwarmBuilder;
use crate::vendor::swarm::{ExternalEventHandle, NetworkBehaviour, SwarmEvent};
use crate::vendor::{identify, ping, Multiaddr, PeerId, Swarm};
#[cfg(all(feature = "tcp", feature = "noise", feature = "yamux"))]
use crate::vendor::{noise, tcp, yamux};
use thiserror::Error;

use crate::admission::{AdmissionControl, AdmissionError, ReputationEvent, ReputationOutcome};
use crate::handshake::{HandshakeCodec, HandshakePayload, HANDSHAKE_PROTOCOL};
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

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "RppBehaviourEvent")]
struct RppBehaviour {
    request_response: request_response::Behaviour<HandshakeCodec>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
}

#[derive(Debug)]
enum RppBehaviourEvent {
    RequestResponse(request_response::Event<HandshakePayload, HandshakePayload>),
    Identify(identify::Event),
    Ping(ping::Event),
    Gossipsub(gossipsub::Event),
    Network(NetworkEvent),
}

impl From<request_response::Event<HandshakePayload, HandshakePayload>> for RppBehaviourEvent {
    fn from(event: request_response::Event<HandshakePayload, HandshakePayload>) -> Self {
        RppBehaviourEvent::RequestResponse(event)
    }
}

impl From<identify::Event> for RppBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        RppBehaviourEvent::Identify(event)
    }
}

impl From<ping::Event> for RppBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        RppBehaviourEvent::Ping(event)
    }
}

impl From<gossipsub::Event> for RppBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        RppBehaviourEvent::Gossipsub(event)
    }
}

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

fn build_peer_score_thresholds() -> gossipsub::PeerScoreThresholds {
    gossipsub::PeerScoreThresholds {
        gossip_threshold: -5.0,
        publish_threshold: -15.0,
        graylist_threshold: -30.0,
        accept_px_threshold: 20.0,
        opportunistic_graft_threshold: 3.0,
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
    ReputationUpdated {
        peer: PeerId,
        tier: TierLevel,
        score: f64,
        label: &'static str,
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
}

pub struct Network {
    swarm: Swarm<RppBehaviour>,
    events_handle: ExternalEventHandle<RppBehaviourEvent>,
    peerstore: Arc<Peerstore>,
    admission: AdmissionControl,
    handshake: HandshakePayload,
    identity: Arc<NodeIdentity>,
    gossip_state: Option<Arc<GossipStateStore>>,
    replay: ReplayProtector,
    rate_limiter: RateLimiter,
}

impl Network {
    #[cfg(all(feature = "tcp", feature = "noise", feature = "yamux"))]
    pub fn new(
        identity: Arc<NodeIdentity>,
        peerstore: Arc<Peerstore>,
        handshake: HandshakePayload,
        gossip_state: Option<Arc<GossipStateStore>>,
    ) -> Result<Self, NetworkError> {
        let local_key = identity.clone_keypair();
        let builder = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|err| NetworkError::Noise(err.to_string()))?
            .with_behaviour(|keypair| {
                RppBehaviour::new(keypair)
                    .map_err(|err| Box::<dyn std::error::Error + Send + Sync>::from(err))
            })
            .map_err(|err| NetworkError::Gossipsub(err.to_string()))?;
        let (swarm, events_handle) = builder.build_with_external_event_handle();
        let admission = AdmissionControl::new(peerstore.clone(), identity.metadata().clone());
        let mut network = Self {
            swarm,
            events_handle,
            peerstore,
            admission,
            handshake,
            identity,
            gossip_state,
            replay: ReplayProtector::with_capacity(1024),
            rate_limiter: RateLimiter::new(Duration::from_secs(1), 128),
        };
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
        self.handshake = HandshakePayload::new(zsi_id, Some(vrf_public_key), Some(vrf_proof), tier);
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
        self.enqueue_outcome(outcome)
    }

    fn sign_handshake(&self) -> Result<HandshakePayload, NetworkError> {
        let keypair = self.identity.clone_keypair();
        self.handshake
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
                    let payload = self.sign_handshake()?;
                    self.swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, payload);
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
                SwarmEvent::Behaviour(RppBehaviourEvent::Network(event)) => {
                    return Ok(event);
                }
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
                    Ok(Some(NetworkEvent::HandshakeCompleted {
                        peer,
                        payload: request,
                    }))
                }
                request_response::Message::Response { response, .. } => {
                    self.peerstore.record_handshake(peer, &response)?;
                    Ok(Some(NetworkEvent::HandshakeCompleted {
                        peer,
                        payload: response,
                    }))
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
                                reason: "gossip_replay",
                            },
                        )?;
                        return Ok(None);
                    }
                    if !self.rate_limiter.allow(propagation_source) {
                        tracing::warn!(
                            ?propagation_source,
                            ?topic,
                            "peer exceeded gossip rate limit"
                        );
                        self.penalise_peer(
                            propagation_source,
                            ReputationEvent::ManualPenalty {
                                amount: 0.5,
                                reason: "gossip_rate_limit",
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
                            self.enqueue_outcome(outcome)?;
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
                                    reason: "unauthorised_publish",
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
                    if let Err(err) = self.admission.can_remote_subscribe(&peer_id, gossip_topic) {
                        self.enqueue_rejection(peer_id, gossip_topic, err.clone())?;
                        self.penalise_peer(
                            peer_id,
                            ReputationEvent::ManualPenalty {
                                amount: 0.5,
                                reason: "unauthorised_subscribe",
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
        self.enqueue_outcome(outcome)
    }

    fn enqueue_outcome(&mut self, outcome: ReputationOutcome) -> Result<(), NetworkError> {
        let snapshot = outcome.snapshot;
        self.push_network_event(NetworkEvent::ReputationUpdated {
            peer: snapshot.peer_id,
            tier: snapshot.tier,
            score: snapshot.reputation,
            label: outcome.label,
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

#[cfg(test)]
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
                    reason: "slash_test",
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
