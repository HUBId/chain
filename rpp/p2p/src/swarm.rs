use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::StreamExt;
use libp2p::gossipsub::{self, MessageId};
use libp2p::identity::Keypair;
use libp2p::noise;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::yamux;
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder, identify, ping};
use thiserror::Error;

use crate::admission::{AdmissionControl, AdmissionError, ReputationEvent, ReputationOutcome};
use crate::handshake::{HANDSHAKE_PROTOCOL, HandshakeCodec, HandshakePayload};
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
}

#[derive(NetworkBehaviour)]
struct RppBehaviour {
    request_response: request_response::Behaviour<HandshakeCodec>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
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
    peerstore: Arc<Peerstore>,
    admission: AdmissionControl,
    handshake: HandshakePayload,
    pending: VecDeque<NetworkEvent>,
    gossip_state: Option<Arc<GossipStateStore>>,
    replay: ReplayProtector,
    rate_limiter: RateLimiter,
}

impl Network {
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
                libp2p::tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|err| NetworkError::Noise(err.to_string()))?
            .with_behaviour(|keypair| {
                RppBehaviour::new(keypair)
                    .map_err(|err| Box::<dyn std::error::Error + Send + Sync>::from(err))
            })
            .map_err(|err| NetworkError::Gossipsub(err.to_string()))?;
        let swarm = builder.build();
        let admission = AdmissionControl::new(peerstore.clone());
        let mut network = Self {
            swarm,
            peerstore,
            admission,
            handshake,
            pending: VecDeque::new(),
            gossip_state,
            replay: ReplayProtector::with_capacity(1024),
            rate_limiter: RateLimiter::new(Duration::from_secs(1), 128),
        };
        network.bootstrap_subscriptions()?;
        Ok(network)
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
        self.enqueue_outcome(outcome);
        Ok(())
    }

    pub async fn next_event(&mut self) -> Result<NetworkEvent, NetworkError> {
        if let Some(event) = self.pending.pop_front() {
            return Ok(event);
        }

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
                    let payload = self.handshake.clone();
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
                SwarmEvent::Behaviour(RppBehaviourEvent::Identify(_)) => {}
                SwarmEvent::Behaviour(RppBehaviourEvent::Ping(_)) => {}
                SwarmEvent::Dialing { .. } | SwarmEvent::ConnectionClosed { .. } => {}
                other => {
                    tracing::trace!(?other, "swarm event ignored");
                }
            }

            if let Some(event) = self.pending.pop_front() {
                return Ok(event);
            }
        }
    }

    fn handle_request_response(
        &mut self,
        event: request_response::Event<HandshakePayload, HandshakePayload>,
    ) -> Result<Option<NetworkEvent>, NetworkError> {
        match event {
            request_response::Event::Message { peer, message } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    self.peerstore.record_handshake(peer, &request)?;
                    let payload = self.handshake.clone();
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
                            self.enqueue_outcome(outcome);
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
                            self.enqueue_rejection(propagation_source, topic, err.clone());
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
                        self.enqueue_rejection(peer_id, gossip_topic, err.clone());
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
        self.enqueue_outcome(outcome);
        Ok(())
    }

    fn enqueue_outcome(&mut self, outcome: ReputationOutcome) {
        let snapshot = outcome.snapshot;
        self.pending.push_back(NetworkEvent::ReputationUpdated {
            peer: snapshot.peer_id,
            tier: snapshot.tier,
            score: snapshot.reputation,
            label: outcome.label,
        });
        if let Some(until) = snapshot.banned_until {
            self.pending.push_back(NetworkEvent::PeerBanned {
                peer: snapshot.peer_id,
                until,
            });
            self.swarm
                .behaviour_mut()
                .gossipsub
                .blacklist_peer(&snapshot.peer_id);
        }
    }

    fn enqueue_rejection(&mut self, peer: PeerId, topic: GossipTopic, reason: AdmissionError) {
        self.pending.push_back(NetworkEvent::AdmissionRejected {
            peer,
            topic,
            reason,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::HandshakePayload;
    use crate::peerstore::PeerstoreConfig;
    use crate::persistence::GossipStateStore;
    use std::time::Duration as StdDuration;
    use tempfile::tempdir;
    use tokio::time::timeout;

    fn temp_identity(path: &std::path::Path) -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::load_or_generate(path).expect("identity"))
    }

    async fn init_network(dir: &tempfile::TempDir, name: &str, tier: TierLevel) -> Network {
        let key_path = dir.path().join(format!("{name}.key"));
        let identity = temp_identity(&key_path);
        let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
        Network::new(
            identity,
            peerstore,
            HandshakePayload::new(name, vec![1, 2, 3], tier),
            None,
        )
        .expect("network")
    }

    #[test]
    fn rehydrates_mesh_from_persistence() {
        let dir = tempdir().expect("tmp");
        let gossip_path = dir.path().join("gossip.json");
        let store = Arc::new(GossipStateStore::open(&gossip_path).expect("gossip"));
        store
            .record_subscription(GossipTopic::Blocks)
            .expect("subscription");
        store
            .record_message(
                GossipTopic::Blocks,
                PeerId::random(),
                blake3::hash(b"payload"),
            )
            .expect("message");

        let key_path = dir.path().join("node.key");
        let identity = temp_identity(&key_path);
        let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
        let network = Network::new(
            identity,
            peerstore,
            HandshakePayload::new("node", vec![1, 2, 3], TierLevel::Tl3),
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
        let peer = PeerId::random();

        network
            .peerstore
            .record_handshake(peer, &HandshakePayload::new("peer", vec![], TierLevel::Tl3))
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
