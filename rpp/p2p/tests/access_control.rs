use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

// NOTE: Vendored libp2p types must be used to avoid pulling upstream crates
// directly into the test harness.
use jsonschema::JSONSchema;
use rand::rngs::OsRng;
use rpp_p2p::vendor::{identity, PeerId};
use rpp_p2p::{
    AdmissionControl, AdmissionError, AllowlistedPeer, GossipTopic, HandshakePayload,
    IdentityMetadata, IdentityVerifier, Network, NetworkError, NetworkEvent, NodeIdentity,
    Peerstore, PeerstoreConfig, ReputationBroadcast, ReputationEvent, ReputationHeuristics,
    TierLevel, TopicPermission, VRF_HANDSHAKE_CONTEXT,
};
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use tempfile::tempdir;
use tokio::time::timeout;

struct StaticVerifier {
    expected: HashMap<String, Vec<u8>>,
}

impl StaticVerifier {
    fn new(entries: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        Self {
            expected: entries.into_iter().collect(),
        }
    }
}

impl IdentityVerifier for StaticVerifier {
    fn expected_vrf_public_key(&self, zsi_id: &str) -> Option<Vec<u8>> {
        self.expected.get(zsi_id).cloned()
    }
}

fn sign_vrf_message(secret: &MiniSecretKey, payload: &HandshakePayload) -> Vec<u8> {
    let keypair = secret.expand_to_keypair(ExpansionMode::Uniform);
    keypair
        .sign_simple(VRF_HANDSHAKE_CONTEXT, &payload.vrf_message())
        .to_bytes()
        .to_vec()
}

fn signed_handshake(
    keypair: &identity::Keypair,
    zsi: &str,
    tier: TierLevel,
    vrf_secret: &MiniSecretKey,
) -> HandshakePayload {
    let public = vrf_secret
        .expand_to_keypair(ExpansionMode::Uniform)
        .public
        .to_bytes()
        .to_vec();
    let template = HandshakePayload::new(zsi.to_string(), Some(public.clone()), None, tier);
    let proof = sign_vrf_message(vrf_secret, &template);
    let template = HandshakePayload::new(zsi.to_string(), Some(public), Some(proof), tier);
    template.signed(keypair).expect("handshake")
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

fn init_network(
    dir: &tempfile::TempDir,
    name: &str,
    tier: TierLevel,
    rate_limit: u64,
    replay: usize,
) -> Network {
    let key_path = dir.path().join(format!("{name}.key"));
    let identity = Arc::new(NodeIdentity::load_or_generate(&key_path).expect("identity"));
    let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
    Network::new(
        identity,
        peerstore,
        template_handshake(name, tier),
        None,
        rate_limit,
        replay,
        ReputationHeuristics::default(),
    )
    .expect("network")
}

#[test]
fn heuristics_vote_timeout_penalises_peer() {
    let store = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
    let peer = PeerId::random();
    store
        .update_reputation(peer.clone(), 2.0)
        .expect("baseline reputation");
    let heuristics = ReputationHeuristics {
        vote_timeout_penalty: 0.7,
        ..Default::default()
    };
    let control =
        AdmissionControl::with_heuristics(store.clone(), IdentityMetadata::default(), heuristics);

    let outcome = control
        .record_event(
            peer.clone(),
            ReputationEvent::VoteTimeout {
                height: 42,
                round: 3,
            },
        )
        .expect("penalty applied");

    assert!(
        (outcome.snapshot.reputation - 1.3).abs() < f64::EPSILON,
        "expected vote timeout penalty to be applied"
    );
}

#[test]
fn heuristics_proof_relay_penalty_respects_configuration() {
    let store = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
    let peer = PeerId::random();
    store
        .update_reputation(peer.clone(), 1.5)
        .expect("baseline reputation");
    let heuristics = ReputationHeuristics {
        proof_relay_penalty: 0.5,
        ..Default::default()
    };
    let control =
        AdmissionControl::with_heuristics(store.clone(), IdentityMetadata::default(), heuristics);

    let outcome = control
        .record_event(
            peer.clone(),
            ReputationEvent::ProofRelayMissed {
                height: Some(12),
                reason: Some(Cow::Borrowed("missing proof commitment")),
            },
        )
        .expect("penalty applied");

    assert!(
        (outcome.snapshot.reputation - 1.0).abs() < f64::EPSILON,
        "expected proof relay penalty to reduce reputation"
    );
}

#[test]
fn heuristics_gossip_backpressure_threshold() {
    let store = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
    let peer = PeerId::random();
    store
        .update_reputation(peer.clone(), 1.0)
        .expect("baseline reputation");
    let heuristics = ReputationHeuristics {
        gossip_backpressure_penalty: 0.25,
        gossip_backpressure_threshold: 5,
        ..Default::default()
    };
    let control =
        AdmissionControl::with_heuristics(store.clone(), IdentityMetadata::default(), heuristics);

    // Below threshold should leave reputation unchanged.
    control
        .record_event(
            peer.clone(),
            ReputationEvent::GossipBackpressure {
                topic: GossipTopic::Blocks,
                queue_depth: 3,
            },
        )
        .expect("event accepted");
    let snapshot = store
        .reputation_snapshot(&peer)
        .expect("snapshot available");
    assert!(
        (snapshot.reputation - 1.0).abs() < f64::EPSILON,
        "no penalty expected below threshold"
    );

    // Above threshold should apply penalty.
    let outcome = control
        .record_event(
            peer.clone(),
            ReputationEvent::GossipBackpressure {
                topic: GossipTopic::Blocks,
                queue_depth: 6,
            },
        )
        .expect("penalty applied");
    assert!(
        (outcome.snapshot.reputation - 0.75).abs() < f64::EPSILON,
        "expected backpressure penalty to be applied"
    );
}

#[test]
fn blocklisted_peers_are_banned_and_rejected() {
    let keypair = identity::Keypair::generate_ed25519();
    let peer = PeerId::from(keypair.public());
    let store = Arc::new(
        Peerstore::open(PeerstoreConfig::memory().with_blocklist(vec![peer])).expect("peerstore"),
    );

    assert!(store.is_blocklisted(&peer));
    let ban_until = store
        .is_banned(&peer)
        .expect("blocklisted peer should be banned");
    assert!(ban_until > SystemTime::now());

    let control = AdmissionControl::new(store.clone(), IdentityMetadata::default());
    let admission = control.can_remote_publish(&peer, GossipTopic::Votes);
    match admission {
        Err(AdmissionError::Banned { until }) => assert!(until >= ban_until),
        other => panic!("expected banned error, got {other:?}"),
    }

    let payload = HandshakePayload::new("peer", None, None, TierLevel::Tl0);
    let error = store
        .record_handshake(peer, &payload)
        .expect_err("handshake must be rejected");
    match error {
        rpp_p2p::PeerstoreError::Blocklisted { .. } => {}
        other => panic!("expected blocklisted error, got {other:?}"),
    }
}

#[test]
fn access_lists_can_be_reloaded_and_persisted() {
    let dir = tempdir().expect("tmp");
    let path = dir.path().join("peerstore.json");
    let allow_peer = PeerId::from(identity::Keypair::generate_ed25519().public());
    let block_peer = PeerId::from(identity::Keypair::generate_ed25519().public());

    {
        let store = Peerstore::open(PeerstoreConfig::persistent(&path)).expect("peerstore");
        store
            .reload_access_lists(
                vec![AllowlistedPeer {
                    peer: allow_peer.clone(),
                    tier: TierLevel::Tl3,
                }],
                vec![block_peer.clone()],
            )
            .expect("reload");
        assert!(store.is_blocklisted(&block_peer));
        assert_eq!(store.tier_of(&allow_peer), TierLevel::Tl3);
    }

    let reopened = Peerstore::open(PeerstoreConfig::persistent(&path)).expect("peerstore");
    assert!(reopened.is_blocklisted(&block_peer));
    assert_eq!(reopened.tier_of(&allow_peer), TierLevel::Tl3);
}

#[test]
fn blocklist_reload_clears_removed_entries() {
    let store = Peerstore::open(PeerstoreConfig::memory()).expect("peerstore");
    let peer = PeerId::from(identity::Keypair::generate_ed25519().public());

    store
        .reload_access_lists(Vec::new(), vec![peer.clone()])
        .expect("reload");
    assert!(store.is_blocklisted(&peer));

    store
        .reload_access_lists(Vec::new(), Vec::new())
        .expect("reload");
    assert!(!store.is_blocklisted(&peer));
    assert!(store.is_banned(&peer).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_gossip_limits_penalise_fast_publishers() {
    let dir = tempdir().expect("tmp");
    let mut network_a = init_network(&dir, "a", TierLevel::Tl3, 1, 256);
    let mut network_b = init_network(&dir, "b", TierLevel::Tl3, 1, 256);

    network_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("listen");

    let listen_addr = loop {
        match timeout(Duration::from_secs(10), network_a.next_event()).await {
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
            if let Ok(Ok(event)) = timeout(Duration::from_millis(250), network_a.next_event()).await
            {
                if let NetworkEvent::HandshakeCompleted { .. } = event {
                    got_a = true;
                }
            }
        }
        if !got_b {
            if let Ok(Ok(event)) = timeout(Duration::from_millis(250), network_b.next_event()).await
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

    assert_eq!(network_a.gossip_rate_limit().1, 1);
    assert_eq!(network_a.replay_window_capacity(), 256);

    let mut publish_ok = false;
    for _ in 0..10 {
        match network_b.publish(GossipTopic::Blocks, b"block-1".to_vec()) {
            Ok(_) => {
                publish_ok = true;
                break;
            }
            Err(NetworkError::Gossipsub(msg)) if msg.contains("InsufficientPeers") => {
                let _ = timeout(Duration::from_millis(200), network_a.next_event()).await;
                let _ = timeout(Duration::from_millis(200), network_b.next_event()).await;
            }
            Err(err) => panic!("unexpected publish error: {err:?}"),
        }
    }
    assert!(publish_ok, "publish did not succeed due to missing peers");

    let peer_b = network_b.local_peer_id();
    let mut success_observed = false;
    for _ in 0..40 {
        if let Ok(Ok(event)) = timeout(Duration::from_secs(1), network_a.next_event()).await {
            match event {
                NetworkEvent::ReputationUpdated { peer, label, .. }
                    if peer == peer_b && label == "gossip_success" =>
                {
                    success_observed = true;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(success_observed, "expected gossip success before penalty");

    network_b
        .publish(GossipTopic::Blocks, b"block-2".to_vec())
        .expect("second publish");

    let mut penalty_observed = false;
    for _ in 0..40 {
        if let Ok(Ok(event)) = timeout(Duration::from_secs(1), network_a.next_event()).await {
            match event {
                NetworkEvent::ReputationUpdated { peer, label, .. }
                    if peer == peer_b && label == "gossip_rate_limit" =>
                {
                    penalty_observed = true;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(penalty_observed, "gossip rate limit penalty missing");
}

#[test]
fn allowlist_initialises_peer_tiers() {
    let keypair = identity::Keypair::generate_ed25519();
    let peer = PeerId::from(keypair.public());
    let allowlist = vec![AllowlistedPeer {
        peer,
        tier: TierLevel::Tl3,
    }];

    let store =
        Peerstore::open(PeerstoreConfig::memory().with_allowlist(allowlist)).expect("peerstore");

    assert_eq!(store.tier_of(&peer), TierLevel::Tl3);
    assert!(store.reputation_of(&peer) >= 3.0);
}

#[test]
fn identity_metadata_controls_topic_thresholds() {
    let mut rng = OsRng;
    let vrf_secret_low = MiniSecretKey::generate_with(&mut rng);
    let vrf_secret_high = MiniSecretKey::generate_with(&mut rng);
    let low_public = vrf_secret_low
        .expand_to_keypair(ExpansionMode::Uniform)
        .public
        .to_bytes()
        .to_vec();
    let high_public = vrf_secret_high
        .expand_to_keypair(ExpansionMode::Uniform)
        .public
        .to_bytes()
        .to_vec();
    let verifier = Arc::new(StaticVerifier::new(vec![
        ("peer-low".to_string(), low_public.clone()),
        ("peer-high".to_string(), high_public.clone()),
    ]));
    let store = Arc::new(
        Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier))
            .expect("peerstore"),
    );

    let mut metadata = IdentityMetadata::default();
    metadata.set_topic_policy(
        GossipTopic::WitnessProofs,
        TopicPermission {
            subscribe: TierLevel::Tl0,
            publish: TierLevel::Tl2,
        },
    );
    let control = AdmissionControl::new(store.clone(), metadata);

    let low_keypair = identity::Keypair::generate_ed25519();
    let high_keypair = identity::Keypair::generate_ed25519();
    let peer_low = PeerId::from(low_keypair.public());
    let peer_high = PeerId::from(high_keypair.public());

    store
        .record_handshake(
            peer_low,
            &signed_handshake(&low_keypair, "peer-low", TierLevel::Tl1, &vrf_secret_low),
        )
        .expect("low handshake");
    store
        .record_handshake(
            peer_high,
            &signed_handshake(&high_keypair, "peer-high", TierLevel::Tl3, &vrf_secret_high),
        )
        .expect("high handshake");

    let low_publish = control.can_remote_publish(&peer_low, GossipTopic::WitnessProofs);
    assert!(
        matches!(low_publish, Err(AdmissionError::TierInsufficient { .. })),
        "low tier must be blocked"
    );

    let low_meta = control.can_remote_publish(&peer_low, GossipTopic::WitnessMeta);
    assert!(low_meta.is_ok(), "tier 1 should publish witness meta");

    let high_publish = control.can_remote_publish(&peer_high, GossipTopic::WitnessProofs);
    assert!(high_publish.is_ok(), "high tier should publish proofs");

    let high_votes = control.can_remote_publish(&peer_high, GossipTopic::Votes);
    assert!(high_votes.is_ok(), "tier 3 should publish votes");
}

#[test]
fn ban_after_slash_blocks_remote_access() {
    let mut rng = OsRng;
    let vrf_secret = MiniSecretKey::generate_with(&mut rng);
    let public = vrf_secret
        .expand_to_keypair(ExpansionMode::Uniform)
        .public
        .to_bytes()
        .to_vec();
    let verifier = Arc::new(StaticVerifier::new(vec![("peer".to_string(), public)]));
    let store = Arc::new(
        Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier))
            .expect("peerstore"),
    );
    let control = AdmissionControl::new(store.clone(), IdentityMetadata::default());

    let keypair = identity::Keypair::generate_ed25519();
    let peer = PeerId::from(keypair.public());

    store
        .record_handshake(
            peer,
            &signed_handshake(&keypair, "peer", TierLevel::Tl3, &vrf_secret),
        )
        .expect("handshake");

    let outcome = control
        .record_event(
            peer,
            ReputationEvent::Slash {
                severity: 2.0,
                reason: "double_sign".into(),
            },
        )
        .expect("slash applied");
    assert!(outcome.snapshot.banned_until.is_some());

    let publish = control.can_remote_publish(&peer, GossipTopic::Votes);
    match publish {
        Err(AdmissionError::Banned { until }) => {
            assert!(until > SystemTime::now());
        }
        other => panic!("expected ban, got {other:?}"),
    }
}

#[test]
fn reputation_broadcast_roundtrip_propagates_ban() {
    let mut rng = OsRng;
    let vrf_secret = MiniSecretKey::generate_with(&mut rng);
    let public = vrf_secret
        .expand_to_keypair(ExpansionMode::Uniform)
        .public
        .to_bytes()
        .to_vec();
    let verifier = Arc::new(StaticVerifier::new(vec![(
        "peer".to_string(),
        public.clone(),
    )]));
    let store_a = Arc::new(
        Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier.clone()))
            .expect("peerstore"),
    );
    let store_b = Arc::new(
        Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier))
            .expect("peerstore"),
    );
    let control_a = AdmissionControl::new(store_a.clone(), IdentityMetadata::default());
    let control_b = AdmissionControl::new(store_b.clone(), IdentityMetadata::default());

    let keypair = identity::Keypair::generate_ed25519();
    let peer = PeerId::from(keypair.public());
    let handshake = signed_handshake(&keypair, "peer", TierLevel::Tl3, &vrf_secret);

    store_a
        .record_handshake(peer, &handshake)
        .expect("handshake");
    store_b
        .record_handshake(peer, &handshake)
        .expect("handshake");

    let outcome = control_a
        .record_event(
            peer,
            ReputationEvent::Slash {
                severity: 1.5,
                reason: "double_sign".into(),
            },
        )
        .expect("slash applied");

    let broadcast = ReputationBroadcast::new(&outcome);
    let encoded = serde_json::to_string(&broadcast).expect("encode broadcast");
    let decoded: ReputationBroadcast = serde_json::from_str(&encoded).expect("decode broadcast");

    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("docs/interfaces/p2p/meta_reputation.jsonschema");
    let schema_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(schema_path).expect("schema"))
            .expect("schema json");
    let compiled = JSONSchema::compile(&schema_json).expect("compile schema");
    let payload_json: serde_json::Value = serde_json::from_str(&encoded).expect("payload json");
    assert!(compiled.is_valid(&payload_json), "broadcast schema invalid");

    let remote_outcome = control_b
        .record_event(peer, decoded.event.clone())
        .expect("apply broadcast event");
    assert_eq!(decoded.label, outcome.label);
    assert!(decoded.banned_until.is_some());
    assert!(remote_outcome.snapshot.banned_until.is_some());

    control_b
        .peerstore()
        .set_reputation(peer, decoded.reputation)
        .expect("set reputation");
    if let Some(until) = decoded.banned_until_time() {
        control_b
            .peerstore()
            .ban_peer_until(peer, until)
            .expect("ban update");
        let updated = control_b
            .peerstore()
            .reputation_snapshot(&peer)
            .expect("snapshot");
        assert_eq!(updated.banned_until, Some(until));
    }
}
