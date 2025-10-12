use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use libp2p::identity;
use libp2p::PeerId;
use rand::rngs::OsRng;
use rpp_p2p::{
    AdmissionControl, AdmissionError, GossipTopic, HandshakePayload, IdentityMetadata,
    IdentityVerifier, Peerstore, PeerstoreConfig, ReputationEvent, TierLevel, TopicPermission,
    VRF_HANDSHAKE_CONTEXT,
};
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};

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
        GossipTopic::Proofs,
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

    let low_publish = control.can_remote_publish(&peer_low, GossipTopic::Proofs);
    assert!(
        matches!(low_publish, Err(AdmissionError::TierInsufficient { .. })),
        "low tier must be blocked"
    );

    let high_publish = control.can_remote_publish(&peer_high, GossipTopic::Proofs);
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
                reason: "double_sign",
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
