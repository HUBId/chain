use std::sync::Arc;

use rand::rngs::OsRng;
use rpp_p2p::admission::{AdmissionControl, AdmissionError};
use rpp_p2p::handshake::{HandshakeOutcome, HandshakePayload, VRF_HANDSHAKE_CONTEXT};
use rpp_p2p::peerstore::{AllowlistedPeer, Peerstore, PeerstoreConfig, PeerstoreError};
use rpp_p2p::tier::TierLevel;
use rpp_p2p::topics::GossipTopic;
use rpp_p2p::vendor::identity;
use rpp_p2p::vendor::PeerId;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};

#[test]
fn handshake_rejects_allowlist_downgrade() {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let allowlist = vec![AllowlistedPeer {
        peer: peer_id,
        tier: TierLevel::Tl3,
    }];
    let store = Peerstore::open(PeerstoreConfig::memory().with_allowlist(allowlist))
        .expect("open peerstore");
    store
        .record_public_key(peer_id, keypair.public())
        .expect("record public key");
    let payload = HandshakePayload::new("peer", None, None, TierLevel::Tl0)
        .signed(&keypair)
        .expect("sign handshake");

    match store.record_handshake(peer_id, &payload) {
        Err(PeerstoreError::TierBelowAllowlist {
            required,
            actual,
            ..
        }) => {
            assert_eq!(required, TierLevel::Tl3);
            assert_eq!(actual, TierLevel::Tl0);
        }
        other => panic!("unexpected handshake result: {other:?}"),
    }
}

#[test]
fn gossip_publish_rejected_for_low_tier() {
    let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("open"));
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    peerstore
        .record_public_key(peer_id, keypair.public())
        .expect("record public key");

    let mut rng = OsRng;
    let secret = MiniSecretKey::generate_with(&mut rng);
    let payload = signed_handshake_with_vrf(&keypair, TierLevel::Tl2, &secret);
    let outcome = peerstore
        .record_handshake(peer_id, &payload)
        .expect("handshake accepted");
    assert!(matches!(
        outcome,
        HandshakeOutcome::Accepted {
            tier: TierLevel::Tl2,
            ..
        }
    ));

    let admission = AdmissionControl::new(peerstore.clone(), Default::default());
    match admission.can_remote_publish(&peer_id, GossipTopic::Votes) {
        Err(AdmissionError::TierInsufficient { required, actual }) => {
            assert_eq!(required, TierLevel::Tl3);
            assert_eq!(actual, TierLevel::Tl2);
        }
        other => panic!("unexpected admission result: {other:?}"),
    }
}

fn signed_handshake_with_vrf(
    keypair: &identity::Keypair,
    tier: TierLevel,
    secret: &MiniSecretKey,
) -> HandshakePayload {
    let public = secret
        .expand_to_keypair(ExpansionMode::Uniform)
        .public
        .to_bytes()
        .to_vec();
    let template = HandshakePayload::new("peer", Some(public.clone()), None, tier);
    let proof = sign_vrf_message(secret, &template);
    let template = HandshakePayload::new("peer", Some(public), Some(proof), tier);
    template.signed(keypair).expect("sign handshake")
}

fn sign_vrf_message(secret: &MiniSecretKey, payload: &HandshakePayload) -> Vec<u8> {
    let keypair = secret.expand_to_keypair(ExpansionMode::Uniform);
    keypair
        .sign_simple(VRF_HANDSHAKE_CONTEXT, &payload.vrf_message())
        .to_bytes()
        .to_vec()
}
