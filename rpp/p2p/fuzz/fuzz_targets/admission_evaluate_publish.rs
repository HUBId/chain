#![no_main]

use std::sync::Arc;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use rpp_p2p::vendor::identity::{Keypair, PeerId};
use rpp_p2p::{AdmissionControl, GossipTopic, IdentityMetadata, Peerstore, PeerstoreConfig};

#[derive(Debug, Arbitrary)]
struct PublishInput {
    seed: Vec<u8>,
    topic: u8,
}

static METADATA: Lazy<IdentityMetadata> = Lazy::new(IdentityMetadata::default);

fn peer_id_from_seed(seed: &[u8]) -> Option<PeerId> {
    if seed.is_empty() {
        return None;
    }
    let mut key_bytes = [0u8; 64];
    for (idx, byte) in key_bytes.iter_mut().enumerate() {
        *byte = seed.get(idx).copied().unwrap_or(0);
    }
    Keypair::ed25519_from_bytes(&mut key_bytes)
        .map(|keypair| PeerId::from_public_key(&keypair.public()))
        .ok()
}

fn evaluate(seed: &[u8], topic_byte: u8) {
    let Some(peer) = peer_id_from_seed(seed) else {
        return;
    };
    let store =
        Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore initialisation"));
    let admission = AdmissionControl::new(store, METADATA.clone());
    let topics = GossipTopic::all();
    let topic = topics[(topic_byte as usize) % topics.len()];
    let _ = admission.sanitize_evaluate_publish(&peer, topic);
}

fuzz_target!(|input: PublishInput| {
    evaluate(&input.seed, input.topic);
});
