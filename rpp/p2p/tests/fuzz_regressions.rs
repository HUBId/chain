use rpp_chain::consensus::SignedBftVote;
use rpp_chain::types::Block;
use rpp_p2p::{
    sanitize_block_payload, sanitize_meta_payload, sanitize_vote_payload, GossipPayloadError,
};

const META_REPUTATION: &[u8] = include_bytes!("corpus/handle_meta/valid_reputation.json");
const BLOCK_INVALID_HASH: &[u8] = include_bytes!("corpus/handle_blocks/invalid_hash.json");
const VOTE_INVALID_SIGNATURE: &[u8] = include_bytes!("corpus/handle_votes/invalid_signature.json");

#[test]
fn meta_payload_sanitizer_accepts_reputation_broadcast() {
    assert!(sanitize_meta_payload(META_REPUTATION).is_ok());
}

#[test]
fn block_payload_sanitizer_detects_hash_mismatch() {
    let result = sanitize_block_payload::<Block>(BLOCK_INVALID_HASH);
    assert!(
        matches!(result, Err(GossipPayloadError::Validation(message)) if message.contains("block hash mismatch"))
    );
}

#[test]
fn vote_payload_sanitizer_rejects_invalid_signature() {
    let result = sanitize_vote_payload::<SignedBftVote>(VOTE_INVALID_SIGNATURE);
    assert!(
        matches!(result, Err(GossipPayloadError::Validation(message)) if message.contains("vote verification failed"))
    );
}
