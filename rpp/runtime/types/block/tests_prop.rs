use super::*;
use crate::errors::ChainError;
use proptest::prelude::*;
use proptest::string::string_regex;
use rpp_pruning::{
    BlockHeight, Commitment, Envelope as PruningEnvelope, ParameterVersion, ProofSegment,
    SchemaVersion, SegmentIndex, Snapshot, TaggedDigest, COMMITMENT_TAG, ENVELOPE_TAG,
    PROOF_SEGMENT_TAG, SNAPSHOT_STATE_TAG,
};
use std::convert::TryInto;

fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(32);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

prop_compose! {
    fn arb_hex_digest()(bytes in prop::array::uniform32(any::<u8>())) -> String {
        hex::encode(bytes)
    }
}

prop_compose! {
    fn arb_decimal_string()(value in 0u128..1_000_000_000_000u128) -> String {
        value.to_string()
    }
}

const TEST_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1);
const TEST_PARAMETER_VERSION: ParameterVersion = ParameterVersion::new(0);
const TEST_SEGMENT_INDEX: SegmentIndex = SegmentIndex::new(0);

fn decode_hex_digest(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value).expect("hex decode");
    bytes.as_slice().try_into().expect("32-byte digest")
}

fn fabricate_pruning_proof(
    height: u64,
    previous_hash: &str,
    previous_state: &str,
    pruned_tx: &str,
    resulting: &str,
) -> PruningProof {
    let snapshot = Snapshot::new(
        TEST_SCHEMA_VERSION,
        TEST_PARAMETER_VERSION,
        BlockHeight::new(height),
        TaggedDigest::new(SNAPSHOT_STATE_TAG, decode_hex_digest(previous_state)),
    )
    .expect("snapshot");
    let segment = ProofSegment::new(
        TEST_SCHEMA_VERSION,
        TEST_PARAMETER_VERSION,
        TEST_SEGMENT_INDEX,
        BlockHeight::new(height),
        BlockHeight::new(height),
        TaggedDigest::new(PROOF_SEGMENT_TAG, decode_hex_digest(pruned_tx)),
    )
    .expect("segment");
    let aggregate = super::compute_pruning_aggregate(
        height,
        &decode_hex_digest(previous_hash),
        snapshot.state_commitment().digest(),
        segment.segment_commitment().digest(),
    );
    let commitment = Commitment::new(TEST_SCHEMA_VERSION, TEST_PARAMETER_VERSION, aggregate)
        .expect("commitment");
    let binding = super::compute_pruning_binding(
        &commitment.aggregate_commitment(),
        &decode_hex_digest(resulting),
    );
    let envelope = PruningEnvelope::new(
        TEST_SCHEMA_VERSION,
        TEST_PARAMETER_VERSION,
        snapshot,
        vec![segment],
        commitment,
        binding,
    )
    .expect("envelope");
    envelope
}

fn tamper_previous_hash(proof: &PruningProof, header: &BlockHeader) -> PruningProof {
    let snapshot = proof.snapshot().clone();
    let segments: Vec<ProofSegment> = proof.segments().to_vec();
    let mut mutated_hash = decode_hex_digest(&header.previous_hash);
    mutated_hash[0] ^= 0xFF;
    let aggregate = super::compute_pruning_aggregate(
        snapshot.block_height().as_u64(),
        &mutated_hash,
        snapshot.state_commitment().digest(),
        segments[0].segment_commitment().digest(),
    );
    let commitment = Commitment::new(
        proof.schema_version(),
        proof.parameter_version(),
        aggregate,
    )
    .expect("tampered commitment");
    let binding = super::compute_pruning_binding(
        &commitment.aggregate_commitment(),
        &decode_hex_digest(&header.state_root),
    );
    let tampered = PruningEnvelope::new(
        proof.schema_version(),
        proof.parameter_version(),
        snapshot,
        segments,
        commitment,
        binding,
    )
    .expect("tampered envelope");
    tampered
}

prop_compose! {
    fn arb_pruning_fixture()(height in 0u64..1_000,
                             prev_hash in arb_hex_digest(),
                             prev_state in arb_hex_digest(),
                             pruned_tx in arb_hex_digest(),
                             resulting in arb_hex_digest(),
                             tx_root in arb_hex_digest(),
                             utxo_root in arb_hex_digest(),
                             reputation_root in arb_hex_digest(),
                             timetoke_root in arb_hex_digest(),
                             zsi_root in arb_hex_digest(),
                             proof_root in arb_hex_digest(),
                             total_stake in arb_decimal_string(),
                             randomness in arb_decimal_string(),
                             vrf_public_key in arb_hex_digest(),
                             vrf_preoutput in arb_hex_digest(),
                             vrf_proof in string_regex("[0-9a-f]{128}").unwrap(),
                             proposer in string_regex("0x[0-9a-f]{40}").unwrap(),
                             leader_tier in string_regex("TL[1-5]").unwrap(),
                             leader_timetoke in any::<u64>(),
                             timestamp in any::<u64>())
        -> (PruningProof, BlockHeader)
    {
        let proof = fabricate_pruning_proof(
            height,
            &prev_hash,
            &prev_state,
            &pruned_tx,
            &resulting,
        );
        let header = BlockHeader {
            height: height + 1,
            previous_hash: prev_hash,
            tx_root,
            state_root: resulting,
            utxo_root,
            reputation_root,
            timetoke_root,
            zsi_root,
            proof_root,
            total_stake,
            randomness,
            vrf_public_key,
            vrf_preoutput,
            vrf_proof,
            timestamp,
            proposer,
            leader_tier,
            leader_timetoke,
        };
        (proof, header)
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_roundtrip((proof, header) in arb_pruning_fixture()) {
        let json = serde_json::to_string(&proof).expect("serialize pruning proof");
        let decoded: PruningProof = serde_json::from_str(&json).expect("deserialize pruning proof");
        assert_eq!(decoded, proof);
        decoded.verify(None, &header).expect("valid pruning proof must verify");
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_detects_previous_hash_mismatch((proof, header) in arb_pruning_fixture()) {
        let tampered = tamper_previous_hash(&proof, &header);
        match tampered.verify(None, &header) {
            Err(ChainError::Crypto(message)) => {
                assert!(message.contains("commitment"));
            }
            other => panic!("unexpected verification result: {other:?}"),
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_metadata_roundtrip((proof, _) in arb_pruning_fixture()) {
        let metadata = proof.envelope_metadata();
        let reconstructed = pruning_from_metadata(metadata.clone())
            .expect("metadata should rebuild pruning proof");
        assert_eq!(reconstructed, proof);
        assert_eq!(metadata.binding_digest.as_str(), proof.binding_digest_hex());
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn parse_natural_accepts_decimals(value in arb_decimal_string()) {
        let parsed = parse_natural(&value).expect("decimal strings must parse");
        assert_eq!(parsed.to_string(), value);
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn parse_natural_rejects_invalid(text in string_regex("[a-f]{1,8}").unwrap()) {
        match parse_natural(&text) {
            Err(ChainError::Crypto(message)) => {
                assert!(message.contains("invalid natural encoding"));
            }
            other => panic!("unexpected parse result: {other:?}"),
        }
    }
}
