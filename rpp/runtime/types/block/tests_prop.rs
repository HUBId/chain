use super::*;
use crate::errors::ChainError;
use proptest::prelude::*;
use proptest::string::string_regex;
use rpp_pruning::{
    BlockHeight, Commitment, ParameterVersion, ProofSegment, SchemaVersion, SegmentIndex, Snapshot,
    TaggedDigest, COMMITMENT_TAG, ENVELOPE_TAG, PROOF_SEGMENT_TAG, SNAPSHOT_STATE_TAG,
};
use std::convert::TryInto;
use std::sync::Arc;

#[derive(Clone, Debug)]
struct PruningFixture {
    proof: PruningProof,
    header: BlockHeader,
    previous: Block,
}

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

const TEST_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1);
const TEST_PARAMETER_VERSION: ParameterVersion = ParameterVersion::new(0);
const TEST_SEGMENT_INDEX: SegmentIndex = SegmentIndex::new(0);

fn decode_hex_digest(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value).expect("hex decode");
    bytes.as_slice().try_into().expect("32-byte digest")
}

fn encode_hex_digest(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
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
    let commitment = Commitment::new(proof.schema_version(), proof.parameter_version(), aggregate)
        .expect("tampered commitment");
    let binding = super::compute_pruning_binding(
        &commitment.aggregate_commitment(),
        &decode_hex_digest(&header.state_root),
    );
    Arc::new(
        rpp_pruning::Envelope::new(
            proof.schema_version(),
            proof.parameter_version(),
            snapshot,
            segments,
            commitment,
            binding,
        )
        .expect("tampered envelope"),
    )
}

fn fabricate_previous_block(header: BlockHeader, pruning: &PruningProof) -> Block {
    let recursive_payload = dummy_proof(ProofKind::Recursive);
    let recursive_commitment = recursive_payload.commitment.clone();
    let recursive_chain_proof = ChainProof::Stwo(recursive_payload.clone());
    Block {
        header: header.clone(),
        identities: Vec::new(),
        transactions: Vec::new(),
        uptime_proofs: Vec::new(),
        timetoke_updates: Vec::new(),
        reputation_updates: Vec::new(),
        bft_votes: Vec::new(),
        module_witnesses: ModuleWitnessBundle {
            transactions: Vec::new(),
            timetoke: Vec::new(),
            reputation: Vec::new(),
            zsi: Vec::new(),
            consensus: Vec::new(),
        },
        proof_artifacts: Vec::new(),
        pruning_proof: Arc::clone(pruning),
        recursive_proof: RecursiveProof {
            system: ProofSystem::Stwo,
            commitment: recursive_commitment,
            previous_commitment: Some(RecursiveProof::anchor()),
            pruning_binding_digest: pruning.binding_digest().prefixed_bytes(),
            pruning_segment_commitments: pruning
                .segments()
                .iter()
                .map(|segment| segment.segment_commitment().prefixed_bytes())
                .collect(),
            proof: recursive_chain_proof.clone(),
        },
        stark: BlockProofBundle::new(
            Vec::new(),
            ChainProof::Stwo(dummy_proof(ProofKind::State)),
            ChainProof::Stwo(dummy_proof(ProofKind::Pruning)),
            ChainProof::Stwo(dummy_proof(ProofKind::Recursive)),
        ),
        signature: "00".repeat(64),
        consensus: ConsensusCertificate::genesis(),
        consensus_proof: None,
        hash: hex::encode(header.hash()),
        pruned: false,
    }
}

prop_compose! {
    fn arb_pruning_fixture()(height in 0u64..1_000,
                             prev_prev_hash_bytes in prop::array::uniform32(any::<u8>()),
                             prev_state_bytes in prop::array::uniform32(any::<u8>()),
                             segment_bytes in prop::array::uniform32(any::<u8>()),
                             resulting_state_bytes in prop::array::uniform32(any::<u8>()),
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
        -> PruningFixture
    {
        let previous_header = BlockHeader {
            height,
            previous_hash: encode_hex_digest(&prev_prev_hash_bytes),
            tx_root: encode_hex_digest(&segment_bytes),
            state_root: encode_hex_digest(&prev_state_bytes),
            utxo_root: utxo_root.clone(),
            reputation_root: reputation_root.clone(),
            timetoke_root: timetoke_root.clone(),
            zsi_root: zsi_root.clone(),
            proof_root: proof_root.clone(),
            total_stake: total_stake.clone(),
            randomness: randomness.clone(),
            vrf_public_key: vrf_public_key.clone(),
            vrf_preoutput: vrf_preoutput.clone(),
            vrf_proof: vrf_proof.clone(),
            timestamp,
            proposer: proposer.clone(),
            leader_tier: leader_tier.clone(),
            leader_timetoke,
        };
        let previous_block_hash = previous_header.hash();

        let snapshot = Snapshot::new(
            TEST_SCHEMA_VERSION,
            TEST_PARAMETER_VERSION,
            BlockHeight::new(height),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, prev_state_bytes),
        ).expect("snapshot");

        let segment = ProofSegment::new(
            TEST_SCHEMA_VERSION,
            TEST_PARAMETER_VERSION,
            TEST_SEGMENT_INDEX,
            BlockHeight::new(height),
            BlockHeight::new(height),
            TaggedDigest::new(PROOF_SEGMENT_TAG, segment_bytes),
        ).expect("segment");

        let aggregate = super::compute_pruning_aggregate(
            height,
            &previous_block_hash,
            snapshot.state_commitment().digest(),
            segment.segment_commitment().digest(),
        );
        let commitment = Commitment::new(TEST_SCHEMA_VERSION, TEST_PARAMETER_VERSION, aggregate)
            .expect("commitment");
        let binding = super::compute_pruning_binding(
            &commitment.aggregate_commitment(),
            &resulting_state_bytes,
        );

        let envelope = rpp_pruning::Envelope::new(
            TEST_SCHEMA_VERSION,
            TEST_PARAMETER_VERSION,
            snapshot,
            vec![segment],
            commitment,
            binding,
        ).expect("envelope");
        let proof = Arc::new(envelope);

        let previous = fabricate_previous_block(previous_header.clone(), &proof);

        let header = BlockHeader {
            height: height + 1,
            previous_hash: encode_hex_digest(&previous_block_hash),
            tx_root: previous_header.tx_root.clone(),
            state_root: encode_hex_digest(&resulting_state_bytes),
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
        PruningFixture {
            proof,
            header,
            previous,
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_roundtrip(fixture in arb_pruning_fixture()) {
        let proof = fixture.proof.clone();
        let header = fixture.header.clone();
        let previous = fixture.previous.clone();
        let json = serde_json::to_string(&proof).expect("serialize pruning proof");
        let decoded: PruningProof = serde_json::from_str(&json).expect("deserialize pruning proof");
        assert_eq!(decoded, proof);
        ValidatedPruningEnvelope::new(
            Arc::clone(&decoded),
            &header,
            Some(&previous),
        ).expect("valid pruning proof must verify");
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_detects_previous_hash_mismatch(fixture in arb_pruning_fixture()) {
        let tampered = tamper_previous_hash(&fixture.proof, &fixture.header);
        match ValidatedPruningEnvelope::new(tampered, &fixture.header, Some(&fixture.previous)) {
            Err(ChainError::Crypto(message)) => {
                assert!(message.contains("aggregate commitment"));
            }
            other => panic!("unexpected verification result: {other:?}"),
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_metadata_roundtrip(fixture in arb_pruning_fixture()) {
        let metadata = fixture.proof.envelope_metadata();
        let reconstructed = pruning_from_metadata(metadata.clone())
            .expect("metadata should rebuild pruning proof");
        assert_eq!(reconstructed, fixture.proof);
        let expected_schema_digest = hex::encode(fixture.proof.schema_version().canonical_digest());
        let expected_parameter_digest =
            hex::encode(fixture.proof.parameter_version().canonical_digest());
        let expected_binding = hex::encode(fixture.proof.binding_digest().prefixed_bytes());
        let json_a = serde_json::to_string(&metadata).expect("serialize metadata");
        let json_b = serde_json::to_string(&metadata).expect("serialize metadata");
        assert_eq!(json_a, json_b);
        assert_eq!(metadata.schema_digest, expected_schema_digest);
        assert_eq!(metadata.parameter_digest, expected_parameter_digest);
        assert_eq!(metadata.binding_digest.as_str(), expected_binding);
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn canonical_envelope_serialization_is_deterministic(fixture in arb_pruning_fixture()) {
        let canonical = CanonicalPruningEnvelope::from(fixture.proof.as_ref());
        let encoded_a = rpp_pruning::canonical_bincode_options()
            .serialize(&canonical)
            .expect("serialize canonical envelope");
        let encoded_b = rpp_pruning::canonical_bincode_options()
            .serialize(&canonical)
            .expect("serialize canonical envelope");
        assert_eq!(encoded_a, encoded_b);

        let decoded: CanonicalPruningEnvelope = rpp_pruning::canonical_bincode_options()
            .deserialize(&encoded_a)
            .expect("deserialize canonical envelope");
        let restored = decoded
            .into_envelope()
            .expect("canonical envelope converts");
        assert_eq!(Arc::new(restored), fixture.proof);
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_metadata_rejects_swapped_digests(fixture in arb_pruning_fixture()) {
        let mut metadata = fixture.proof.envelope_metadata();
        std::mem::swap(&mut metadata.schema_digest, &mut metadata.parameter_digest);
        match pruning_from_metadata(metadata) {
            Err(ChainError::Crypto(message)) => {
                assert!(message.contains("digest"));
            }
            other => panic!("unexpected result for swapped digests: {other:?}"),
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn canonical_envelope_rejects_swapped_digests(fixture in arb_pruning_fixture()) {
        let mut canonical = CanonicalPruningEnvelope::from(fixture.proof.as_ref());
        std::mem::swap(&mut canonical.schema_digest, &mut canonical.parameter_digest);
        match canonical.into_envelope() {
            Err(ChainError::Crypto(message)) => {
                assert!(message.contains("digest"));
            }
            other => panic!("unexpected result for swapped digests: {other:?}"),
        }
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
