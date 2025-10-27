#![cfg(all(feature = "prover-stwo", nightly))]

use std::sync::Arc;

use anyhow::Result;
use blake2::digest::{consts::U32, generic_array::GenericArray};
use blake2::Blake2s256;
use hex::FromHex;
use prover_backend_interface::ProofBytes;
use prover_backend_interface::{
    PruningCircuitDef, RecursiveCircuitDef, StateCircuitDef, UptimeCircuitDef, WitnessBytes,
    WitnessHeader,
};
use prover_stwo_backend::backend::io::{
    decode_pruning_proof, decode_recursive_proof, decode_state_proof, decode_uptime_proof,
};
use prover_stwo_backend::backend::StwoBackend;
use prover_stwo_backend::official::aggregation::{
    RecursiveAggregator as OfficialRecursiveAggregator,
    StateCommitmentSnapshot as OfficialStateCommitmentSnapshot,
};
use prover_stwo_backend::official::circuit::pruning::PruningWitness;
use prover_stwo_backend::official::circuit::recursive::{PrefixedDigest, RecursiveWitness};
use prover_stwo_backend::official::circuit::state::StateWitness;
use prover_stwo_backend::official::circuit::uptime::UptimeWitness;
use prover_stwo_backend::official::proof::StarkProof;
use prover_stwo_backend::types::{Account, Stake, UptimeProof};
use prover_stwo_backend::utils::fri::compress_proof as compress_lightweight_fri;
use rpp_chain::proof_system::ProofVerifierRegistry;
use rpp_chain::reputation::{ReputationWeights, Tier};
use rpp_chain::stwo::aggregation::StateCommitmentSnapshot as ChainStateCommitmentSnapshot;
use rpp_chain::types::{BlockProofBundle, ChainProof};
use rpp_chain::utils::merkle::merkle_root;
use rpp_pruning::{
    BlockHeight, Commitment, Envelope, ParameterVersion, ProofSegment, SchemaVersion, SegmentIndex,
    Snapshot, TaggedDigest, COMMITMENT_TAG, DIGEST_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG,
    SNAPSHOT_STATE_TAG,
};

const MAX_PROOF_LEN: usize = 256 * 1024; // 256 KiB leaves plenty of headroom for nightly smoke tests.

#[test]
fn prove_and_verify_ok() -> Result<()> {
    let fixture = ProverFixture::new()?;

    assert!(fixture.state_bytes.as_slice().len() < MAX_PROOF_LEN);
    assert!(fixture.pruning_bytes.as_slice().len() < MAX_PROOF_LEN);
    assert!(fixture.uptime_bytes.as_slice().len() < MAX_PROOF_LEN);
    assert!(fixture.recursive_bytes.as_slice().len() < MAX_PROOF_LEN);

    let verifier = ProofVerifierRegistry::default();
    verifier.verify_block_bundle(
        &fixture.bundle,
        &[],
        &fixture.uptime_proofs,
        &[],
        fixture.pruning_envelope.as_ref(),
        &fixture.state_commitments,
        None,
    )?;

    Ok(())
}

#[test]
fn prove_repeatable() -> Result<()> {
    let first = ProverFixture::new()?;
    let second = ProverFixture::new()?;

    assert_eq!(first.state_bytes, second.state_bytes);
    assert_eq!(first.pruning_bytes, second.pruning_bytes);
    assert_eq!(first.uptime_bytes, second.uptime_bytes);
    assert_eq!(first.recursive_bytes, second.recursive_bytes);

    // Canonicalise via the lightweight FRI compressor so future changes can tighten equality if needed.
    let first_digest = digest_proof(&first.recursive_bytes);
    let second_digest = digest_proof(&second.recursive_bytes);
    assert_eq!(
        first_digest, second_digest,
        "canonical recursive digests must match"
    );

    Ok(())
}

fn digest_proof(bytes: &ProofBytes) -> [u8; 32] {
    let (_, proof) = decode_recursive_proof(bytes).expect("recursive proof decodes");
    compress_lightweight_fri(&proof.fri_proof)
}

#[derive(Clone)]
struct ProverFixture {
    state_bytes: ProofBytes,
    pruning_bytes: ProofBytes,
    uptime_bytes: ProofBytes,
    recursive_bytes: ProofBytes,
    bundle: BlockProofBundle,
    pruning_envelope: Arc<Envelope>,
    uptime_proofs: Vec<ChainProof>,
    state_commitments: ChainStateCommitmentSnapshot,
}

impl ProverFixture {
    fn new() -> Result<Self> {
        let backend = StwoBackend::new();

        let state_witness = sample_state_witness();
        let state_header =
            WitnessHeader::new(prover_backend_interface::ProofSystemKind::Stwo, "state");
        let state_bytes = WitnessBytes::encode(&state_header, &state_witness)?;
        let (state_pk, _) = backend.keygen_state(&StateCircuitDef::new("state"))?;
        let state_proof_bytes = backend.prove_state(&state_pk, &state_bytes)?;
        let state_stark = decode_state_proof(&state_proof_bytes)?;

        let pruning_witness = sample_pruning_witness();
        let pruning_header =
            WitnessHeader::new(prover_backend_interface::ProofSystemKind::Stwo, "pruning");
        let pruning_bytes = WitnessBytes::encode(&pruning_header, &pruning_witness)?;
        let (pruning_pk, _) = backend.keygen_pruning(&PruningCircuitDef::new("pruning"))?;
        let pruning_proof_bytes = backend.prove_pruning(&pruning_pk, &pruning_bytes)?;
        let pruning_stark = decode_pruning_proof(&pruning_proof_bytes)?;
        let pruning_envelope = sample_pruning_envelope();

        let uptime_witness = sample_uptime_witness();
        let uptime_header =
            WitnessHeader::new(prover_backend_interface::ProofSystemKind::Stwo, "uptime");
        let uptime_bytes = WitnessBytes::encode(&uptime_header, &uptime_witness)?;
        let (uptime_pk, _) = backend.keygen_uptime(&UptimeCircuitDef::new("uptime"))?;
        let uptime_proof_bytes = backend.prove_uptime(&uptime_pk, &uptime_bytes)?;
        let uptime_stark = decode_uptime_proof(&uptime_proof_bytes)?;

        let state_commitments = sample_state_commitments();
        let recursive_witness = sample_recursive_witness(
            &state_commitments,
            &state_stark,
            &pruning_stark,
            &pruning_envelope,
            &[uptime_stark.commitment.clone()],
            7,
        );
        let recursive_header =
            WitnessHeader::new(prover_backend_interface::ProofSystemKind::Stwo, "recursive");
        let recursive_bytes = WitnessBytes::encode(&recursive_header, &recursive_witness)?;
        let (recursive_pk, _) = backend.keygen_recursive(&RecursiveCircuitDef::new("recursive"))?;
        let recursive_proof_bytes = backend.prove_recursive(&recursive_pk, &recursive_bytes)?;
        let recursive_stark = decode_recursive_proof(&recursive_proof_bytes)?;

        let uptime_chain_proof = ChainProof::Stwo(uptime_stark.clone());
        let bundle = BlockProofBundle::new(
            Vec::new(),
            ChainProof::Stwo(state_stark.clone()),
            ChainProof::Stwo(pruning_stark.clone()),
            ChainProof::Stwo(recursive_stark.clone()),
        );

        Ok(Self {
            state_bytes: state_proof_bytes,
            pruning_bytes: pruning_proof_bytes,
            uptime_bytes: uptime_proof_bytes,
            recursive_bytes: recursive_proof_bytes,
            bundle,
            pruning_envelope: Arc::new(pruning_envelope),
            uptime_proofs: vec![uptime_chain_proof],
            state_commitments: to_chain_snapshot(&state_commitments),
        })
    }
}

fn sample_state_witness() -> StateWitness {
    let mut before = vec![Account::new(
        hex::encode([0x24u8; 32]),
        1_000,
        Stake::default(),
    )];
    before[0].reputation.zsi.validated = true;
    let after = before.clone();

    let prev_state_root = state_root_for(&before);
    let new_state_root = state_root_for(&after);

    StateWitness {
        prev_state_root,
        new_state_root,
        identities: Vec::new(),
        transactions: Vec::new(),
        accounts_before: before,
        accounts_after: after,
        required_tier: Tier::Tl0,
        reputation_weights: ReputationWeights::default(),
    }
}

fn sample_pruning_witness() -> PruningWitness {
    let original = vec![hex::encode([0x42u8; 32]), hex::encode([0x52u8; 32])];
    let removed = vec![original[0].clone()];
    let previous_tx_root = merkle_root_from_hex(&original);
    let pruned_tx_root = merkle_root_from_hex(&original[1..].to_vec());

    PruningWitness {
        previous_tx_root,
        pruned_tx_root,
        original_transactions: original,
        removed_transactions: removed,
    }
}

fn sample_uptime_witness() -> UptimeWitness {
    let wallet_address = hex::encode([0x77u8; 32]);
    let window_start = 10;
    let window_end = 20;
    let commitment_bytes = UptimeProof::commitment_bytes(&wallet_address, window_start, window_end);

    UptimeWitness {
        wallet_address,
        node_clock: 42,
        epoch: 3,
        head_hash: hex::encode([0x88u8; 32]),
        window_start,
        window_end,
        commitment: hex::encode(commitment_bytes),
    }
}

fn sample_pruning_envelope() -> Envelope {
    let schema = SchemaVersion::new(1);
    let params = ParameterVersion::new(1);
    let snapshot = Snapshot::new(
        schema,
        params,
        BlockHeight::new(1),
        TaggedDigest::new(SNAPSHOT_STATE_TAG, [0x91; DIGEST_LENGTH]).expect("snapshot"),
    )
    .expect("snapshot");
    let segment = ProofSegment::new(
        schema,
        params,
        SegmentIndex::new(0),
        BlockHeight::new(1),
        BlockHeight::new(2),
        TaggedDigest::new(PROOF_SEGMENT_TAG, [0x92; DIGEST_LENGTH]).expect("segment"),
    )
    .expect("segment");
    let commitment = Commitment::new(
        schema,
        params,
        TaggedDigest::new(COMMITMENT_TAG, [0x93; DIGEST_LENGTH]).expect("commitment"),
    )
    .expect("commitment");
    let envelope = Envelope::new(
        schema,
        params,
        snapshot,
        vec![segment],
        commitment,
        TaggedDigest::new(ENVELOPE_TAG, [0x94; DIGEST_LENGTH]).expect("binding"),
    )
    .expect("envelope");
    envelope
}

fn sample_state_commitments() -> OfficialStateCommitmentSnapshot {
    OfficialStateCommitmentSnapshot::from_header_fields(
        hex::encode([0x11u8; 32]),
        hex::encode([0x22u8; 32]),
        hex::encode([0x33u8; 32]),
        hex::encode([0x44u8; 32]),
        hex::encode([0x55u8; 32]),
        hex::encode([0x66u8; 32]),
    )
}

#[allow(clippy::too_many_arguments)]
fn sample_recursive_witness(
    state_commitments: &OfficialStateCommitmentSnapshot,
    state_proof: &StarkProof,
    pruning_proof: &StarkProof,
    pruning_envelope: &Envelope,
    uptime_commitments: &[String],
    block_height: u64,
) -> RecursiveWitness {
    let pruning_binding_digest = pruning_envelope.binding_digest().prefixed_bytes();
    let expected_segments: Vec<PrefixedDigest> = pruning_envelope
        .segments()
        .iter()
        .map(|segment| segment.segment_commitment().prefixed_bytes())
        .collect();
    let pruning_segment_commitments = expected_segments.clone();
    let aggregator = OfficialRecursiveAggregator::with_blueprint();
    let aggregated = aggregator.aggregate_commitment(
        None,
        &[],
        &[],
        uptime_commitments,
        &[],
        &state_proof.commitment,
        state_commitments,
        &pruning_binding_digest,
        block_height,
    );

    assert_eq!(
        pruning_binding_digest,
        pruning_envelope.binding_digest().prefixed_bytes()
    );
    assert_eq!(pruning_segment_commitments, expected_segments);

    RecursiveWitness {
        previous_commitment: None,
        aggregated_commitment: aggregated.to_hex(),
        identity_commitments: Vec::new(),
        tx_commitments: Vec::new(),
        uptime_commitments: uptime_commitments.to_vec(),
        consensus_commitments: Vec::new(),
        state_commitment: state_proof.commitment.clone(),
        global_state_root: state_commitments.global_state_root.clone(),
        utxo_root: state_commitments.utxo_root.clone(),
        reputation_root: state_commitments.reputation_root.clone(),
        timetoke_root: state_commitments.timetoke_root.clone(),
        zsi_root: state_commitments.zsi_root.clone(),
        proof_root: state_commitments.proof_root.clone(),
        pruning_binding_digest,
        pruning_segment_commitments,
        block_height,
    }
}

fn to_chain_snapshot(snapshot: &OfficialStateCommitmentSnapshot) -> ChainStateCommitmentSnapshot {
    ChainStateCommitmentSnapshot::from_header_fields(
        snapshot.global_state_root.clone(),
        snapshot.utxo_root.clone(),
        snapshot.reputation_root.clone(),
        snapshot.timetoke_root.clone(),
        snapshot.zsi_root.clone(),
        snapshot.proof_root.clone(),
    )
}

fn state_root_for(accounts: &[Account]) -> String {
    let mut sorted = accounts.to_vec();
    sorted.sort_by(|a, b| a.address.cmp(&b.address));
    let mut leaves: Vec<[u8; 32]> = sorted
        .iter()
        .map(|account| {
            let bytes = serde_json::to_vec(account).expect("account serialises");
            blake2s_hash(&bytes)
        })
        .collect();
    hex::encode(merkle_root(&mut leaves))
}

fn merkle_root_from_hex(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return hex::encode(merkle_root(&mut Vec::new()));
    }
    let mut leaves: Vec<[u8; 32]> = hashes
        .iter()
        .map(|hash| <[u8; 32]>::from_hex(hash).expect("hex leaf").into())
        .collect();
    hex::encode(merkle_root(&mut leaves))
}

fn blake2s_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(bytes);
    let output: GenericArray<u8, U32> = hasher.finalize();
    output.into()
}
