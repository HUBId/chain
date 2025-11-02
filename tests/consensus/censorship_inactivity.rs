use std::collections::BTreeMap;
use std::sync::Arc;

#[path = "common.rs"]
mod common;

use common::{digest, metadata_fixture, vrf_entry};
use libp2p::PeerId;
use rpp_consensus::evidence::{CensorshipStage, EvidenceKind, EvidenceType};
use rpp_consensus::messages::{
    compute_consensus_bindings, Block, BlockId, Commit, ConsensusCertificate, ConsensusProof,
    ConsensusProofMetadata, PreVote,
};
use rpp_consensus::proof_backend::{
    BackendError, BackendResult, ConsensusCircuitDef, ConsensusPublicInputs, ProofBackend,
    ProofBytes, VerifyingKey,
};
use rpp_consensus::state::{ConsensusConfig, ConsensusState, GenesisConfig};
use rpp_consensus::validator::{VRFOutput, ValidatorLedgerEntry};
use serde_json::json;

fn sample_metadata(epoch: u64, slot: u64) -> ConsensusProofMetadata {
    metadata_fixture(
        vec![vrf_entry(0x11, 0x22)],
        vec![digest(0x33)],
        vec![digest(0x44)],
        epoch,
        slot,
        digest(0x55),
        digest(0x66),
    )
}

fn decode_digest(hex_value: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hex::decode(hex_value).expect("decode digest"));
    bytes
}

#[derive(Default)]
struct FixtureBackend;

impl ProofBackend for FixtureBackend {
    fn name(&self) -> &'static str {
        "censorship-fixture"
    }

    fn verify_consensus(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        circuit: &ConsensusCircuitDef,
        _public_inputs: &ConsensusPublicInputs,
    ) -> BackendResult<()> {
        if vk.as_slice().is_empty() || proof.as_slice().is_empty() {
            return Err(BackendError::Failure("empty consensus artifacts".into()));
        }
        if circuit.identifier.trim().is_empty() {
            return Err(BackendError::Failure("empty circuit identifier".into()));
        }
        Ok(())
    }

    fn prove_consensus(
        &self,
        witness: &prover_backend_interface::WitnessBytes,
    ) -> BackendResult<(ProofBytes, VerifyingKey, ConsensusCircuitDef)> {
        let digest = blake3::hash(witness.as_slice());
        let identifier = format!("censorship.consensus.{}", digest.to_hex());
        let circuit = ConsensusCircuitDef::new(identifier.clone());
        let header = prover_backend_interface::ProofHeader::new(
            prover_backend_interface::ProofSystemKind::Mock,
            identifier.clone(),
        );
        let proof = ProofBytes::encode(&header, witness.as_slice())?;
        let verifying_key = VerifyingKey(identifier.into_bytes());
        Ok((proof, verifying_key, circuit))
    }
}

fn consensus_backend() -> Arc<dyn ProofBackend> {
    Arc::new(FixtureBackend::default())
}

fn sample_vrf_output(id: &str, output_byte: u8, tier: u8, score: f64, timetoken: u64) -> VRFOutput {
    VRFOutput {
        validator_id: id.to_string(),
        output: [output_byte; 32],
        preoutput: vec![output_byte; 32],
        proof: vec![output_byte; 32],
        reputation_tier: tier,
        reputation_score: score,
        timetoken_balance: timetoken,
        seed: [output_byte; 32],
        public_key: format!("pk-{id}").into_bytes(),
    }
}

fn build_ledger(entries: &[(&str, u64, u8, f64)]) -> BTreeMap<String, ValidatorLedgerEntry> {
    entries
        .iter()
        .map(|(id, stake, tier, score)| {
            (
                (*id).to_string(),
                ValidatorLedgerEntry {
                    stake: *stake,
                    reputation_tier: *tier,
                    reputation_score: *score,
                },
            )
        })
        .collect()
}

fn build_state(
    vote_threshold: u64,
    proof_threshold: u64,
    inactivity_threshold: u64,
) -> ConsensusState {
    let vrf_outputs = vec![
        sample_vrf_output("validator-a", 1, 4, 1.0, 10),
        sample_vrf_output("validator-b", 2, 3, 0.8, 8),
    ];
    let ledger = build_ledger(&[("validator-a", 10, 4, 1.0), ("validator-b", 8, 3, 0.8)]);
    let config = ConsensusConfig::new(40, 40, 10, 0.1)
        .with_witness_params(4, 3, 2)
        .with_participation_thresholds(vote_threshold, proof_threshold, inactivity_threshold);
    let genesis = GenesisConfig::new(0, vrf_outputs, ledger, "root".into(), config);
    ConsensusState::new(genesis, consensus_backend()).expect("consensus state")
}

fn dummy_commit(state: &ConsensusState, height: u64) -> Commit {
    let block = Block {
        height,
        epoch: state.epoch,
        payload: json!({"height": height}),
        timestamp: 0,
    };
    let block_hash = block.hash();
    let metadata = sample_metadata(state.epoch, state.round);
    let certificate =
        state.build_certificate(&block_hash.0, block.height, state.round, metadata.clone());
    let block_hash_bytes = decode_digest(&block_hash.0);
    let quorum_bitmap_root = decode_digest(&metadata.quorum_bitmap_root);
    let quorum_signature_root = decode_digest(&metadata.quorum_signature_root);
    let (vrf_outputs, vrf_proofs): (Vec<[u8; 32]>, Vec<Vec<u8>>) = metadata
        .vrf_entries
        .iter()
        .map(|entry| {
            (
                decode_digest(&entry.randomness),
                hex::decode(&entry.proof).expect("decode vrf proof"),
            )
        })
        .unzip();
    let witness_commitments: Vec<[u8; 32]> = metadata
        .witness_commitments
        .iter()
        .map(|value| decode_digest(value))
        .collect();
    let reputation_roots: Vec<[u8; 32]> = metadata
        .reputation_roots
        .iter()
        .map(|value| decode_digest(value))
        .collect();

    let bindings = compute_consensus_bindings(
        &block_hash_bytes,
        &vrf_outputs,
        &vrf_proofs,
        &witness_commitments,
        &reputation_roots,
        &quorum_bitmap_root,
        &quorum_signature_root,
    );

    let proof = ConsensusProof::new(
        ProofBytes::new(vec![1, 2, 3]),
        VerifyingKey(vec![1, 2, 3]),
        ConsensusCircuitDef::new("consensus-fixture"),
        ConsensusPublicInputs {
            block_hash: block_hash_bytes,
            round: state.round,
            leader_proposal: block_hash_bytes,
            epoch: metadata.epoch,
            slot: metadata.slot,
            quorum_threshold: state.validator_set.quorum_threshold,
            quorum_bitmap_root,
            quorum_signature_root,
            vrf_outputs,
            vrf_proofs,
            witness_commitments,
            reputation_roots,
            vrf_output_binding: bindings.vrf_output,
            vrf_proof_binding: bindings.vrf_proof,
            witness_commitment_binding: bindings.witness_commitment,
            reputation_root_binding: bindings.reputation_root,
            quorum_bitmap_binding: bindings.quorum_bitmap,
            quorum_signature_binding: bindings.quorum_signature,
        },
    );
    Commit {
        block,
        proof,
        certificate,
        signatures: Vec::new(),
    }
}

fn record_prevote_for(state: &mut ConsensusState, validator: &str) {
    let vote = PreVote {
        block_hash: BlockId("block-0".into()),
        proof_valid: true,
        validator_id: validator.to_string(),
        peer_id: PeerId::random(),
        signature: vec![1, 2, 3],
        height: state.block_height,
        round: state.round,
    };
    let outcome = state.record_prevote(vote);
    assert!(matches!(
        outcome,
        rpp_consensus::state::VoteRecordOutcome::Counted { .. }
    ));
}

#[test]
fn vote_and_inactivity_detection_emits_evidence_and_penalties() {
    let mut state = build_state(1, 0, 2);
    let leader_id = state.current_leader.as_ref().expect("leader").id.clone();
    let victim_id = state
        .validator_set
        .validators
        .iter()
        .find(|validator| validator.id != leader_id)
        .expect("secondary validator")
        .id
        .clone();

    // Round 0: leader participates, victim abstains.
    record_prevote_for(&mut state, &leader_id);
    state.next_round();

    let has_censorship = state.pending_evidence.iter().any(|record| {
        record.accused == victim_id
            && matches!(
                record.evidence,
                EvidenceType::Censorship {
                    stage: CensorshipStage::Prevote,
                    ..
                }
            )
    });
    assert!(has_censorship, "expected censorship evidence for victim");

    let triggers = state.take_slashing_triggers();
    assert!(triggers.iter().any(|trigger| trigger.validator == victim_id
        && trigger.reason.starts_with("consensus_censorship")));

    // Round 1: leader continues participation, victim remains absent to trigger inactivity.
    record_prevote_for(&mut state, &leader_id);
    state.next_round();

    let has_inactivity = state.pending_evidence.iter().any(|record| {
        record.accused == victim_id && matches!(record.evidence, EvidenceType::Inactivity { .. })
    });
    assert!(has_inactivity, "expected inactivity evidence for victim");

    let inactivity_triggers = state.take_slashing_triggers();
    assert!(inactivity_triggers
        .iter()
        .any(|trigger| trigger.validator == victim_id && trigger.reason == "consensus_inactivity"));

    // Apply commit to materialise reward penalties.
    let commit = dummy_commit(&state, state.block_height + 1);
    state.apply_commit(commit);
    let rewards = state
        .pending_rewards
        .last()
        .expect("pending rewards after commit");
    let penalty = rewards
        .penalties
        .get(&victim_id)
        .copied()
        .unwrap_or_default();
    assert!(penalty > 0, "expected withheld validator rewards");
    assert_eq!(
        rewards.rewards.get(&victim_id).copied().unwrap_or_default(),
        0
    );
}

#[test]
fn proof_censorship_detection_flags_leader() {
    let mut state = build_state(0, 1, 0);
    let leader_id = state.current_leader.as_ref().expect("leader").id.clone();

    state.next_round();

    let proof_censorship = state
        .pending_evidence
        .iter()
        .find(|record| {
            record.accused == leader_id
                && matches!(
                    record.evidence,
                    EvidenceType::Censorship {
                        stage: CensorshipStage::Proof,
                        ..
                    }
                )
        })
        .expect("leader proof censorship evidence");
    assert_eq!(proof_censorship.evidence.kind(), EvidenceKind::Censorship);

    let triggers = state.take_slashing_triggers();
    assert!(triggers.iter().any(|trigger| trigger.validator == leader_id
        && trigger.reason.starts_with("consensus_censorship_proof")));
}
