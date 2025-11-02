#![cfg(feature = "prover-stwo")]

use crate::errors::ChainError;
use crate::stwo::circuit::consensus::{ConsensusCircuit, ConsensusWitness, VotePower};
use rpp_crypto_vrf::VRF_PROOF_LENGTH;

fn sample_vote(weight: u64) -> VotePower {
    VotePower {
        voter: "validator-1".to_string(),
        weight,
    }
}

fn valid_witness() -> ConsensusWitness {
    let block_hash = "11".repeat(32);
    let quorum_bitmap_root = "22".repeat(32);
    let quorum_signature_root = "33".repeat(32);
    let vrf_output = "44".repeat(32);
    let witness_commitment = "55".repeat(32);
    let reputation_root = "66".repeat(32);

    let vrf_proof = hex::encode(vec![0x77; VRF_PROOF_LENGTH]);

    ConsensusWitness {
        block_hash: block_hash.clone(),
        round: 4,
        epoch: 7,
        slot: 9,
        leader_proposal: block_hash,
        quorum_threshold: 67,
        pre_votes: vec![sample_vote(80)],
        pre_commits: vec![sample_vote(80)],
        commit_votes: vec![sample_vote(80)],
        quorum_bitmap_root,
        quorum_signature_root,
        vrf_outputs: vec![vrf_output],
        vrf_proofs: vec![vrf_proof],
        witness_commitments: vec![witness_commitment],
        reputation_roots: vec![reputation_root],
    }
}

fn expect_err_message(error: ChainError, needle: &str) {
    let rendered = error.to_string();
    assert!(
        rendered.contains(needle),
        "expected error to mention '{needle}', got '{rendered}'",
    );
}

#[test]
fn consensus_witness_requires_vrf_metadata() {
    let mut witness = valid_witness();
    witness.vrf_outputs.clear();
    witness.vrf_proofs.clear();

    let circuit = ConsensusCircuit::new(witness);
    let err = circuit
        .evaluate_constraints()
        .expect_err("missing VRF metadata must fail");
    expect_err_message(err, "missing VRF outputs");
}

#[test]
fn consensus_witness_rejects_invalid_quorum_root() {
    let mut witness = valid_witness();
    witness.quorum_bitmap_root = "deadbeef".into();

    let circuit = ConsensusCircuit::new(witness);
    let err = circuit
        .evaluate_constraints()
        .expect_err("invalid quorum root must fail");
    expect_err_message(err, "quorum bitmap root");
}
