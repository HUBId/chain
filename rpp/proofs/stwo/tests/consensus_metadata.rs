#![cfg(feature = "prover-stwo")]

use crate::errors::ChainError;
use crate::stwo::circuit::consensus::{
    ConsensusCircuit, ConsensusVrfPoseidonInput, ConsensusVrfWitnessEntry, ConsensusWitness,
    VotePower,
};
use rpp_crypto_vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};

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
    let witness_commitment = "55".repeat(32);
    let reputation_root = "66".repeat(32);

    let vrf_proof = hex::encode(vec![0x77; VRF_PROOF_LENGTH]);
    let vrf_entry = ConsensusVrfWitnessEntry {
        randomness: "44".repeat(32),
        pre_output: "88".repeat(VRF_PREOUTPUT_LENGTH),
        proof: vrf_proof,
        public_key: "99".repeat(32),
        input: ConsensusVrfPoseidonInput {
            last_block_header: block_hash.clone(),
            epoch: 7,
            tier_seed: "aa".repeat(32),
        },
    };

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
        vrf_entries: vec![vrf_entry],
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
    witness.vrf_entries.clear();

    let circuit = ConsensusCircuit::new(witness);
    let err = circuit
        .evaluate_constraints()
        .expect_err("missing VRF metadata must fail");
    expect_err_message(err, "missing VRF entries");
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

#[test]
fn consensus_witness_rejects_poseidon_header_mismatch() {
    let mut witness = valid_witness();
    witness.vrf_entries[0].input.last_block_header = "de".repeat(32);

    let circuit = ConsensusCircuit::new(witness);
    let err = circuit
        .evaluate_constraints()
        .expect_err("poseidon header mismatch must fail");
    expect_err_message(err, "poseidon last block header");
}

#[test]
fn consensus_witness_rejects_poseidon_epoch_mismatch() {
    let mut witness = valid_witness();
    witness.vrf_entries[0].input.epoch += 1;

    let circuit = ConsensusCircuit::new(witness);
    let err = circuit
        .evaluate_constraints()
        .expect_err("poseidon epoch mismatch must fail");
    expect_err_message(err, "poseidon epoch");
}
