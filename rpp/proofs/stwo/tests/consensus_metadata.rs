#![cfg(feature = "prover-stwo")]

use crate::errors::ChainError;
use crate::stwo::circuit::consensus::{
    ConsensusCircuit, ConsensusVrfPoseidonInput, ConsensusVrfWitnessEntry, ConsensusWitness,
    VotePower,
};
use rpp_crypto_vrf::{generate_vrf, PoseidonVrfInput, VrfSecretKey};
use std::convert::{TryFrom, TryInto};

const TEST_SECRET_KEY_BYTES: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

fn test_secret_key() -> VrfSecretKey {
    VrfSecretKey::try_from(TEST_SECRET_KEY_BYTES).expect("valid VRF secret key")
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    let bytes = hex::decode(value).expect("decode hex");
    let array: [u8; N] = bytes.as_slice().try_into().expect("hex length");
    array
}

fn build_vrf_entry(block_hash: &str, epoch: u64, tier_seed_byte: u8) -> ConsensusVrfWitnessEntry {
    let tier_seed_bytes = vec![tier_seed_byte; 32];
    let tier_seed_hex = hex::encode(&tier_seed_bytes);
    let input = PoseidonVrfInput::new(
        decode_hex::<32>(block_hash),
        epoch,
        decode_hex::<32>(&tier_seed_hex),
    );
    let secret = test_secret_key();
    let output = generate_vrf(&input, &secret).expect("generate vrf output");
    let public_key = secret.derive_public();

    ConsensusVrfWitnessEntry {
        randomness: hex::encode(output.randomness),
        pre_output: hex::encode(output.preoutput),
        proof: hex::encode(output.proof),
        public_key: hex::encode(public_key.to_bytes()),
        input: ConsensusVrfPoseidonInput {
            last_block_header: block_hash.to_string(),
            epoch,
            tier_seed: tier_seed_hex,
        },
    }
}

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

    let vrf_entry = build_vrf_entry(&block_hash, 7, 0xAA);

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

#[test]
fn consensus_witness_rejects_invalid_randomness_hex() {
    let mut witness = valid_witness();
    witness.vrf_entries[0].randomness = "zz".into();

    let circuit = ConsensusCircuit::new(witness);
    let err = circuit
        .evaluate_constraints()
        .expect_err("invalid randomness hex must fail");
    expect_err_message(err, "randomness encoding");
}

#[test]
fn consensus_witness_rejects_malformed_proof() {
    let mut witness = valid_witness();
    witness.vrf_entries[0].proof = "00".repeat(rpp_crypto_vrf::VRF_PROOF_LENGTH);

    let circuit = ConsensusCircuit::new(witness);
    let err = circuit
        .evaluate_constraints()
        .expect_err("malformed proof must fail");
    expect_err_message(err, "proof is invalid");
}

#[test]
fn consensus_witness_rejects_randomness_mismatch() {
    let mut witness = valid_witness();
    let mut randomness_bytes = hex::decode(&witness.vrf_entries[0].randomness).unwrap();
    randomness_bytes[0] ^= 0xFF;
    witness.vrf_entries[0].randomness = hex::encode(randomness_bytes);

    let circuit = ConsensusCircuit::new(witness);
    let err = circuit
        .evaluate_constraints()
        .expect_err("randomness mismatch must fail");
    expect_err_message(err, "randomness mismatch");
}

#[test]
fn consensus_witness_rejects_missing_public_key() {
    let mut witness = valid_witness();
    witness.vrf_entries[0].public_key.clear();

    let circuit = ConsensusCircuit::new(witness);
    let err = circuit
        .evaluate_constraints()
        .expect_err("missing public key must fail");
    expect_err_message(err, "public key");
}
