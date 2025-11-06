#[path = "consensus/common.rs"]
mod common;

use common::{align_poseidon_last_block_header, digest, metadata_fixture, vrf_entry};
use libp2p::PeerId;
use rpp_chain::consensus::{ConsensusCertificate, ConsensusProofMetadata};
use rpp_chain::consensus_engine::messages::{BlockId, TalliedVote};
use rpp_chain::plonky3::crypto;
use rpp_chain::plonky3::experimental::force_enable_for_tests;
use rpp_chain::plonky3::proof::Plonky3Proof;
use rpp_chain::plonky3::prover::Plonky3Prover;
use rpp_chain::plonky3::verifier::Plonky3Verifier;
use rpp_chain::proof_system::{ProofProver, ProofVerifier};
use rpp_chain::types::ChainProof;
use serde_json::Value;

fn sample_vote(validator: &str, voting_power: u64) -> TalliedVote {
    TalliedVote {
        validator_id: validator.to_string(),
        peer_id: PeerId::random(),
        signature: vec![0xAA, 0xBB],
        voting_power,
    }
}

fn sample_metadata() -> ConsensusProofMetadata {
    let epoch = 11;
    metadata_fixture(
        vec![vrf_entry(0x10, 0x20, epoch)],
        vec![digest(0x33)],
        vec![digest(0x44)],
        epoch,
        9,
        digest(0x55),
        digest(0x66),
    )
}

fn sample_certificate() -> ConsensusCertificate {
    let vote = sample_vote("validator-1", 10);
    let block_hash = BlockId("88".repeat(32));
    let mut metadata = sample_metadata();
    align_poseidon_last_block_header(&mut metadata, &block_hash.0);

    ConsensusCertificate {
        block_hash,
        height: 5,
        round: 3,
        total_power: 10,
        quorum_threshold: 6,
        prevote_power: 10,
        precommit_power: 10,
        commit_power: 10,
        prevotes: vec![vote.clone()],
        precommits: vec![vote.clone()],
        metadata,
        commit_votes: vec![vote],
    }
}

fn consensus_public_inputs() -> Value {
    force_enable_for_tests();
    let prover = Plonky3Prover::new();
    let certificate = sample_certificate();
    let block_hash = certificate.block_hash.0.clone();
    let witness = prover
        .build_consensus_witness(&block_hash, &certificate)
        .expect("build consensus witness");
    witness
        .public_inputs()
        .expect("serialize consensus public inputs")
}

#[test]
fn crypto_consensus_roundtrip_verifies() {
    let public_inputs = consensus_public_inputs();
    let proof = crypto::finalize("consensus".to_string(), public_inputs.clone())
        .expect("finalize consensus proof");
    crypto::verify_proof(&proof).expect("consensus proof verifies");
}

#[test]
fn crypto_consensus_rejects_inconsistent_inputs() {
    let mut public_inputs = consensus_public_inputs();
    if let Some(object) = public_inputs.as_object_mut() {
        object.insert("quorum_signature_root".into(), Value::String(digest(0xAB)));
    }
    let err = crypto::finalize("consensus".to_string(), public_inputs).unwrap_err();
    assert!(
        err.to_string().contains("consensus public inputs"),
        "unexpected finalize error: {err:?}"
    );
}

#[test]
fn crypto_consensus_rejects_wrong_key_on_verify() {
    let public_inputs = consensus_public_inputs();
    let proof =
        crypto::finalize("consensus".to_string(), public_inputs).expect("finalize consensus proof");
    let mut value = proof.clone().into_value().expect("serialize proof");
    let mut parsed = Plonky3Proof::from_value(&value).expect("decode proof");
    parsed.payload.metadata.trace_commitment[0] ^= 0x80;
    value = parsed.into_value().expect("serialize mutated proof");
    let tampered = ChainProof::Plonky3(value);

    let verifier = Plonky3Verifier::default();
    let err = verifier
        .verify_consensus(&tampered)
        .expect_err("verifier rejects tampered key");
    assert!(
        err.to_string().contains("verifying key mismatch"),
        "unexpected verifier error: {err:?}"
    );
}
