use libp2p::PeerId;
use plonky3_backend::{ConsensusCircuit, ConsensusWitness as BackendConsensusWitness};
use rpp_chain::consensus::{ConsensusCertificate, ConsensusProofMetadata};
use rpp_chain::consensus_engine::messages::{BlockId, TalliedVote};
use rpp_chain::plonky3::prover::Plonky3Prover;
use rpp_chain::plonky3::verifier::Plonky3Verifier;
use rpp_chain::proof_system::{ProofProver, ProofVerifier};
use rpp_chain::types::ChainProof;
use rpp_chain::vrf::VRF_PROOF_LENGTH;
use serde_json::{Map, Value};

fn sample_vote(validator: &str, voting_power: u64) -> TalliedVote {
    TalliedVote {
        validator_id: validator.to_string(),
        peer_id: PeerId::random(),
        signature: vec![0xAA, 0xBB],
        voting_power,
    }
}

fn sample_metadata() -> ConsensusProofMetadata {
    let digest = |byte: u8| hex::encode([byte; 32]);
    let proof_bytes = |byte: u8| hex::encode(vec![byte; VRF_PROOF_LENGTH]);

    ConsensusProofMetadata {
        vrf_outputs: vec![digest(0x11)],
        vrf_proofs: vec![proof_bytes(0x21)],
        witness_commitments: vec![digest(0x33)],
        reputation_roots: vec![digest(0x44)],
        epoch: 7,
        slot: 9,
        quorum_bitmap_root: digest(0x55),
        quorum_signature_root: digest(0x66),
    }
}

fn sample_certificate() -> ConsensusCertificate {
    let vote = sample_vote("validator-1", 10);
    ConsensusCertificate {
        block_hash: BlockId("99".repeat(32)),
        height: 5,
        round: 3,
        total_power: 10,
        quorum_threshold: 6,
        prevote_power: 10,
        precommit_power: 10,
        commit_power: 10,
        prevotes: vec![vote.clone()],
        precommits: vec![vote.clone()],
        metadata: sample_metadata(),
        commit_votes: vec![vote],
    }
}

fn tamper_proof(proof: &ChainProof, mutator: impl FnOnce(&mut Map<String, Value>)) -> ChainProof {
    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = rpp_chain::plonky3::proof::Plonky3Proof::from_value(value)
            .expect("decode plonky3 proof");
        let witness = parsed
            .public_inputs
            .get_mut("witness")
            .and_then(Value::as_object_mut)
            .expect("consensus witness value");
        mutator(witness);

        // Recompute bindings so the mutation mimics a sophisticated attacker.
        let backend_witness: BackendConsensusWitness =
            serde_json::from_value(Value::Object(witness.clone())).expect("backend witness");
        let circuit = ConsensusCircuit::new(backend_witness).expect("backend circuit");
        let bindings = circuit.bindings().clone();
        parsed.public_inputs.as_object_mut().unwrap().insert(
            "bindings".into(),
            serde_json::to_value(&bindings).expect("bindings value"),
        );

        // Update commitment to align with the mutated public inputs.
        parsed.commitment = rpp_chain::plonky3::crypto::compute_commitment(&parsed.public_inputs)
            .expect("compute commitment");
        *value = parsed.into_value().expect("serialize proof");
    }
    tampered
}

#[test]
fn plonky3_rejects_consensus_manipulation() {
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();

    let certificate = sample_certificate();
    let block_hash = certificate.block_hash.0.clone();
    let witness = prover
        .build_consensus_witness(&block_hash, &certificate)
        .expect("build witness");
    let proof = prover.prove_consensus(witness).expect("prove consensus");

    verifier
        .verify_consensus(&proof)
        .expect("baseline proof verifies");

    let tampered = tamper_proof(&proof, |witness| {
        witness.insert(
            "quorum_signature_root".into(),
            Value::String("77".repeat(32)),
        );
    });
    assert!(verifier.verify_consensus(&tampered).is_err());
}
