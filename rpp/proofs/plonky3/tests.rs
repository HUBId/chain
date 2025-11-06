//! Regression tests for the experimental Plonky3 backend.
//!
//! The prover shims are deterministic when fed the same witnesses, so each
//! helper below seeds `StdRng` with fixed byte arrays to keep CI runs
//! reproducible without depending on JSON fixtures.

use blake3::hash as blake3_hash;
use ed25519_dalek::{Keypair, Signer};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::json;
use serde_json::Value;
use std::convert::TryInto;

use crate::crypto::address_from_public_key;
use crate::plonky3::circuit::consensus::{
    ConsensusVrfEntry, ConsensusVrfPoseidonInput, ConsensusWitness, VotePower,
};
use crate::plonky3::circuit::pruning::PruningWitness;
use crate::plonky3::params::Plonky3Parameters;
use crate::plonky3::prover::Plonky3Prover;
use crate::plonky3::verifier::Plonky3Verifier;
use crate::plonky3::{crypto, proof::Plonky3Proof, public_inputs};
use crate::proof_system::{ProofProver, ProofVerifier};
use crate::rpp::GlobalStateCommitments;
use crate::types::{
    pruning_from_previous, BlockHeader, BlockProofBundle, ChainProof, PruningProof,
    SignedTransaction, Transaction,
};
use plonky3_backend::{
    BackendError, CircuitStarkConfig, HashFormat, ProverContext as BackendProverContext,
};
use rpp_crypto_vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};
use rpp_pruning::Envelope;

const TRANSACTION_SEED: [u8; 32] = [7u8; 32];

fn test_prover() -> Plonky3Prover {
    Plonky3Prover::new()
}

fn test_verifier() -> Plonky3Verifier {
    Plonky3Verifier::default()
}

fn canonical_pruning_header() -> BlockHeader {
    BlockHeader::new(
        0,
        "00".repeat(32),
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
        "55".repeat(32),
        "66".repeat(32),
        "77".repeat(32),
        "0".to_string(),
        "88".repeat(32),
        "99".repeat(32),
        "aa".repeat(32),
        "bb".repeat(64),
        format!("0x{}", "cc".repeat(20)),
        "TL1".to_string(),
        0,
    )
}

fn sample_transaction() -> SignedTransaction {
    let mut rng = StdRng::from_seed(TRANSACTION_SEED);
    let keypair = Keypair::generate(&mut rng);
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), from.clone(), 42, 1, 0, None);
    let signature = keypair.sign(&tx.canonical_bytes());
    SignedTransaction::new(tx, signature, &keypair.public)
}

fn sample_pruning_artifacts(prover: &Plonky3Prover) -> (PruningProof, ChainProof) {
    let header = canonical_pruning_header();
    let pruning_envelope = pruning_from_previous(None, &header);
    let witness = prover
        .build_pruning_witness(None, &[], &[], pruning_envelope.as_ref(), Vec::new())
        .unwrap();
    let proof = prover.prove_pruning(witness).unwrap();
    (pruning_envelope, proof)
}

fn extract_pruning_witness(proof: &ChainProof) -> PruningWitness {
    match proof {
        ChainProof::Plonky3(value) => {
            let parsed = Plonky3Proof::from_value(value).expect("parse pruning proof");
            let witness_value = parsed
                .public_inputs
                .get("witness")
                .cloned()
                .expect("pruning witness payload");
            serde_json::from_value(witness_value).expect("decode pruning witness")
        }
        ChainProof::Stwo(_) => panic!("expected Plonky3 pruning proof"),
    }
}

fn assert_pruning_matches_envelope(witness: &PruningWitness, envelope: &Envelope) {
    assert_eq!(witness.snapshot, envelope.snapshot().clone());
    assert_eq!(witness.segments, envelope.segments().to_vec());
    assert_eq!(
        witness.commitment.schema_version(),
        envelope.commitment().schema_version()
    );
    assert_eq!(
        witness.commitment.parameter_version(),
        envelope.commitment().parameter_version()
    );
    assert_eq!(
        witness.commitment.aggregate_commitment(),
        envelope.commitment().aggregate_commitment()
    );
    assert_eq!(witness.binding_digest, envelope.binding_digest());
}

#[test]
fn compute_commitment_is_stable_for_map_ordering() {
    let first: Value = serde_json::from_str(
        r#"{
            "outer": {
                "alpha": 1,
                "beta": {
                    "gamma": [
                        {"key": "value", "number": 7},
                        {"number": 8, "key": "other"}
                    ],
                    "delta": true
                }
            },
            "array": [
                {"x": 1, "y": 2},
                {"y": 3, "x": 4}
            ]
        }"#,
    )
    .unwrap();
    let second: Value = serde_json::from_str(
        r#"{
            "array": [
                {"y": 2, "x": 1},
                {"x": 4, "y": 3}
            ],
            "outer": {
                "beta": {
                    "delta": true,
                    "gamma": [
                        {"number": 7, "key": "value"},
                        {"key": "other", "number": 8}
                    ]
                },
                "alpha": 1
            }
        }"#,
    )
    .unwrap();

    let first_commitment = crypto::compute_commitment(&first).unwrap();
    let second_commitment = crypto::compute_commitment(&second).unwrap();

    assert_eq!(first_commitment, second_commitment);
}

#[test]
fn backend_context_roundtrip_matches_shared_commitment() {
    let params = Plonky3Parameters::default();
    let (verifying_key, proving_key) = crypto::circuit_keys("transaction").unwrap();
    let context = BackendProverContext::new(
        "transaction",
        verifying_key,
        proving_key,
        params.security_bits,
        params.use_gpu_acceleration,
    )
    .unwrap();

    let public_inputs = json!({
        "witness": {
            "payload": "deadbeef",
            "nonce": 42,
        },
        "meta": [1, 2, 3, 4],
    });

    let (commitment, proof) = context.prove(&public_inputs).unwrap();
    let computed = public_inputs::compute_commitment(&public_inputs).unwrap();
    assert_eq!(commitment, computed);

    context
        .verifier()
        .verify(&commitment, &public_inputs, &proof)
        .unwrap();
}

#[test]
fn backend_context_detects_tampered_inputs() {
    let params = Plonky3Parameters::default();
    let (verifying_key, proving_key) = crypto::circuit_keys("transaction").unwrap();
    let context = BackendProverContext::new(
        "transaction",
        verifying_key,
        proving_key,
        params.security_bits,
        params.use_gpu_acceleration,
    )
    .unwrap();

    let public_inputs = json!({
        "witness": {
            "payload": "feedface",
            "nonce": 7,
        },
        "meta": {
            "height": 10,
            "network": "localnet",
        },
    });

    let (commitment, proof) = context.prove(&public_inputs).unwrap();
    let verifier = context.verifier();

    let tampered_commitment = format!("{commitment}00");
    assert!(matches!(
        verifier.verify(&tampered_commitment, &public_inputs, &proof),
        Err(BackendError::PublicInputDigestMismatch(_))
    ));

    let mut tampered_inputs = public_inputs.clone();
    tampered_inputs
        .as_object_mut()
        .unwrap()
        .insert("meta".into(), json!({"height": 11, "network": "localnet"}));
    assert!(matches!(
        verifier.verify(&commitment, &tampered_inputs, &proof),
        Err(BackendError::PublicInputDigestMismatch(_))
    ));
}

#[test]
fn transaction_proof_roundtrip() {
    let prover = test_prover();
    let verifier = test_verifier();
    let tx = sample_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    verifier.verify_transaction(&proof).unwrap();

    let parsed = match &proof {
        ChainProof::Plonky3(value) => Plonky3Proof::from_value(value).unwrap(),
        ChainProof::Stwo(_) => panic!("expected Plonky3 proof"),
    };
    assert!(
        parsed.payload.metadata.fri_commitments.len() >= 1,
        "transaction proofs must record FRI commit-phase digests"
    );
    assert!(
        parsed.payload.metadata.challenger_digests.len() >= 1,
        "transaction proofs must expose challenger checkpoints"
    );
    assert!(!parsed.payload.stark_proof.is_empty());
    let decoded: p3_uni_stark::Proof<CircuitStarkConfig> =
        bincode::deserialize(&parsed.payload.stark_proof).unwrap();
    let reserialized = bincode::serialize(&decoded).unwrap();
    assert_eq!(parsed.payload.stark_proof, reserialized);
    assert!(parsed.payload.auxiliary_payloads.is_empty());
    let (_, expected_digest, encoded_inputs) =
        public_inputs::compute_commitment_and_inputs(&parsed.public_inputs).unwrap();
    assert_eq!(parsed.payload.metadata.public_inputs_hash, expected_digest);
    let inputs_hash = blake3_hash(&encoded_inputs);
    assert_eq!(
        parsed.payload.metadata.public_inputs_hash,
        *inputs_hash.as_bytes()
    );
    let params = Plonky3Parameters::default();
    assert_eq!(parsed.payload.metadata.security_bits, params.security_bits);
    assert!(
        parsed.payload.metadata.derived_security_bits >= params.security_bits,
        "derived security cannot undershoot negotiated security"
    );
    assert_eq!(parsed.payload.metadata.use_gpu, params.use_gpu_acceleration);
    parsed.payload.validate().unwrap();
    let computed = crypto::compute_commitment(&parsed.public_inputs).unwrap();
    assert_eq!(parsed.commitment, computed);
    let decoded: crate::plonky3::circuit::transaction::TransactionWitness = serde_json::from_value(
        parsed
            .public_inputs
            .get("witness")
            .cloned()
            .expect("transaction witness"),
    )
    .unwrap();
    assert_eq!(decoded.transaction, tx);
}

#[test]
fn transaction_payload_serialization_roundtrip() {
    let prover = test_prover();
    let tx = sample_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let parsed = match &proof {
        ChainProof::Plonky3(value) => Plonky3Proof::from_value(value).unwrap(),
        ChainProof::Stwo(_) => panic!("expected Plonky3 proof"),
    };

    let serialized = serde_json::to_string_pretty(&parsed.payload).unwrap();
    let recovered: crate::plonky3::proof::ProofPayload = serde_json::from_str(&serialized).unwrap();
    assert_eq!(recovered.stark_proof, parsed.payload.stark_proof);
    assert_eq!(
        recovered.auxiliary_payloads,
        parsed.payload.auxiliary_payloads
    );
    assert_eq!(
        recovered.metadata.hash_format,
        HashFormat::PoseidonMerkleCap
    );
    recovered.validate().unwrap();

    let fixture: crate::plonky3::proof::ProofPayload =
        serde_json::from_str(include_str!("fixtures/transaction_payload_v1.json")).unwrap();
    fixture.validate().unwrap();
    assert!(!fixture.stark_proof.is_empty());
    assert!(fixture.auxiliary_payloads.is_empty());
    let decoded: p3_uni_stark::Proof<CircuitStarkConfig> =
        bincode::deserialize(&fixture.stark_proof).unwrap();
    let reserialized = bincode::serialize(&decoded).unwrap();
    assert_eq!(fixture.stark_proof, reserialized);
    assert_eq!(fixture.metadata.hash_format, HashFormat::PoseidonMerkleCap);
    fixture.to_backend("transaction").unwrap();
}

fn consensus_witness_fixture() -> ConsensusWitness {
    let vote = VotePower {
        voter: "validator-1".into(),
        weight: 80,
    };
    let vrf_entry = ConsensusVrfEntry {
        randomness: "dd".repeat(32),
        pre_output: "ee".repeat(VRF_PREOUTPUT_LENGTH),
        proof: hex::encode(vec![0xee; VRF_PROOF_LENGTH]),
        public_key: "ff".repeat(32),
        poseidon: ConsensusVrfPoseidonInput {
            digest: "11".repeat(32),
            last_block_header: "22".repeat(32),
            epoch: "5".into(),
            tier_seed: "33".repeat(32),
        },
    };
    ConsensusWitness::new(
        "aa".repeat(32),
        3,
        5,
        7,
        "aa".repeat(32),
        67,
        vec![vote.clone()],
        vec![vote.clone()],
        vec![vote],
        "bb".repeat(32),
        "cc".repeat(32),
        vec![vrf_entry],
        vec!["ff".repeat(32)],
        vec!["11".repeat(32)],
    )
}

#[test]
fn consensus_witness_rejects_missing_metadata() {
    let mut witness = consensus_witness_fixture();
    witness.vrf_entries.clear();

    let err = witness
        .validate_metadata()
        .expect_err("missing metadata must fail");
    assert!(
        err.to_string().contains("missing VRF entries"),
        "unexpected error: {err}"
    );
}

#[test]
fn consensus_witness_rejects_missing_vrf_proof() {
    let mut witness = consensus_witness_fixture();
    if let Some(entry) = witness.vrf_entries.first_mut() {
        entry.proof.clear();
    }

    let err = witness
        .validate_metadata()
        .expect_err("missing vrf proof must fail");
    assert!(
        err.to_string().contains("missing proof"),
        "unexpected error: {err}"
    );
}

#[test]
fn consensus_witness_rejects_missing_vrf_pre_output() {
    let mut witness = consensus_witness_fixture();
    if let Some(entry) = witness.vrf_entries.first_mut() {
        entry.pre_output.clear();
    }

    let err = witness
        .validate_metadata()
        .expect_err("missing vrf pre-output must fail");
    assert!(
        err.to_string().contains("missing pre-output"),
        "unexpected error: {err}"
    );
}

#[test]
fn consensus_witness_rejects_missing_vrf_poseidon_digest() {
    let mut witness = consensus_witness_fixture();
    if let Some(entry) = witness.vrf_entries.first_mut() {
        entry.poseidon.digest.clear();
    }

    let err = witness
        .validate_metadata()
        .expect_err("missing vrf poseidon digest must fail");
    assert!(
        err.to_string().contains("poseidon digest"),
        "unexpected error: {err}"
    );
}

#[test]
fn consensus_witness_rejects_invalid_quorum_root() {
    let mut witness = consensus_witness_fixture();
    witness.quorum_bitmap_root = "deadbeef".into();

    let err = witness
        .validate_metadata()
        .expect_err("invalid quorum root must fail");
    assert!(
        err.to_string().contains("quorum bitmap root"),
        "unexpected error: {err}"
    );
}

#[test]
fn consensus_witness_preserves_enriched_vrf_metadata() {
    let witness = consensus_witness_fixture();
    let backend = witness
        .to_backend()
        .expect("consensus witness converts to backend");

    assert_eq!(backend.vrf_entries, witness.vrf_entries);
}

#[test]
fn consensus_witness_rejects_missing_vrf_public_key() {
    let mut witness = consensus_witness_fixture();
    if let Some(entry) = witness.vrf_entries.first_mut() {
        entry.public_key.clear();
    }

    let err = witness
        .validate_metadata()
        .expect_err("missing vrf public key must fail");
    assert!(
        err.to_string().contains("public key"),
        "unexpected error: {err}"
    );
}

#[test]
fn transaction_proof_rejects_tampered_verifying_key() {
    let prover = test_prover();
    let verifier = test_verifier();
    let tx = sample_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.metadata.trace_commitment[0] ^= 0x80;
        *value = parsed.into_value().unwrap();
    }

    let verify_err = verifier.verify_transaction(&tampered).unwrap_err();
    assert!(
        verify_err.to_string().contains("verifying key mismatch"),
        "unexpected verifier error: {verify_err:?}"
    );

    if let ChainProof::Plonky3(value) = &tampered {
        let parsed = Plonky3Proof::from_value(value).unwrap();
        let backend_err = crypto::verify_proof(&parsed).unwrap_err();
        assert!(
            backend_err.to_string().contains("verifying key mismatch"),
            "unexpected backend error: {backend_err:?}"
        );
    }
}

#[test]
fn transaction_proof_rejects_malformed_witness() {
    let prover = test_prover();
    let verifier = test_verifier();
    let tx = sample_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut malformed = proof.clone();
    if let ChainProof::Plonky3(value) = &mut malformed {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        if let Value::Object(ref mut root) = parsed.public_inputs {
            root.insert("witness".to_string(), json!({"transaction": "oops"}));
        }
        *value = parsed.into_value().unwrap();
    }

    let verify_err = verifier.verify_transaction(&malformed).unwrap_err();
    assert!(
        verify_err.to_string().contains("commitment mismatch"),
        "unexpected verifier error: {verify_err:?}"
    );

    if let ChainProof::Plonky3(value) = &malformed {
        let parsed = Plonky3Proof::from_value(value).unwrap();
        let backend_err = crypto::verify_proof(&parsed).unwrap_err();
        assert!(
            backend_err.to_string().contains("commitment mismatch"),
            "unexpected backend error: {backend_err:?}"
        );
    }
}

#[test]
fn transaction_proof_rejects_truncated_payload() {
    let prover = test_prover();
    let verifier = test_verifier();
    let tx = sample_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut truncated = proof.clone();
    if let ChainProof::Plonky3(value) = &mut truncated {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed
            .payload
            .stark_proof
            .truncate(parsed.payload.stark_proof.len().saturating_sub(1));
        *value = parsed.into_value().unwrap();
    }

    let verify_err = verifier.verify_transaction(&truncated).unwrap_err();
    assert!(
        verify_err
            .to_string()
            .contains("failed to decode Plonky3 transaction proof payload"),
        "unexpected verifier error: {verify_err:?}"
    );
}

#[test]
fn transaction_proof_rejects_oversized_payload() {
    let prover = test_prover();
    let verifier = test_verifier();
    let tx = sample_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut oversized = proof;
    if let ChainProof::Plonky3(value) = &mut oversized {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.stark_proof.push(0);
        *value = parsed.into_value().unwrap();
    }

    let verify_err = verifier.verify_transaction(&oversized).unwrap_err();
    assert!(
        verify_err
            .to_string()
            .contains("failed to decode Plonky3 transaction proof payload"),
        "unexpected verifier error: {verify_err:?}"
    );
}

#[test]
fn recursive_aggregator_rejects_tampered_inputs() {
    let prover = test_prover();
    let tx = sample_transaction();
    let transaction_proof = prover
        .prove_transaction(prover.build_transaction_witness(&tx).unwrap())
        .unwrap();

    let state_inputs = json!({"witness": {"state_root": "alpha"}});
    let state_proof = ChainProof::Plonky3(
        Plonky3Proof::new("state", state_inputs)
            .unwrap()
            .into_value()
            .unwrap(),
    );
    let (pruning_envelope, pruning_proof) = sample_pruning_artifacts(&prover);
    let pruning_witness = extract_pruning_witness(&pruning_proof);
    assert_pruning_matches_envelope(&pruning_witness, pruning_envelope.as_ref());

    let mut tampered = transaction_proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        if let Some(object) = value.as_object_mut() {
            object.insert("commitment".into(), json!("deadbeef"));
        }
    }

    let tampered_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[tampered.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            pruning_envelope.as_ref(),
            &pruning_proof,
            1,
        )
        .unwrap();
    assert!(prover.prove_recursive(tampered_witness).is_err());

    let valid_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[transaction_proof.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            pruning_envelope.as_ref(),
            &pruning_proof,
            1,
        )
        .unwrap();
    assert!(prover.prove_recursive(valid_witness).is_ok());
}

#[test]
fn recursive_bundle_verification_detects_tampering() {
    let prover = test_prover();
    let verifier = test_verifier();
    let tx = sample_transaction();
    let transaction_proof = prover
        .prove_transaction(prover.build_transaction_witness(&tx).unwrap())
        .unwrap();
    let state_inputs = json!({"witness": {"state_root": "abc"}});
    let state_proof = ChainProof::Plonky3(
        Plonky3Proof::new("state", state_inputs)
            .unwrap()
            .into_value()
            .unwrap(),
    );
    let (pruning_envelope, pruning_proof) = sample_pruning_artifacts(&prover);
    let pruning_witness = extract_pruning_witness(&pruning_proof);
    assert_pruning_matches_envelope(&pruning_witness, pruning_envelope.as_ref());
    let recursive_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[transaction_proof.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            pruning_envelope.as_ref(),
            &pruning_proof,
            42,
        )
        .unwrap();
    let recursive_proof = prover.prove_recursive(recursive_witness).unwrap();

    let bundle = BlockProofBundle::new(
        vec![transaction_proof.clone()],
        state_proof.clone(),
        pruning_proof.clone(),
        recursive_proof.clone(),
    );
    verifier.verify_bundle(&bundle, None).unwrap();

    let mut bad_key_bundle = bundle.clone();
    if let ChainProof::Plonky3(value) = &mut bad_key_bundle.recursive_proof {
        if let Some(object) = value.as_object_mut() {
            if let Some(payload) = object.get_mut("payload").and_then(Value::as_object_mut) {
                if let Some(metadata) = payload.get_mut("metadata").and_then(Value::as_object_mut) {
                    metadata.insert("trace_commitment".into(), json!("00".repeat(32)));
                }
            }
        }
    }
    assert!(verifier.verify_bundle(&bad_key_bundle, None).is_err());

    let mut tampered = recursive_proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        if let Some(object) = value.as_object_mut() {
            object.insert("commitment".into(), json!("deadbeef"));
        }
    }
    let tampered_bundle = BlockProofBundle::new(
        vec![transaction_proof.clone()],
        state_proof.clone(),
        pruning_proof.clone(),
        tampered,
    );
    assert!(verifier.verify_bundle(&tampered_bundle, None).is_err());

    let mut oversized = recursive_proof.clone();
    if let ChainProof::Plonky3(value) = &mut oversized {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.stark_proof.push(0);
        *value = parsed.into_value().unwrap();
    }
    let oversized_bundle = BlockProofBundle::new(
        vec![transaction_proof],
        state_proof,
        pruning_proof,
        oversized,
    );
    assert!(verifier.verify_bundle(&oversized_bundle, None).is_err());
}

#[test]
fn recursive_roundtrip_spans_state_and_transactions() {
    let prover = test_prover();
    let verifier = test_verifier();

    let tx = sample_transaction();
    let transaction_proof = prover
        .prove_transaction(prover.build_transaction_witness(&tx).unwrap())
        .unwrap();

    let state_witness = prover
        .build_state_witness("prev", "next", &[], &[tx.clone()])
        .unwrap();
    let state_proof = prover.prove_state_transition(state_witness).unwrap();

    let header = canonical_pruning_header();
    let pruning = pruning_from_previous(None, &header);
    let pruning_witness = prover
        .build_pruning_witness(None, &[], &[], pruning.as_ref(), Vec::new())
        .unwrap();
    let pruning_proof = prover.prove_pruning(pruning_witness).unwrap();
    let pruning_witness = extract_pruning_witness(&pruning_proof);
    assert_pruning_matches_envelope(&pruning_witness, pruning.as_ref());

    let recursive_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[transaction_proof.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            pruning.as_ref(),
            &pruning_proof,
            7,
        )
        .unwrap();
    let recursive_proof = prover.prove_recursive(recursive_witness).unwrap();

    verifier.verify_transaction(&transaction_proof).unwrap();
    verifier.verify_state(&state_proof).unwrap();
    verifier.verify_pruning(&pruning_proof).unwrap();
    verifier.verify_recursive(&recursive_proof).unwrap();

    let bundle = BlockProofBundle::new(
        vec![transaction_proof.clone()],
        state_proof.clone(),
        pruning_proof.clone(),
        recursive_proof.clone(),
    );
    verifier.verify_bundle(&bundle, None).unwrap();

    // Tampering with any sub-proof now causes the bundle verification to fail.
    let mut broken_state = state_proof.clone();
    if let ChainProof::Plonky3(value) = &mut broken_state {
        if let Some(object) = value.as_object_mut() {
            if let Some(payload) = object.get_mut("payload").and_then(Value::as_object_mut) {
                payload.insert("stark_proof".into(), json!("ZG9nZ29nb28="));
            }
        }
    }
    let broken_bundle = BlockProofBundle::new(
        vec![transaction_proof.clone()],
        broken_state,
        pruning_proof.clone(),
        recursive_proof.clone(),
    );
    assert!(verifier.verify_bundle(&broken_bundle, None).is_err());

    let mut broken_links = recursive_proof.clone();
    if let ChainProof::Plonky3(value) = &mut broken_links {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        if let Value::Object(ref mut root) = parsed.public_inputs {
            if let Some(Value::Object(witness)) = root.get_mut("witness") {
                witness.insert("transaction_proofs".into(), json!([]));
            }
        }
        *value = parsed.into_value().unwrap();
    }
    assert!(verifier.verify_recursive(&broken_links).is_err());
    let broken_link_bundle = BlockProofBundle::new(
        vec![transaction_proof],
        state_proof,
        pruning_proof,
        broken_links,
    );
    assert!(verifier.verify_bundle(&broken_link_bundle, None).is_err());
}
