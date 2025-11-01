use std::fs;
use std::path::Path;

use blake3::hash as blake3_hash;
use serde_json::json;
use serde_json::Value;
use uuid::Uuid;

use crate::plonky3::circuit::pruning::PruningWitness;
use crate::plonky3::params::Plonky3Parameters;
use crate::plonky3::prover::Plonky3Prover;
use crate::plonky3::verifier::Plonky3Verifier;
use crate::plonky3::{crypto, proof::Plonky3Proof};
use crate::proof_system::{ProofProver, ProofVerifier};
use crate::rpp::GlobalStateCommitments;
use crate::types::{
    pruning_from_previous, BlockHeader, BlockProofBundle, ChainProof, PruningProof,
    SignedTransaction, Transaction,
};
use rpp_pruning::Envelope;

use plonky3_backend::Circuit;

const FIXTURE_DIR: &str = "rpp/proofs/plonky3/tests/fixtures";

fn enable_experimental_backend() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| crate::plonky3::experimental::force_enable_for_tests());
}

fn test_prover() -> Plonky3Prover {
    enable_experimental_backend();
    Plonky3Prover::new()
}

fn test_verifier() -> Plonky3Verifier {
    enable_experimental_backend();
    Plonky3Verifier::default()
}

fn load_fixture(name: &str) -> Value {
    let path = Path::new(FIXTURE_DIR).join(name);
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to load Plonky3 fixture {}: {err}", path.display()));
    serde_json::from_str(&data)
        .unwrap_or_else(|err| panic!("failed to decode Plonky3 fixture {}: {err}", path.display()))
}

#[test]
fn keygen_uses_setup_artifacts() {
    enable_experimental_backend();
    let params = Plonky3Parameters::default();
    for circuit in [
        "identity",
        "transaction",
        "state",
        "pruning",
        "recursive",
        "uptime",
        "consensus",
    ] {
        let (verifying_key, proving_key) = crypto::circuit_keys(circuit).unwrap();
        let compiled = Circuit::keygen(
            circuit.to_string(),
            verifying_key.clone(),
            proving_key.clone(),
            params.security_bits,
            params.use_gpu_acceleration,
        )
        .unwrap();
        assert_eq!(compiled.verifying_key(), verifying_key.as_slice());
        assert_eq!(compiled.proving_key(), proving_key.as_slice());
        assert_eq!(compiled.security_bits(), params.security_bits);
        assert_eq!(compiled.use_gpu(), params.use_gpu_acceleration);
    }
}

#[test]
fn transaction_proof_matches_fixture() {
    let prover = test_prover();
    let tx = sample_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();
    let generated = match proof {
        ChainProof::Plonky3(value) => value,
        ChainProof::Stwo(_) => panic!("expected plonky3 proof"),
    };

    let expected = load_fixture("transaction_roundtrip.json");
    assert_eq!(generated, expected);
}

#[test]
fn transaction_fixture_verifies() {
    let verifier = test_verifier();
    let value = load_fixture("transaction_roundtrip.json");
    let proof = ChainProof::Plonky3(value.clone());

    verifier.verify_transaction(&proof).unwrap();

    let parsed = Plonky3Proof::from_value(&value).unwrap();
    crypto::verify_proof(&parsed).unwrap();
}

#[test]
fn transaction_fixture_rejects_tampered_verifying_key() {
    let verifier = test_verifier();
    let value = load_fixture("transaction_roundtrip.json");
    let mut parsed = Plonky3Proof::from_value(&value).unwrap();
    assert!(!parsed.verifying_key.is_empty(), "fixture verifying key must not be empty");
    parsed.verifying_key[0] ^= 0x80;
    let tampered_value = parsed.into_value().unwrap();
    let proof = ChainProof::Plonky3(tampered_value.clone());

    let verify_err = verifier.verify_transaction(&proof).unwrap_err();
    assert!(
        verify_err
            .to_string()
            .contains("verifying key mismatch"),
        "unexpected verifier error: {verify_err:?}"
    );

    let parsed_tampered = Plonky3Proof::from_value(&tampered_value).unwrap();
    let crypto_err = crypto::verify_proof(&parsed_tampered).unwrap_err();
    assert!(
        crypto_err
            .to_string()
            .contains("verifying key mismatch"),
        "unexpected crypto verification error: {crypto_err:?}"
    );
}

#[test]
fn transaction_fixture_rejects_tampered_public_inputs() {
    let verifier = test_verifier();
    let value = load_fixture("transaction_roundtrip.json");
    let mut parsed = Plonky3Proof::from_value(&value).unwrap();
    if let Value::Object(ref mut root) = parsed.public_inputs {
        if let Some(Value::Object(witness)) = root.get_mut("witness") {
            if let Some(Value::Object(tx)) = witness.get_mut("transaction") {
                if let Some(Value::Object(payload)) = tx.get_mut("payload") {
                    payload.insert("amount".to_string(), json!(1337));
                }
            }
        }
    }
    let tampered_value = parsed.into_value().unwrap();
    let proof = ChainProof::Plonky3(tampered_value.clone());

    let verify_err = verifier.verify_transaction(&proof).unwrap_err();
    assert!(verify_err
        .to_string()
        .contains("commitment mismatch"), "unexpected verifier error: {verify_err:?}");

    let parsed_tampered = Plonky3Proof::from_value(&tampered_value).unwrap();
    let crypto_err = crypto::verify_proof(&parsed_tampered).unwrap_err();
    assert!(crypto_err
        .to_string()
        .contains("commitment mismatch"), "unexpected crypto verification error: {crypto_err:?}");
}

#[test]
fn transaction_fixture_rejects_truncated_proof_blob() {
    let verifier = test_verifier();
    let value = load_fixture("transaction_roundtrip.json");
    let mut parsed = Plonky3Proof::from_value(&value).unwrap();
    parsed.proof.truncate(parsed.proof.len().saturating_sub(1));
    let tampered_value = parsed.into_value().unwrap();
    let proof = ChainProof::Plonky3(tampered_value.clone());

    let verify_err = verifier.verify_transaction(&proof).unwrap_err();
    assert!(verify_err
        .to_string()
        .contains("proof blob must be"), "unexpected verifier error: {verify_err:?}");

    let parsed_tampered = Plonky3Proof::from_value(&tampered_value).unwrap();
    let crypto_err = crypto::verify_proof(&parsed_tampered).unwrap_err();
    assert!(crypto_err
        .to_string()
        .contains("proof blob must be"), "unexpected crypto verification error: {crypto_err:?}");
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
    let address = "bc4e7908ec08920102e7faf0898e7f4f71b24a5cc1b812e88c390794d557fcfa".to_string();
    let payload = Transaction {
        from: address.clone(),
        to: address,
        amount: 42,
        fee: 1,
        nonce: 0,
        memo: None,
        timestamp: 1,
    };
    SignedTransaction {
        id: Uuid::from_u128(1),
        payload,
        signature: "dc31c33a9c5b011a05281343f90bfd304d0e19f17d4929911eeddd6ee3f653f75e111d1c3cb66a03a234bce714d5b5f2bfb160fdbab5b12919046066116e0406".to_string(),
        public_key: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8".to_string(),
    }
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
    assert_eq!(
        parsed.verifying_key,
        crypto::verifying_key("transaction").unwrap()
    );
    assert_eq!(parsed.proof.len(), crypto::PROOF_BLOB_LEN);
    let verifying_hash = blake3_hash(&parsed.verifying_key);
    assert_eq!(&parsed.proof[..32], verifying_hash.as_bytes());
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
            object.insert("verifying_key".into(), json!("AA=="));
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
        vec![transaction_proof],
        state_proof,
        pruning_proof,
        tampered,
    );
    assert!(verifier.verify_bundle(&tampered_bundle, None).is_err());
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
            object.insert("proof".into(), json!("ZG9nZ29nb28="));
        }
    }
    let broken_bundle = BlockProofBundle::new(
        vec![transaction_proof],
        broken_state,
        pruning_proof,
        recursive_proof,
    );
    assert!(verifier.verify_bundle(&broken_bundle, None).is_err());
}
