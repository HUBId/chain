#[path = "common.rs"]
mod common;

use common::{align_poseidon_last_block_header, digest, metadata_fixture, vrf_entry};
use libp2p::PeerId;
use rpp_chain::consensus::{ConsensusCertificate, ConsensusProofMetadata};
use rpp_chain::consensus_engine::messages::{BlockId, TalliedVote};
use rpp_chain::types::ChainProof;

fn sample_metadata() -> ConsensusProofMetadata {
    metadata_fixture(
        vec![vrf_entry(0x01, 0x11, 9), vrf_entry(0x02, 0x22, 9)],
        vec![digest(0x33)],
        vec![digest(0x44)],
        9,
        5,
        digest(0x55),
        digest(0x66),
    )
}

fn sample_vote(label: &str, power: u64) -> TalliedVote {
    TalliedVote {
        validator_id: label.to_string(),
        peer_id: PeerId::random(),
        signature: vec![0xAA, 0xBB, 0xCC],
        voting_power: power,
    }
}

fn sample_certificate() -> ConsensusCertificate {
    let mut metadata = sample_metadata();
    let block_hash = BlockId("99".repeat(32));

    align_poseidon_last_block_header(&mut metadata, &block_hash.0);

    ConsensusCertificate {
        block_hash,
        height: 123,
        round: 7,
        total_power: 200,
        quorum_threshold: 133,
        prevote_power: 150,
        precommit_power: 150,
        commit_power: 150,
        prevotes: vec![sample_vote("validator-1", 150)],
        precommits: vec![sample_vote("validator-2", 150)],
        metadata,
    }
}

#[cfg(feature = "backend-plonky3")]
mod plonky3_backend {
    use super::*;
    use rpp_chain::plonky3::crypto;
    use rpp_chain::plonky3::proof::Plonky3Proof;
    use rpp_chain::plonky3::prover::Plonky3Prover;
    use rpp_chain::plonky3::verifier::Plonky3Verifier;
    use serde_json::Value;

    fn tamper_payload(
        original: &ChainProof,
        mutator: impl FnOnce(&mut Plonky3Proof),
    ) -> ChainProof {
        let mut tampered = original.clone();
        match &mut tampered {
            ChainProof::Plonky3(value) => {
                let mut parsed = Plonky3Proof::from_value(value).expect("decode plonky3 proof");
                mutator(&mut parsed);
                *value = parsed.into_value().expect("encode plonky3 proof");
            }
            other => panic!("expected Plonky3 proof, got {other:?}"),
        }
        tampered
    }

    fn tamper_public_inputs(original: &ChainProof, mutator: impl FnOnce(&mut Value)) -> ChainProof {
        let mut tampered = original.clone();
        match &mut tampered {
            ChainProof::Plonky3(value) => {
                let mut parsed =
                    Plonky3Proof::from_value(value).expect("decode plonky3 proof payload");
                mutator(&mut parsed.public_inputs);
                // Keep the commitment consistent with the mutated public inputs so verification
                // exercises the AIR relations instead of short-circuiting on hash mismatches.
                parsed.commitment = crypto::compute_commitment(&parsed.public_inputs)
                    .expect("recompute commitment");
                *value = parsed.into_value().expect("encode plonky3 proof");
            }
            other => panic!("expected Plonky3 proof, got {other:?}"),
        }
        tampered
    }

    #[test]
    fn plonky3_rejects_public_vrf_randomness_tampering() {
        let prover = Plonky3Prover::new();
        let verifier = Plonky3Verifier::default();

        let certificate = super::sample_certificate();
        let block_hash = certificate.block_hash.0.clone();
        let witness = prover
            .build_consensus_witness(&block_hash, &certificate)
            .expect("build consensus witness");
        let proof = prover.prove_consensus(witness).expect("prove consensus");

        verifier
            .verify_consensus(&proof)
            .expect("baseline verification succeeds");

        let tampered = tamper_public_inputs(&proof, |public_inputs| {
            if let Some(Value::Object(witness)) = public_inputs.get_mut("witness") {
                if let Some(Value::Array(entries)) = witness.get_mut("vrf_entries") {
                    if let Some(Value::Object(first)) = entries.first_mut() {
                        if let Some(Value::String(randomness)) = first.get_mut("randomness") {
                            let mut chars: Vec<_> = randomness.chars().collect();
                            if let Some(first) = chars.first_mut() {
                                *first = match *first {
                                    '0' => '1',
                                    _ => '0',
                                };
                            }
                            *randomness = chars.into_iter().collect();
                        }
                    }
                }
            }
        });

        assert!(verifier.verify_consensus(&tampered).is_err());
    }

    #[test]
    fn plonky3_rejects_public_quorum_root_tampering() {
        let prover = Plonky3Prover::new();
        let verifier = Plonky3Verifier::default();

        let certificate = super::sample_certificate();
        let block_hash = certificate.block_hash.0.clone();
        let witness = prover
            .build_consensus_witness(&block_hash, &certificate)
            .expect("build consensus witness");
        let proof = prover.prove_consensus(witness).expect("prove consensus");

        verifier
            .verify_consensus(&proof)
            .expect("baseline verification succeeds");

        let tampered = tamper_public_inputs(&proof, |public_inputs| {
            if let Some(Value::Object(bindings)) = public_inputs.get_mut("bindings") {
                bindings.insert("quorum_bitmap".into(), Value::String("deadc0de".into()));
            }
        });

        assert!(verifier.verify_consensus(&tampered).is_err());
    }

    #[test]
    fn plonky3_rejects_payload_vrf_metadata_tampering() {
        let prover = Plonky3Prover::new();
        let verifier = Plonky3Verifier::default();

        let certificate = super::sample_certificate();
        let block_hash = certificate.block_hash.0.clone();
        let witness = prover
            .build_consensus_witness(&block_hash, &certificate)
            .expect("build consensus witness");
        let proof = prover.prove_consensus(witness).expect("prove consensus");

        verifier
            .verify_consensus(&proof)
            .expect("baseline verification succeeds");

        let tampered = tamper_payload(&proof, |parsed| {
            let metadata = &mut parsed.payload.metadata;
            let mut canonical: Value = serde_json::from_slice(&metadata.canonical_public_inputs)
                .expect("decode canonical public inputs");
            if let Some(entries) = canonical
                .get_mut("witness")
                .and_then(Value::as_object_mut)
                .and_then(|witness| witness.get_mut("vrf_entries"))
                .and_then(Value::as_array_mut)
            {
                if let Some(Value::Object(first)) = entries.first_mut() {
                    if let Some(Value::String(randomness)) = first.get_mut("randomness") {
                        let mut chars: Vec<_> = randomness.chars().collect();
                        if let Some(first) = chars.first_mut() {
                            *first = match *first {
                                '0' => '1',
                                _ => '0',
                            };
                        }
                        *randomness = chars.into_iter().collect();
                    }
                }
            }
            metadata.canonical_public_inputs =
                serde_json::to_vec(&canonical).expect("encode canonical inputs");
        });

        assert!(verifier.verify_consensus(&tampered).is_err());
    }
}

#[cfg(feature = "prover-stwo")]
mod stwo_backend {
    use super::*;
    use prover_stwo_backend::official::params::StarkParameters;
    use rpp_chain::storage::Storage;
    use rpp_chain::stwo::prover::WalletProver;
    use rpp_chain::stwo::verifier::NodeVerifier;
    use tempfile::tempdir;

    fn tamper_public_inputs(
        original: &ChainProof,
        mutator: impl FnOnce(&mut Vec<String>),
    ) -> ChainProof {
        let mut tampered = original.clone();
        match &mut tampered {
            ChainProof::Stwo(proof) => {
                mutator(&mut proof.public_inputs);
                let parameters = StarkParameters::blueprint_default();
                let hasher = parameters.poseidon_hasher();
                let fields: Vec<_> = proof
                    .public_inputs
                    .iter()
                    .map(|hex| {
                        let bytes = hex::decode(hex).expect("decode public input hex");
                        parameters.element_from_bytes(&bytes)
                    })
                    .collect();
                proof.commitment = hasher.hash(&fields).to_hex();
            }
            other => panic!("expected STWO proof, got {other:?}"),
        }
        tampered
    }

    #[test]
    fn stwo_rejects_public_vrf_randomness_tampering() {
        let temp_dir = tempdir().expect("temporary storage directory");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let prover = WalletProver::new(&storage);
        let verifier = NodeVerifier::new();

        let certificate = super::sample_certificate();
        let block_hash = certificate.block_hash.0.clone();
        let witness = prover
            .build_consensus_witness(&block_hash, &certificate)
            .expect("build consensus witness");
        let proof = prover.prove_consensus(witness).expect("prove consensus");

        verifier
            .verify_consensus(&proof)
            .expect("baseline verification succeeds");

        let tampered = tamper_public_inputs(&proof, |inputs| {
            if let Some(first) = inputs.get_mut(8) {
                if first.len() >= 2 {
                    let mut chars: Vec<_> = first.chars().collect();
                    chars[0] = match chars[0] {
                        '0' => '1',
                        _ => '0',
                    };
                    *first = chars.into_iter().collect();
                }
            }
        });

        assert!(verifier.verify_consensus(&tampered).is_err());
    }

    #[test]
    fn stwo_rejects_public_quorum_root_tampering() {
        let temp_dir = tempdir().expect("temporary storage directory");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let prover = WalletProver::new(&storage);
        let verifier = NodeVerifier::new();

        let certificate = super::sample_certificate();
        let block_hash = certificate.block_hash.0.clone();
        let witness = prover
            .build_consensus_witness(&block_hash, &certificate)
            .expect("build consensus witness");
        let proof = prover.prove_consensus(witness).expect("prove consensus");

        verifier
            .verify_consensus(&proof)
            .expect("baseline verification succeeds");

        let tampered = tamper_public_inputs(&proof, |inputs| {
            if let Some(root) = inputs.get_mut(6) {
                if root.len() >= 2 {
                    let mut chars: Vec<_> = root.chars().collect();
                    chars.rotate_left(2.min(chars.len()));
                    *root = chars.into_iter().collect();
                }
            }
        });

        assert!(verifier.verify_consensus(&tampered).is_err());
    }
}
