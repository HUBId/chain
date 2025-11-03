#[path = "common.rs"]
mod common;

use common::{digest, metadata_fixture, vrf_entry};
use libp2p::PeerId;
use rpp_chain::consensus::{ConsensusCertificate, ConsensusProofMetadata};
use rpp_chain::consensus_engine::messages::{BlockId, TalliedVote};
use rpp_chain::proof_system::{ProofProver, ProofVerifier};
use rpp_chain::types::ChainProof;

fn sample_metadata() -> ConsensusProofMetadata {
    metadata_fixture(
        vec![vrf_entry(0x11, 0x21), vrf_entry(0x12, 0x22)],
        vec![digest(0x33)],
        vec![digest(0x44), digest(0x45)],
        5,
        7,
        digest(0x55),
        digest(0x66),
    )
}

fn sample_vote(validator: &str, voting_power: u64) -> TalliedVote {
    TalliedVote {
        validator_id: validator.to_string(),
        peer_id: PeerId::random(),
        signature: vec![0xAB, 0xCD, 0xEF],
        voting_power,
    }
}

fn sample_certificate() -> ConsensusCertificate {
    let metadata = sample_metadata();
    let vote = sample_vote("validator-1", 80);
    let block_hash = BlockId("99".repeat(32));

    ConsensusCertificate {
        block_hash,
        height: 42,
        round: 3,
        total_power: 100,
        quorum_threshold: 67,
        prevote_power: 80,
        precommit_power: 80,
        commit_power: 80,
        prevotes: vec![vote.clone()],
        precommits: vec![vote],
        metadata,
    }
}

#[cfg(feature = "backend-plonky3")]
mod plonky3_backend {
    use super::*;
    use plonky3_backend::ConsensusCircuit;
    use rpp_chain::plonky3::proof::Plonky3Proof;
    use rpp_chain::plonky3::prover::Plonky3Prover;
    use rpp_chain::plonky3::verifier::Plonky3Verifier;
    use rpp_chain::plonky3::{
        circuit::consensus::ConsensusWitness as Plonky3ConsensusWitness, crypto,
    };
    use serde_json::{Map, Value};

    fn tamper_proof(
        original: &ChainProof,
        mutator: impl FnOnce(&mut Map<String, Value>),
    ) -> ChainProof {
        let mut tampered = original.clone();
        match &mut tampered {
            ChainProof::Plonky3(value) => {
                let mut parsed = Plonky3Proof::from_value(value).expect("decode plonky3 proof");
                let witness = parsed
                    .public_inputs
                    .get_mut("witness")
                    .and_then(Value::as_object_mut)
                    .expect("consensus witness payload");
                mutator(witness);
                let consensus_witness: Plonky3ConsensusWitness =
                    serde_json::from_value(Value::Object(witness.clone()))
                        .expect("consensus witness struct");
                let backend_witness =
                    consensus_witness.to_backend().expect("prepare backend witness");
                let circuit = ConsensusCircuit::new(backend_witness).expect("backend circuit");
                let bindings = circuit.bindings().clone();
                parsed
                    .public_inputs
                    .as_object_mut()
                    .expect("public inputs object")
                    .insert(
                        "bindings".into(),
                        serde_json::to_value(&bindings).expect("bindings value"),
                    );
                parsed.commitment =
                    crypto::compute_commitment(&parsed.public_inputs).expect("compute commitment");
                *value = parsed.into_value().expect("encode plonky3 proof");
            }
            _ => panic!("expected Plonky3 proof"),
        }
        tampered
    }

    #[test]
    fn plonky3_rejects_tampered_consensus_metadata() {
        let prover = Plonky3Prover::new();
        let verifier = Plonky3Verifier::default();

        let certificate = sample_certificate();
        let block_hash = certificate.block_hash.0.clone();
        let witness = prover
            .build_consensus_witness(&block_hash, &certificate)
            .expect("build consensus witness");
        let proof = prover.prove_consensus(witness).expect("prove consensus");

        verifier
            .verify_consensus(&proof)
            .expect("baseline consensus proof should verify");

        let missing_vrf = tamper_proof(&proof, |witness| {
            witness.insert("vrf_entries".into(), Value::Array(Vec::new()));
        });
        assert!(verifier.verify_consensus(&missing_vrf).is_err());

        let invalid_quorum_root = tamper_proof(&proof, |witness| {
            witness.insert(
                "quorum_bitmap_root".into(),
                Value::String("deadbeef".into()),
            );
        });
        assert!(verifier.verify_consensus(&invalid_quorum_root).is_err());

        let tampered_vrf_output = tamper_proof(&proof, |witness| {
            if let Some(Value::Array(entries)) = witness.get_mut("vrf_entries") {
                if let Some(Value::Object(first)) = entries.first_mut() {
                    if let Some(Value::Object(poseidon)) =
                        first.get_mut("poseidon").and_then(Value::as_object_mut)
                    {
                        poseidon.insert("digest".into(), Value::String(digest(0xFF)));
                    }
                }
            }
        });
        assert!(verifier.verify_consensus(&tampered_vrf_output).is_err());

        let tampered_quorum_signature = tamper_proof(&proof, |witness| {
            witness.insert(
                "quorum_signature_root".into(),
                Value::String("11".repeat(32)),
            );
        });
        assert!(verifier
            .verify_consensus(&tampered_quorum_signature)
            .is_err());
    }
}

#[cfg(feature = "prover-stwo")]
mod stwo_backend {
    use super::*;
    use rpp_chain::storage::Storage;
    use rpp_chain::stwo::circuit::consensus::ConsensusWitness;
    use rpp_chain::stwo::proof::ProofPayload;
    use rpp_chain::stwo::prover::WalletProver;
    use rpp_chain::stwo::verifier::NodeVerifier;
    use tempfile::tempdir;

    fn tamper_proof(
        original: &ChainProof,
        mutator: impl FnOnce(&mut ConsensusWitness),
    ) -> ChainProof {
        let mut tampered = original.clone();
        match &mut tampered {
            ChainProof::Stwo(inner) => match &mut inner.payload {
                ProofPayload::Consensus(witness) => mutator(witness),
                _ => panic!("expected consensus witness payload"),
            },
            _ => panic!("expected STWO proof"),
        }
        tampered
    }

    #[test]
    fn stwo_rejects_tampered_consensus_metadata() {
        let temp_dir = tempdir().expect("temporary storage directory");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let prover = WalletProver::new(&storage);
        let verifier = NodeVerifier::new();

        let certificate = sample_certificate();
        let block_hash = certificate.block_hash.0.clone();
        let witness = prover
            .build_consensus_witness(&block_hash, &certificate)
            .expect("build consensus witness");
        let proof = prover.prove_consensus(witness).expect("prove consensus");

        verifier
            .verify_consensus(&proof)
            .expect("baseline consensus proof should verify");

        let missing_vrf = tamper_proof(&proof, |witness| {
            witness.vrf_entries.clear();
        });
        assert!(verifier.verify_consensus(&missing_vrf).is_err());

        let invalid_quorum_root = tamper_proof(&proof, |witness| {
            witness.quorum_bitmap_root = "cafebabe".into();
        });
        assert!(verifier.verify_consensus(&invalid_quorum_root).is_err());

        let tampered_vrf_output = tamper_proof(&proof, |witness| {
            if let Some(first) = witness.vrf_entries.first_mut() {
                first.poseidon.digest = digest(0xEE);
            }
        });
        assert!(verifier.verify_consensus(&tampered_vrf_output).is_err());

        let tampered_quorum_signature = tamper_proof(&proof, |witness| {
            witness.quorum_signature_root = "77".repeat(32);
        });
        assert!(verifier
            .verify_consensus(&tampered_quorum_signature)
            .is_err());
    }
}
