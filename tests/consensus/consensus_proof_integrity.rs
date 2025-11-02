use libp2p::PeerId;
use rpp_chain::consensus::{ConsensusCertificate, ConsensusProofMetadata};
use rpp_chain::consensus_engine::messages::{BlockId, TalliedVote};
use rpp_chain::proof_system::{ProofProver, ProofVerifier};
use rpp_chain::types::ChainProof;
use rpp_chain::vrf::VRF_PROOF_LENGTH;

fn sample_metadata() -> ConsensusProofMetadata {
    let digest = |byte: u8| hex::encode([byte; 32]);
    let proof_bytes = |byte: u8| hex::encode(vec![byte; VRF_PROOF_LENGTH]);

    ConsensusProofMetadata {
        vrf_outputs: vec![digest(0x11), digest(0x12)],
        vrf_proofs: vec![proof_bytes(0x21), proof_bytes(0x22)],
        witness_commitments: vec![digest(0x33)],
        reputation_roots: vec![digest(0x44), digest(0x45)],
        epoch: 5,
        slot: 7,
        quorum_bitmap_root: digest(0x55),
        quorum_signature_root: digest(0x66),
    }
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
    use rpp_chain::plonky3::proof::Plonky3Proof;
    use rpp_chain::plonky3::prover::Plonky3Prover;
    use rpp_chain::plonky3::verifier::Plonky3Verifier;
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
            witness.insert("vrf_outputs".into(), Value::Array(Vec::new()));
            witness.insert("vrf_proofs".into(), Value::Array(Vec::new()));
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
            if let Some(Value::Array(outputs)) = witness.get_mut("vrf_outputs") {
                if let Some(first) = outputs.first_mut() {
                    *first = Value::String("ff".repeat(32));
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
            witness.vrf_outputs.clear();
            witness.vrf_proofs.clear();
        });
        assert!(verifier.verify_consensus(&missing_vrf).is_err());

        let invalid_quorum_root = tamper_proof(&proof, |witness| {
            witness.quorum_bitmap_root = "cafebabe".into();
        });
        assert!(verifier.verify_consensus(&invalid_quorum_root).is_err());

        let tampered_vrf_output = tamper_proof(&proof, |witness| {
            if let Some(first) = witness.vrf_outputs.first_mut() {
                *first = "ee".repeat(32);
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
