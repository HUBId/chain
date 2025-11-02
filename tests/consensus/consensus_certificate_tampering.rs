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
        vrf_outputs: vec![digest(0xAA), digest(0xBB), digest(0xCC)],
        vrf_proofs: vec![proof_bytes(0x11), proof_bytes(0x22), proof_bytes(0x33)],
        witness_commitments: vec![digest(0xDD)],
        reputation_roots: vec![digest(0xEE)],
        epoch: 17,
        slot: 29,
        quorum_bitmap_root: digest(0xF1),
        quorum_signature_root: digest(0xF2),
    }
}

fn sample_vote(validator: &str, voting_power: u64) -> TalliedVote {
    TalliedVote {
        validator_id: validator.to_string(),
        peer_id: PeerId::random(),
        signature: vec![0x44, 0x55, 0x66],
        voting_power,
    }
}

fn sample_certificate() -> ConsensusCertificate {
    let metadata = sample_metadata();
    let prevote = sample_vote("validator-1", 60);
    let precommit = sample_vote("validator-2", 60);
    let block_hash = BlockId("AA".repeat(32));

    ConsensusCertificate {
        block_hash,
        height: 99,
        round: 2,
        total_power: 100,
        quorum_threshold: 67,
        prevote_power: 60,
        precommit_power: 60,
        commit_power: 60,
        prevotes: vec![prevote.clone()],
        precommits: vec![precommit],
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
            other => panic!("expected Plonky3 proof, got {other:?}"),
        }
        tampered
    }

    #[test]
    fn plonky3_rejects_twisted_certificate_fields() {
        let prover = Plonky3Prover::new();
        let verifier = Plonky3Verifier::default();

        let certificate = sample_certificate();
        let block_hash = certificate.block_hash.0.clone();
        let witness = prover
            .build_consensus_witness(&block_hash, &certificate)
            .expect("build consensus witness");
        let proof = prover
            .prove_consensus(witness)
            .expect("produce baseline consensus proof");

        verifier
            .verify_consensus(&proof)
            .expect("baseline consensus proof should verify");

        let twisted_vrf_outputs = tamper_proof(&proof, |witness| {
            if let Some(Value::Array(outputs)) = witness.get_mut("vrf_outputs") {
                if outputs.len() > 1 {
                    outputs.rotate_left(1);
                }
            }
        });
        assert!(verifier.verify_consensus(&twisted_vrf_outputs).is_err());

        let scrambled_quorum_bitmap = tamper_proof(&proof, |witness| {
            if let Some(Value::String(root)) = witness.get_mut("quorum_bitmap_root") {
                let mut chars: Vec<_> = root.chars().collect();
                chars.rotate_left(2);
                *root = chars.into_iter().collect();
            }
        });
        assert!(verifier.verify_consensus(&scrambled_quorum_bitmap).is_err());

        let reversed_signature_root = tamper_proof(&proof, |witness| {
            if let Some(Value::String(root)) = witness.get_mut("quorum_signature_root") {
                *root = root.chars().rev().collect();
            }
        });
        assert!(verifier.verify_consensus(&reversed_signature_root).is_err());
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
                other => panic!("expected consensus witness payload, got {other:?}"),
            },
            other => panic!("expected STWO proof, got {other:?}"),
        }
        tampered
    }

    #[test]
    fn stwo_rejects_twisted_certificate_fields() {
        let temp_dir = tempdir().expect("temporary storage directory");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let prover = WalletProver::new(&storage);
        let verifier = NodeVerifier::new();

        let certificate = sample_certificate();
        let block_hash = certificate.block_hash.0.clone();
        let witness = prover
            .build_consensus_witness(&block_hash, &certificate)
            .expect("build consensus witness");
        let proof = prover
            .prove_consensus(witness)
            .expect("produce baseline consensus proof");

        verifier
            .verify_consensus(&proof)
            .expect("baseline consensus proof should verify");

        let twisted_vrf_outputs = tamper_proof(&proof, |witness| {
            if witness.vrf_outputs.len() > 1 {
                witness.vrf_outputs.rotate_left(1);
            }
        });
        assert!(verifier.verify_consensus(&twisted_vrf_outputs).is_err());

        let scrambled_quorum_bitmap = tamper_proof(&proof, |witness| {
            witness.quorum_bitmap_root = witness
                .quorum_bitmap_root
                .chars()
                .cycle()
                .skip(4)
                .take(witness.quorum_bitmap_root.len())
                .collect();
        });
        assert!(verifier.verify_consensus(&scrambled_quorum_bitmap).is_err());

        let reversed_signature_root = tamper_proof(&proof, |witness| {
            witness.quorum_signature_root = witness.quorum_signature_root.chars().rev().collect();
        });
        assert!(verifier.verify_consensus(&reversed_signature_root).is_err());
    }
}
