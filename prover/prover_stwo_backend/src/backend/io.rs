#[cfg(feature = "official")]
use crate::official::params::StarkParameters;
#[cfg(feature = "official")]
use crate::official::{
    circuit::{
        consensus::{ConsensusCircuit, ConsensusWitness},
        identity::IdentityWitness,
        pruning::PruningWitness,
        recursive::RecursiveWitness,
        state::StateWitness,
        transaction::TransactionWitness,
        uptime::UptimeWitness,
    },
    proof::{ProofKind, ProofPayload, StarkProof},
};
use prover_backend_interface::{
    BackendError, BackendResult, ProofBytes, ProofHeader, ProofSystemKind, WitnessBytes,
    WitnessHeader, PROOF_FORMAT_VERSION, WITNESS_FORMAT_VERSION,
};

#[cfg(feature = "official")]
const TX_CIRCUIT: &str = "tx";
#[cfg(feature = "official")]
const IDENTITY_CIRCUIT: &str = "identity";
#[cfg(feature = "official")]
const STATE_CIRCUIT: &str = "state";
#[cfg(feature = "official")]
const PRUNING_CIRCUIT: &str = "pruning";
#[cfg(feature = "official")]
const RECURSIVE_CIRCUIT: &str = "recursive";
#[cfg(feature = "official")]
const UPTIME_CIRCUIT: &str = "uptime";
#[cfg(feature = "official")]
const CONSENSUS_CIRCUIT: &str = "consensus";

fn ensure_stwo_backend(system: ProofSystemKind, context: &str) -> BackendResult<()> {
    if system == ProofSystemKind::Stwo {
        Ok(())
    } else {
        Err(BackendError::Failure(format!(
            "expected STWO {context} header, found backend {system:?}"
        )))
    }
}

#[cfg(feature = "official")]
fn ensure_circuit_matches(actual: &str, expected: &str) -> BackendResult<()> {
    let actual_trimmed = actual.trim();
    if actual_trimmed.eq_ignore_ascii_case(expected) {
        return Ok(());
    }
    let actual_lower = actual_trimmed.to_ascii_lowercase();
    let expected_lower = expected.to_ascii_lowercase();
    if actual_lower.starts_with(&format!("{expected_lower}-")) {
        return Ok(());
    }
    Err(BackendError::Failure(format!(
        "unexpected circuit '{actual_trimmed}', expected prefix '{expected}'",
    )))
}

#[cfg(feature = "official")]
fn ensure_witness_header(header: &WitnessHeader, circuit: &str) -> BackendResult<()> {
    if header.version != WITNESS_FORMAT_VERSION {
        return Err(BackendError::Failure(format!(
            "unsupported witness format version {} (expected {})",
            header.version, WITNESS_FORMAT_VERSION
        )));
    }
    ensure_stwo_backend(header.backend, "witness")?;
    ensure_circuit_matches(&header.circuit, circuit)
}

fn ensure_proof_header(header: &ProofHeader, circuit: &str) -> BackendResult<()> {
    if header.version != PROOF_FORMAT_VERSION {
        return Err(BackendError::Failure(format!(
            "unsupported proof format version {} (expected {})",
            header.version, PROOF_FORMAT_VERSION
        )));
    }
    ensure_stwo_backend(header.backend, "proof")?;
    ensure_circuit_matches(&header.circuit, circuit)
}

#[cfg(feature = "official")]
fn ensure_transaction_payload(proof: &StarkProof) -> BackendResult<()> {
    if proof.kind != ProofKind::Transaction {
        return Err(BackendError::Failure(format!(
            "expected transaction proof kind, found {:?}",
            proof.kind
        )));
    }
    if !matches!(&proof.payload, ProofPayload::Transaction(_)) {
        return Err(BackendError::Failure(
            "proof payload does not contain a transaction witness".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "official")]
pub fn decode_tx_witness(witness: &WitnessBytes) -> BackendResult<TransactionWitness> {
    let (header, witness) = witness.decode::<TransactionWitness>()?;
    ensure_witness_header(&header, TX_CIRCUIT)?;
    Ok(witness)
}

#[cfg(feature = "official")]
pub fn decode_tx_proof(proof: &ProofBytes) -> BackendResult<StarkProof> {
    let (header, proof) = proof.decode::<StarkProof>()?;
    ensure_proof_header(&header, TX_CIRCUIT)?;
    ensure_transaction_payload(&proof)?;
    Ok(proof)
}

#[cfg(feature = "official")]
pub fn encode_tx_proof(proof: &StarkProof) -> BackendResult<ProofBytes> {
    ensure_transaction_payload(proof)?;
    let header = ProofHeader::new(ProofSystemKind::Stwo, TX_CIRCUIT);
    ProofBytes::encode(&header, proof)
}

#[cfg(feature = "official")]
fn ensure_identity_payload(proof: &StarkProof) -> BackendResult<()> {
    if proof.kind != ProofKind::Identity {
        return Err(BackendError::Failure(format!(
            "expected identity proof kind, found {:?}",
            proof.kind
        )));
    }
    if !matches!(&proof.payload, ProofPayload::Identity(_)) {
        return Err(BackendError::Failure(
            "proof payload does not contain an identity witness".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "official")]
fn ensure_state_payload(proof: &StarkProof) -> BackendResult<()> {
    if proof.kind != ProofKind::State {
        return Err(BackendError::Failure(format!(
            "expected state proof kind, found {:?}",
            proof.kind
        )));
    }
    if !matches!(&proof.payload, ProofPayload::State(_)) {
        return Err(BackendError::Failure(
            "proof payload does not contain a state witness".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "official")]
fn ensure_pruning_payload(proof: &StarkProof) -> BackendResult<()> {
    if proof.kind != ProofKind::Pruning {
        return Err(BackendError::Failure(format!(
            "expected pruning proof kind, found {:?}",
            proof.kind
        )));
    }
    if !matches!(&proof.payload, ProofPayload::Pruning(_)) {
        return Err(BackendError::Failure(
            "proof payload does not contain a pruning witness".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "official")]
fn ensure_recursive_payload(proof: &StarkProof) -> BackendResult<()> {
    if proof.kind != ProofKind::Recursive {
        return Err(BackendError::Failure(format!(
            "expected recursive proof kind, found {:?}",
            proof.kind
        )));
    }
    if !matches!(&proof.payload, ProofPayload::Recursive(_)) {
        return Err(BackendError::Failure(
            "proof payload does not contain a recursive witness".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "official")]
fn ensure_uptime_payload(proof: &StarkProof) -> BackendResult<()> {
    if proof.kind != ProofKind::Uptime {
        return Err(BackendError::Failure(format!(
            "expected uptime proof kind, found {:?}",
            proof.kind
        )));
    }
    if !matches!(&proof.payload, ProofPayload::Uptime(_)) {
        return Err(BackendError::Failure(
            "proof payload does not contain an uptime witness".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "official")]
fn ensure_consensus_payload(proof: &StarkProof) -> BackendResult<()> {
    if proof.kind != ProofKind::Consensus {
        return Err(BackendError::Failure(format!(
            "expected consensus proof kind, found {:?}",
            proof.kind
        )));
    }
    let witness = match &proof.payload {
        ProofPayload::Consensus(witness) => witness,
        _ => {
            return Err(BackendError::Failure(
                "proof payload does not contain a consensus witness".into(),
            ));
        }
    };
    ensure_consensus_witness_metadata(witness)?;
    let parameters = StarkParameters::blueprint_default();
    let expected_inputs: Vec<_> = ConsensusCircuit::public_inputs(&parameters, witness)
        .into_iter()
        .map(|element| element.to_hex())
        .collect();
    if proof.public_inputs != expected_inputs {
        return Err(BackendError::Failure(
            "consensus public inputs do not match witness metadata".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "official")]
fn ensure_consensus_witness_metadata(witness: &ConsensusWitness) -> BackendResult<()> {
    if witness.vrf_outputs.is_empty() {
        return Err(BackendError::Failure(
            "consensus witness missing VRF outputs".into(),
        ));
    }
    if witness.vrf_proofs.is_empty() {
        return Err(BackendError::Failure(
            "consensus witness missing VRF proofs".into(),
        ));
    }
    if witness.vrf_outputs.len() != witness.vrf_proofs.len() {
        return Err(BackendError::Failure(
            "consensus witness VRF output/proof count mismatch".into(),
        ));
    }
    if witness.witness_commitments.is_empty() {
        return Err(BackendError::Failure(
            "consensus witness missing witness commitments".into(),
        ));
    }
    if witness.reputation_roots.is_empty() {
        return Err(BackendError::Failure(
            "consensus witness missing reputation roots".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "official")]
pub fn decode_identity_witness(witness: &WitnessBytes) -> BackendResult<IdentityWitness> {
    let (header, witness) = witness.decode::<IdentityWitness>()?;
    ensure_witness_header(&header, IDENTITY_CIRCUIT)?;
    Ok(witness)
}

#[cfg(feature = "official")]
pub fn decode_identity_proof(proof: &ProofBytes) -> BackendResult<StarkProof> {
    let (header, proof) = proof.decode::<StarkProof>()?;
    ensure_proof_header(&header, IDENTITY_CIRCUIT)?;
    ensure_identity_payload(&proof)?;
    Ok(proof)
}

#[cfg(feature = "official")]
pub fn encode_identity_proof(proof: &StarkProof) -> BackendResult<ProofBytes> {
    ensure_identity_payload(proof)?;
    let header = ProofHeader::new(ProofSystemKind::Stwo, IDENTITY_CIRCUIT);
    ProofBytes::encode(&header, proof)
}

#[cfg(feature = "official")]
pub fn decode_state_witness(witness: &WitnessBytes) -> BackendResult<StateWitness> {
    let (header, witness) = witness.decode::<StateWitness>()?;
    ensure_witness_header(&header, STATE_CIRCUIT)?;
    Ok(witness)
}

#[cfg(feature = "official")]
pub fn decode_state_proof(proof: &ProofBytes) -> BackendResult<StarkProof> {
    let (header, proof) = proof.decode::<StarkProof>()?;
    ensure_proof_header(&header, STATE_CIRCUIT)?;
    ensure_state_payload(&proof)?;
    Ok(proof)
}

#[cfg(feature = "official")]
pub fn encode_state_proof(proof: &StarkProof) -> BackendResult<ProofBytes> {
    ensure_state_payload(proof)?;
    let header = ProofHeader::new(ProofSystemKind::Stwo, STATE_CIRCUIT);
    ProofBytes::encode(&header, proof)
}

#[cfg(feature = "official")]
pub fn decode_pruning_witness(witness: &WitnessBytes) -> BackendResult<PruningWitness> {
    let (header, witness) = witness.decode::<PruningWitness>()?;
    ensure_witness_header(&header, PRUNING_CIRCUIT)?;
    Ok(witness)
}

#[cfg(feature = "official")]
pub fn decode_pruning_proof(proof: &ProofBytes) -> BackendResult<StarkProof> {
    let (header, proof) = proof.decode::<StarkProof>()?;
    ensure_proof_header(&header, PRUNING_CIRCUIT)?;
    ensure_pruning_payload(&proof)?;
    Ok(proof)
}

#[cfg(feature = "official")]
pub fn encode_pruning_proof(proof: &StarkProof) -> BackendResult<ProofBytes> {
    ensure_pruning_payload(proof)?;
    let header = ProofHeader::new(ProofSystemKind::Stwo, PRUNING_CIRCUIT);
    ProofBytes::encode(&header, proof)
}

#[cfg(feature = "official")]
pub fn decode_recursive_witness(witness: &WitnessBytes) -> BackendResult<RecursiveWitness> {
    let (header, witness) = witness.decode::<RecursiveWitness>()?;
    ensure_witness_header(&header, RECURSIVE_CIRCUIT)?;
    Ok(witness)
}

#[cfg(feature = "official")]
pub fn decode_recursive_proof(proof: &ProofBytes) -> BackendResult<StarkProof> {
    let (header, proof) = proof.decode::<StarkProof>()?;
    ensure_proof_header(&header, RECURSIVE_CIRCUIT)?;
    ensure_recursive_payload(&proof)?;
    Ok(proof)
}

#[cfg(feature = "official")]
pub fn encode_recursive_proof(proof: &StarkProof) -> BackendResult<ProofBytes> {
    ensure_recursive_payload(proof)?;
    let header = ProofHeader::new(ProofSystemKind::Stwo, RECURSIVE_CIRCUIT);
    ProofBytes::encode(&header, proof)
}

#[cfg(feature = "official")]
pub fn decode_uptime_witness(witness: &WitnessBytes) -> BackendResult<UptimeWitness> {
    let (header, witness) = witness.decode::<UptimeWitness>()?;
    ensure_witness_header(&header, UPTIME_CIRCUIT)?;
    Ok(witness)
}

#[cfg(feature = "official")]
pub fn decode_uptime_proof(proof: &ProofBytes) -> BackendResult<StarkProof> {
    let (header, proof) = proof.decode::<StarkProof>()?;
    ensure_proof_header(&header, UPTIME_CIRCUIT)?;
    ensure_uptime_payload(&proof)?;
    Ok(proof)
}

#[cfg(feature = "official")]
pub fn encode_uptime_proof(proof: &StarkProof) -> BackendResult<ProofBytes> {
    ensure_uptime_payload(proof)?;
    let header = ProofHeader::new(ProofSystemKind::Stwo, UPTIME_CIRCUIT);
    ProofBytes::encode(&header, proof)
}

#[cfg(feature = "official")]
pub fn decode_consensus_witness(
    witness: &WitnessBytes,
) -> BackendResult<(WitnessHeader, ConsensusWitness)> {
    let (header, witness) = witness.decode::<ConsensusWitness>()?;
    ensure_witness_header(&header, CONSENSUS_CIRCUIT)?;
    ensure_consensus_witness_metadata(&witness)?;
    Ok((header, witness))
}

#[cfg(feature = "official")]
pub fn decode_consensus_proof(proof: &ProofBytes) -> BackendResult<(ProofHeader, StarkProof)> {
    let (header, proof) = proof.decode::<StarkProof>()?;
    ensure_proof_header(&header, CONSENSUS_CIRCUIT)?;
    ensure_consensus_payload(&proof)?;
    Ok((header, proof))
}

#[cfg(feature = "official")]
pub fn encode_consensus_proof(circuit: &str, proof: &StarkProof) -> BackendResult<ProofBytes> {
    ensure_consensus_payload(proof)?;
    let header = ProofHeader::new(ProofSystemKind::Stwo, circuit);
    ProofBytes::encode(&header, proof)
}

#[cfg(all(test, feature = "official"))]
mod tests {
    use super::*;
    use crate::official::circuit::consensus::VotePower;
    use crate::official::circuit::{ExecutionTrace, TraceSegment};
    use crate::official::params::FieldElement;
    use crate::vrf::VRF_PROOF_LENGTH;
    use prover_backend_interface::{ProofHeader, WitnessBytes, WitnessHeader};

    #[test]
    fn rejects_non_stwo_witness_headers() {
        let header = WitnessHeader {
            version: WITNESS_FORMAT_VERSION,
            backend: ProofSystemKind::Mock,
            circuit: "tx".into(),
        };
        let result = ensure_witness_header(&header, "tx");
        assert!(matches!(result, Err(BackendError::Failure(message)) if message.contains("STWO")));
    }

    #[test]
    fn rejects_non_stwo_proof_headers() {
        let header = ProofHeader {
            version: PROOF_FORMAT_VERSION,
            backend: ProofSystemKind::Mock,
            circuit: "tx".into(),
        };
        let result = ensure_proof_header(&header, "tx");
        assert!(matches!(result, Err(BackendError::Failure(message)) if message.contains("STWO")));
    }

    #[test]
    fn rejects_future_witness_versions() {
        let header = WitnessHeader {
            version: WITNESS_FORMAT_VERSION + 1,
            backend: ProofSystemKind::Stwo,
            circuit: "tx".into(),
        };
        let result = ensure_witness_header(&header, "tx");
        assert!(
            matches!(result, Err(BackendError::Failure(message)) if message.contains("unsupported witness format version"))
        );
    }

    #[test]
    fn rejects_future_proof_versions() {
        let header = ProofHeader {
            version: PROOF_FORMAT_VERSION + 1,
            backend: ProofSystemKind::Stwo,
            circuit: "tx".into(),
        };
        let result = ensure_proof_header(&header, "tx");
        assert!(
            matches!(result, Err(BackendError::Failure(message)) if message.contains("unsupported proof format version"))
        );
    }

    fn sample_consensus_witness() -> ConsensusWitness {
        let vote = VotePower {
            voter: "validator".into(),
            weight: 1,
        };
        ConsensusWitness {
            block_hash: "11".repeat(32),
            round: 1,
            epoch: 0,
            slot: 1,
            leader_proposal: "11".repeat(32),
            quorum_threshold: 1,
            pre_votes: vec![vote.clone()],
            pre_commits: vec![vote.clone()],
            commit_votes: vec![vote],
            quorum_bitmap_root: "22".repeat(32),
            quorum_signature_root: "33".repeat(32),
            vrf_outputs: vec!["44".repeat(32)],
            vrf_proofs: vec!["55".repeat(VRF_PROOF_LENGTH)],
            witness_commitments: vec!["66".repeat(32)],
            reputation_roots: vec!["77".repeat(32)],
        }
    }

    fn dummy_trace(parameters: &StarkParameters) -> ExecutionTrace {
        let zero = FieldElement::zero(parameters.modulus());
        let segment = TraceSegment::new("dummy", vec!["value".into()], vec![vec![zero]])
            .expect("dummy segment");
        ExecutionTrace::from_segments(vec![segment]).expect("dummy trace")
    }

    #[test]
    fn decode_consensus_witness_rejects_missing_metadata() {
        let mut witness = sample_consensus_witness();
        witness.vrf_outputs.clear();
        let bytes = WitnessBytes::encode(
            &WitnessHeader::new(ProofSystemKind::Stwo, CONSENSUS_CIRCUIT),
            &witness,
        )
        .expect("encode witness");
        let result = decode_consensus_witness(&bytes);
        assert!(
            matches!(result, Err(BackendError::Failure(message)) if message.contains("missing VRF outputs"))
        );
    }

    #[test]
    fn consensus_payload_rejects_public_input_mismatch() {
        let parameters = StarkParameters::blueprint_default();
        let witness = sample_consensus_witness();
        let public_inputs: Vec<_> = ConsensusCircuit::public_inputs(&parameters, &witness)
            .into_iter()
            .map(|value| value.to_hex())
            .collect();
        let trace = dummy_trace(&parameters);
        let mut proof = StarkProof {
            kind: ProofKind::Consensus,
            commitment: String::new(),
            public_inputs,
            payload: ProofPayload::Consensus(witness.clone()),
            trace: trace.clone(),
            commitment_proof: Default::default(),
            fri_proof: Default::default(),
        };

        ensure_consensus_payload(&proof).expect("valid consensus payload");

        let mut tampered = proof.clone();
        tampered
            .public_inputs
            .last_mut()
            .expect("consensus inputs present")
            .clear();
        let result = ensure_consensus_payload(&tampered);
        assert!(
            matches!(result, Err(BackendError::Failure(message)) if message.contains("public inputs"))
        );

        // Ensure the witness metadata is also validated independently of inputs.
        let mut broken = proof;
        if let ProofPayload::Consensus(inner) = &mut broken.payload {
            inner.reputation_roots.clear();
        }
        let result = ensure_consensus_payload(&broken);
        assert!(
            matches!(result, Err(BackendError::Failure(message)) if message.contains("missing reputation roots"))
        );
    }

    #[test]
    fn pruning_witness_roundtrips_prefixed_digests() {
        use crate::official::circuit::pruning::PruningWitness;
        use rpp_pruning::{TaggedDigest, DIGEST_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG};

        let witness = PruningWitness {
            previous_tx_root: "aa".repeat(32),
            pruned_tx_root: "bb".repeat(32),
            original_transactions: vec!["cc".repeat(32)],
            removed_transactions: vec!["cc".repeat(32)],
            pruning_binding_digest: TaggedDigest::new(ENVELOPE_TAG, [0x11; DIGEST_LENGTH])
                .prefixed_bytes(),
            pruning_segment_commitments: vec![TaggedDigest::new(
                PROOF_SEGMENT_TAG,
                [0x22; DIGEST_LENGTH],
            )
            .prefixed_bytes()],
            pruning_fold: "dd".repeat(32),
        };

        let bytes = WitnessBytes::encode(
            &WitnessHeader::new(ProofSystemKind::Stwo, "pruning"),
            &witness,
        )
        .expect("encode pruning witness");
        let (_, decoded) = bytes
            .decode::<PruningWitness>()
            .expect("decode pruning witness");

        assert_eq!(
            decoded.pruning_binding_digest,
            witness.pruning_binding_digest
        );
        assert_eq!(
            decoded.pruning_segment_commitments,
            witness.pruning_segment_commitments
        );
    }

    #[test]
    fn recursive_witness_roundtrips_prefixed_digests() {
        use crate::official::circuit::recursive::RecursiveWitness;
        use rpp_pruning::{TaggedDigest, DIGEST_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG};

        let witness = RecursiveWitness {
            previous_commitment: Some("11".repeat(32)),
            aggregated_commitment: "22".repeat(32),
            identity_commitments: vec!["33".repeat(32)],
            tx_commitments: vec!["44".repeat(32)],
            uptime_commitments: vec!["55".repeat(32)],
            consensus_commitments: vec!["66".repeat(32)],
            state_commitment: "77".repeat(32),
            global_state_root: "88".repeat(32),
            utxo_root: "99".repeat(32),
            reputation_root: "aa".repeat(32),
            timetoke_root: "bb".repeat(32),
            zsi_root: "cc".repeat(32),
            proof_root: "dd".repeat(32),
            pruning_binding_digest: TaggedDigest::new(ENVELOPE_TAG, [0x33; DIGEST_LENGTH])
                .prefixed_bytes(),
            pruning_segment_commitments: vec![
                TaggedDigest::new(PROOF_SEGMENT_TAG, [0x44; DIGEST_LENGTH]).prefixed_bytes(),
                TaggedDigest::new(PROOF_SEGMENT_TAG, [0x55; DIGEST_LENGTH]).prefixed_bytes(),
            ],
            block_height: 42,
        };

        let bytes = WitnessBytes::encode(
            &WitnessHeader::new(ProofSystemKind::Stwo, "recursive"),
            &witness,
        )
        .expect("encode recursive witness");
        let (_, decoded) = bytes
            .decode::<RecursiveWitness>()
            .expect("decode recursive witness");

        assert_eq!(
            decoded.pruning_binding_digest,
            witness.pruning_binding_digest
        );
        assert_eq!(
            decoded.pruning_segment_commitments,
            witness.pruning_segment_commitments
        );
    }
}
