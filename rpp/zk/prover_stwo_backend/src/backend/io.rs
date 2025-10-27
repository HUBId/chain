#[cfg(feature = "official")]
use crate::official::{
    circuit::{
        consensus::ConsensusWitness, identity::IdentityWitness, pruning::PruningWitness,
        recursive::RecursiveWitness, state::StateWitness, transaction::TransactionWitness,
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
    if !matches!(&proof.payload, ProofPayload::Consensus(_)) {
        return Err(BackendError::Failure(
            "proof payload does not contain a consensus witness".into(),
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
    use prover_backend_interface::{ProofHeader, WitnessHeader};

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
