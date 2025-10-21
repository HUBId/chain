#[cfg(feature = "official")]
use crate::official::{
    circuit::{consensus::ConsensusWitness, transaction::TransactionWitness},
    proof::{ProofKind, ProofPayload, StarkProof},
};
use prover_backend_interface::{
    BackendError, BackendResult, ProofBytes, ProofHeader, ProofSystemKind, WitnessBytes,
    WitnessHeader, PROOF_FORMAT_VERSION, WITNESS_FORMAT_VERSION,
};

#[cfg(feature = "official")]
const TX_CIRCUIT: &str = "tx";
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

fn ensure_witness_header(header: &WitnessHeader) -> BackendResult<()> {
    if header.version != WITNESS_FORMAT_VERSION {
        return Err(BackendError::Failure(format!(
            "unsupported witness format version {} (expected {})",
            header.version, WITNESS_FORMAT_VERSION
        )));
    }
    ensure_stwo_backend(header.backend, "witness")
}

fn ensure_proof_header(header: &ProofHeader) -> BackendResult<()> {
    if header.version != PROOF_FORMAT_VERSION {
        return Err(BackendError::Failure(format!(
            "unsupported proof format version {} (expected {})",
            header.version, PROOF_FORMAT_VERSION
        )));
    }
    ensure_stwo_backend(header.backend, "proof")
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
    ensure_witness_header(&header)?;
    Ok(witness)
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
pub fn decode_consensus_witness(witness: &WitnessBytes) -> BackendResult<ConsensusWitness> {
    let (header, witness) = witness.decode::<ConsensusWitness>()?;
    ensure_witness_header(&header)?;
    if header.circuit != CONSENSUS_CIRCUIT {
        return Err(BackendError::Failure(format!(
            "unexpected consensus witness circuit '{}', expected '{}'",
            header.circuit, CONSENSUS_CIRCUIT
        )));
    }
    Ok(witness)
}

#[cfg(feature = "official")]
pub fn decode_tx_proof(proof: &ProofBytes) -> BackendResult<StarkProof> {
    let (header, proof) = proof.decode::<StarkProof>()?;
    ensure_proof_header(&header)?;
    ensure_transaction_payload(&proof)?;
    Ok(proof)
}

#[cfg(feature = "official")]
pub fn decode_consensus_proof(proof: &ProofBytes) -> BackendResult<StarkProof> {
    let (header, proof) = proof.decode::<StarkProof>()?;
    ensure_proof_header(&header)?;
    if header.circuit != CONSENSUS_CIRCUIT {
        return Err(BackendError::Failure(format!(
            "unexpected consensus proof circuit '{}', expected '{}'",
            header.circuit, CONSENSUS_CIRCUIT
        )));
    }
    ensure_consensus_payload(&proof)?;
    Ok(proof)
}

#[cfg(feature = "official")]
pub fn encode_tx_proof(proof: &StarkProof) -> BackendResult<ProofBytes> {
    ensure_transaction_payload(proof)?;
    let header = ProofHeader::new(ProofSystemKind::Stwo, TX_CIRCUIT);
    ProofBytes::encode(&header, proof)
}

#[cfg(feature = "official")]
pub fn encode_consensus_proof(proof: &StarkProof) -> BackendResult<ProofBytes> {
    ensure_consensus_payload(proof)?;
    let header = ProofHeader::new(ProofSystemKind::Stwo, CONSENSUS_CIRCUIT);
    ProofBytes::encode(&header, proof)
}

#[cfg(test)]
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
        let result = ensure_witness_header(&header);
        assert!(matches!(result, Err(BackendError::Failure(message)) if message.contains("STWO")));
    }

    #[test]
    fn rejects_non_stwo_proof_headers() {
        let header = ProofHeader {
            version: PROOF_FORMAT_VERSION,
            backend: ProofSystemKind::Mock,
            circuit: "tx".into(),
        };
        let result = ensure_proof_header(&header);
        assert!(matches!(result, Err(BackendError::Failure(message)) if message.contains("STWO")));
    }

    #[test]
    fn rejects_future_witness_versions() {
        let header = WitnessHeader {
            version: WITNESS_FORMAT_VERSION + 1,
            backend: ProofSystemKind::Stwo,
            circuit: "tx".into(),
        };
        let result = ensure_witness_header(&header);
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
        let result = ensure_proof_header(&header);
        assert!(
            matches!(result, Err(BackendError::Failure(message)) if message.contains("unsupported proof format version"))
        );
    }
}
