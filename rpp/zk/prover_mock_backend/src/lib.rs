use prover_backend_interface::{
    BackendError, BackendResult, ConsensusCircuitDef, ConsensusPublicInputs, ProofBackend,
    ProofBytes, ProofHeader, ProofSystemKind, ProvingKey, SecurityLevel, TxCircuitDef,
    TxPublicInputs, VerifyingKey, WitnessBytes, WitnessHeader,
};
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "prover-stwo", feature = "prover-mock"))]
compile_error!("features `prover-stwo` and `prover-mock` are mutually exclusive");

/// Lightweight mock backend that records inputs and produces deterministic
/// placeholder artifacts for development and testing on stable toolchains.
#[derive(Default)]
pub struct MockBackend;

impl MockBackend {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MockProof {
    pub header: ProofHeader,
    pub witness_header: WitnessHeader,
    pub payload: Vec<u8>,
}

impl ProofBackend for MockBackend {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn setup_params(&self, _security: SecurityLevel) -> BackendResult<()> {
        Ok(())
    }

    fn keygen_tx(&self, circuit: &TxCircuitDef) -> BackendResult<(ProvingKey, VerifyingKey)> {
        let tag = format!("mock-keygen::{}", circuit.identifier);
        Ok((
            ProvingKey(tag.as_bytes().to_vec()),
            VerifyingKey(tag.into_bytes()),
        ))
    }

    fn prove_tx(&self, pk: &ProvingKey, witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        let proof = MockProof {
            header: ProofHeader::new(ProofSystemKind::Mock, "tx"),
            witness_header: WitnessHeader::new(ProofSystemKind::Mock, "tx"),
            payload: [pk.as_slice(), witness.as_slice()].concat(),
        };
        let bytes = bincode::serialize(&proof)?;
        Ok(ProofBytes(bytes))
    }

    fn verify_tx(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        _public_inputs: &TxPublicInputs,
    ) -> BackendResult<bool> {
        let decoded: MockProof = bincode::deserialize(proof.as_slice())?;
        let expected = ProofHeader::new(ProofSystemKind::Mock, "tx");
        let prefix_matches = decoded
            .payload
            .get(..vk.as_slice().len())
            .map(|slice| slice == vk.as_slice())
            .unwrap_or(false);
        Ok(decoded.header == expected
            && decoded.witness_header.backend == ProofSystemKind::Mock
            && prefix_matches)
    }

    fn verify_consensus(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        circuit: &ConsensusCircuitDef,
        _public_inputs: &ConsensusPublicInputs,
    ) -> BackendResult<()> {
        if circuit.identifier.trim().is_empty() {
            return Err(BackendError::Failure(
                "consensus circuit identifier cannot be empty".into(),
            ));
        }
        if proof.as_slice().is_empty() {
            return Err(BackendError::Failure(
                "consensus proof payload empty".into(),
            ));
        }
        if vk.as_slice().is_empty() {
            return Err(BackendError::Failure(
                "consensus verifying key empty".into(),
            ));
        }
        Ok(())
    }

    fn prove_consensus(
        &self,
        witness: &WitnessBytes,
    ) -> BackendResult<(ProofBytes, VerifyingKey, ConsensusCircuitDef)> {
        let digest = blake3::hash(witness.as_slice());
        let identifier = format!("mock.consensus.{}", digest.to_hex());
        let circuit = ConsensusCircuitDef::new(identifier.clone());
        let header = ProofHeader::new(ProofSystemKind::Mock, identifier.clone());
        let proof = ProofBytes::encode(&header, witness)?;
        let verifying_key = VerifyingKey(identifier.into_bytes());
        Ok((proof, verifying_key, circuit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prover_backend_interface::{ProofSystemKind, WitnessHeader};

    #[test]
    fn mock_backend_roundtrip() {
        let backend = MockBackend::new();
        backend.setup_params(SecurityLevel::Standard128).unwrap();
        let circuit = TxCircuitDef::new("tx.demo");
        let (pk, vk) = backend.keygen_tx(&circuit).unwrap();
        let witness_header = WitnessHeader::new(ProofSystemKind::Mock, "tx");
        let witness = WitnessBytes::encode(&witness_header, &42u64).unwrap();
        let proof = backend.prove_tx(&pk, &witness).unwrap();
        assert!(backend
            .verify_tx(
                &vk,
                &proof,
                &TxPublicInputs {
                    utxo_root: [0u8; 32],
                    transaction_commitment: [0u8; 32],
                }
            )
            .unwrap());
    }
}
