use prover_backend_interface::{
    BackendResult, ConsensusCircuitDef, ConsensusPublicInputs, ConsensusVerifyingKeyMetadata,
    ProofBackend, ProofBytes, ProofHeader, ProofSystemKind, ProvingKey, SecurityLevel,
    TxCircuitDef, TxPublicInputs, VerifyingKey, WitnessBytes, WitnessHeader,
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

    fn keygen_consensus(
        &self,
        circuit: &ConsensusCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey, ConsensusVerifyingKeyMetadata)> {
        let tag = format!("mock-consensus-keygen::{}", circuit.identifier);
        let proving_key = ProvingKey(tag.as_bytes().to_vec());
        let verifying_key = VerifyingKey(tag.clone().into_bytes());
        let metadata = ConsensusVerifyingKeyMetadata::new(tag, verifying_key.as_slice());
        Ok((proving_key, verifying_key, metadata))
    }

    fn prove_consensus(
        &self,
        pk: &ProvingKey,
        witness: &WitnessBytes,
    ) -> BackendResult<(ProofBytes, ConsensusVerifyingKeyMetadata)> {
        let header = ProofHeader::new(ProofSystemKind::Mock, "consensus");
        let witness_header = WitnessHeader::new(ProofSystemKind::Mock, "consensus");
        let proof = MockProof {
            header,
            witness_header,
            payload: [pk.as_slice(), witness.as_slice()].concat(),
        };
        let bytes = bincode::serialize(&proof)?;
        let tag = String::from_utf8_lossy(pk.as_slice()).to_string();
        let metadata = ConsensusVerifyingKeyMetadata::new(tag, pk.as_slice());
        Ok((ProofBytes(bytes), metadata))
    }

    fn verify_consensus(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        _public_inputs: &ConsensusPublicInputs,
    ) -> BackendResult<(bool, ConsensusVerifyingKeyMetadata)> {
        let decoded: MockProof = bincode::deserialize(proof.as_slice())?;
        let expected = ProofHeader::new(ProofSystemKind::Mock, "consensus");
        let prefix_matches = decoded
            .payload
            .get(..vk.as_slice().len())
            .map(|slice| slice == vk.as_slice())
            .unwrap_or(false);
        let valid = decoded.header == expected
            && decoded.witness_header.backend == ProofSystemKind::Mock
            && prefix_matches;
        let tag = String::from_utf8_lossy(vk.as_slice()).to_string();
        let metadata = ConsensusVerifyingKeyMetadata::new(tag, vk.as_slice());
        Ok((valid, metadata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prover_backend_interface::{
        ConsensusCircuitDef, ConsensusPublicInputs, ProofSystemKind, WitnessHeader,
    };

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

        let consensus_circuit = ConsensusCircuitDef::new("consensus.demo");
        let (cons_pk, cons_vk, metadata) = backend.keygen_consensus(&consensus_circuit).unwrap();
        assert_eq!(
            metadata.circuit,
            format!("mock-consensus-keygen::{}", consensus_circuit.identifier)
        );
        let consensus_witness_header = WitnessHeader::new(ProofSystemKind::Mock, "consensus");
        let consensus_witness = WitnessBytes::encode(&consensus_witness_header, &13u64).unwrap();
        let (cons_proof, prove_meta) = backend
            .prove_consensus(&cons_pk, &consensus_witness)
            .unwrap();
        assert_eq!(prove_meta.verifying_key_hash, metadata.verifying_key_hash);
        assert_eq!(prove_meta.circuit, metadata.circuit);
        let (valid, verify_meta) = backend
            .verify_consensus(
                &cons_vk,
                &cons_proof,
                &ConsensusPublicInputs {
                    block_hash: [0u8; 32],
                    round: 0,
                    leader_proposal: [0u8; 32],
                    quorum_threshold: 0,
                },
            )
            .unwrap();
        assert!(valid);
        assert_eq!(verify_meta.verifying_key_hash, metadata.verifying_key_hash);
        assert_eq!(verify_meta.circuit, metadata.circuit);
    }
}
