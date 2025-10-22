#[cfg(feature = "official")]
mod io;
#[cfg(feature = "official")]
mod keys;

#[cfg(feature = "official")]
pub use io::{
    decode_consensus_proof, decode_consensus_witness, decode_identity_proof,
    decode_identity_witness, decode_pruning_proof, decode_pruning_witness, decode_recursive_proof,
    decode_recursive_witness, decode_state_proof, decode_state_witness, decode_tx_proof,
    decode_tx_witness, decode_uptime_proof, decode_uptime_witness, encode_consensus_proof,
    encode_identity_proof, encode_pruning_proof, encode_recursive_proof, encode_state_proof,
    encode_tx_proof, encode_uptime_proof,
};

use prover_backend_interface::{
    BackendError, BackendResult, ConsensusCircuitDef, ConsensusPublicInputs, IdentityCircuitDef,
    IdentityPublicInputs, ProofBackend, ProofBytes, ProvingKey, PruningCircuitDef,
    PruningPublicInputs, RecursiveCircuitDef, RecursivePublicInputs, SecurityLevel,
    StateCircuitDef, StatePublicInputs, TxCircuitDef, TxPublicInputs, UptimeCircuitDef,
    UptimePublicInputs, VerifyingKey, WitnessBytes,
};

#[cfg(feature = "official")]
use crate::official::params::{FieldElement, StarkParameters};
#[cfg(feature = "official")]
use crate::official::verifier::NodeVerifier;
#[cfg(feature = "official")]
use crate::proof_system::ProofVerifier;
#[cfg(feature = "official")]
use crate::types::ChainProof;
#[cfg(feature = "official")]
use keys::{decode_key_payload, encode_key_payload, KeyPayload, SupportedCircuit};

/// Thin adapter exposing the STWO integration through the shared backend
/// interface.  The concrete proving routines are wired in lazily to keep the
/// nightly-only dependencies isolated from stable crates.
#[derive(Debug, Default)]
pub struct StwoBackend;

impl StwoBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ProofBackend for StwoBackend {
    fn name(&self) -> &'static str {
        "stwo"
    }

    fn setup_params(&self, _security: SecurityLevel) -> BackendResult<()> {
        Ok(())
    }

    fn keygen_tx(&self, circuit: &TxCircuitDef) -> BackendResult<(ProvingKey, VerifyingKey)> {
        #[cfg(feature = "official")]
        {
            return keygen_for_circuit(&circuit.identifier, SupportedCircuit::Transaction);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = circuit;
            Err(BackendError::Unsupported("transaction keygen"))
        }
    }

    fn keygen_identity(
        &self,
        circuit: &IdentityCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        #[cfg(feature = "official")]
        {
            return keygen_for_circuit(&circuit.identifier, SupportedCircuit::Identity);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = circuit;
            Err(BackendError::Unsupported("identity keygen"))
        }
    }

    fn keygen_state(&self, circuit: &StateCircuitDef) -> BackendResult<(ProvingKey, VerifyingKey)> {
        #[cfg(feature = "official")]
        {
            return keygen_for_circuit(&circuit.identifier, SupportedCircuit::State);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = circuit;
            Err(BackendError::Unsupported("state keygen"))
        }
    }

    fn keygen_pruning(
        &self,
        circuit: &PruningCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        #[cfg(feature = "official")]
        {
            return keygen_for_circuit(&circuit.identifier, SupportedCircuit::Pruning);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = circuit;
            Err(BackendError::Unsupported("pruning keygen"))
        }
    }

    fn keygen_recursive(
        &self,
        circuit: &RecursiveCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        #[cfg(feature = "official")]
        {
            return keygen_for_circuit(&circuit.identifier, SupportedCircuit::Recursive);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = circuit;
            Err(BackendError::Unsupported("recursive keygen"))
        }
    }

    fn keygen_uptime(
        &self,
        circuit: &UptimeCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        #[cfg(feature = "official")]
        {
            return keygen_for_circuit(&circuit.identifier, SupportedCircuit::Uptime);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = circuit;
            Err(BackendError::Unsupported("uptime keygen"))
        }
    }

    fn prove_tx(&self, pk: &ProvingKey, witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(pk.as_slice(), SupportedCircuit::Transaction)?;
            let witness = decode_tx_witness(witness)?;
            let prover = crate::official::prover::WalletProver::new(payload.parameters.clone());
            let proof = prover
                .prove_transaction_witness(witness)
                .map_err(|err| BackendError::Failure(err.to_string()))?;
            return encode_tx_proof(&proof);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (pk, witness);
            Err(BackendError::Unsupported("transaction proving"))
        }
    }

    fn prove_identity(&self, pk: &ProvingKey, witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(pk.as_slice(), SupportedCircuit::Identity)?;
            let witness = decode_identity_witness(witness)?;
            let prover = crate::official::prover::WalletProver::new(payload.parameters.clone());
            let proof = prover
                .prove_identity_witness(witness)
                .map_err(|err| BackendError::Failure(err.to_string()))?;
            return encode_identity_proof(&proof);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (pk, witness);
            Err(BackendError::Unsupported("identity proving"))
        }
    }

    fn prove_state(&self, pk: &ProvingKey, witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(pk.as_slice(), SupportedCircuit::State)?;
            let witness = decode_state_witness(witness)?;
            let prover = crate::official::prover::WalletProver::new(payload.parameters.clone());
            let proof = prover
                .prove_state_witness(witness)
                .map_err(|err| BackendError::Failure(err.to_string()))?;
            return encode_state_proof(&proof);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (pk, witness);
            Err(BackendError::Unsupported("state proving"))
        }
    }

    fn prove_pruning(&self, pk: &ProvingKey, witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(pk.as_slice(), SupportedCircuit::Pruning)?;
            let witness = decode_pruning_witness(witness)?;
            let prover = crate::official::prover::WalletProver::new(payload.parameters.clone());
            let proof = prover
                .prove_pruning_witness(witness)
                .map_err(|err| BackendError::Failure(err.to_string()))?;
            return encode_pruning_proof(&proof);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (pk, witness);
            Err(BackendError::Unsupported("pruning proving"))
        }
    }

    fn prove_recursive(
        &self,
        pk: &ProvingKey,
        witness: &WitnessBytes,
    ) -> BackendResult<ProofBytes> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(pk.as_slice(), SupportedCircuit::Recursive)?;
            let witness = decode_recursive_witness(witness)?;
            let prover = crate::official::prover::WalletProver::new(payload.parameters.clone());
            let proof = prover
                .prove_recursive_witness(witness)
                .map_err(|err| BackendError::Failure(err.to_string()))?;
            return encode_recursive_proof(&proof);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (pk, witness);
            Err(BackendError::Unsupported("recursive proving"))
        }
    }

    fn prove_uptime(&self, pk: &ProvingKey, witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(pk.as_slice(), SupportedCircuit::Uptime)?;
            let witness = decode_uptime_witness(witness)?;
            let prover = crate::official::prover::WalletProver::new(payload.parameters.clone());
            let proof = prover
                .prove_uptime_witness(witness)
                .map_err(|err| BackendError::Failure(err.to_string()))?;
            return encode_uptime_proof(&proof);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (pk, witness);
            Err(BackendError::Unsupported("uptime proving"))
        }
    }

    fn prove_consensus(
        &self,
        witness: &WitnessBytes,
    ) -> BackendResult<(ProofBytes, VerifyingKey, ConsensusCircuitDef)> {
        #[cfg(feature = "official")]
        {
            let (header, witness) = decode_consensus_witness(witness)?;
            let parameters = StarkParameters::blueprint_default();
            let prover = crate::official::prover::WalletProver::new(parameters.clone());
            let proof = prover
                .prove_consensus_witness(witness)
                .map_err(|err| BackendError::Failure(err.to_string()))?;
            let proof_bytes = encode_consensus_proof(&header.circuit, &proof)?;
            let payload = KeyPayload::new(SupportedCircuit::Consensus, parameters);
            let encoded = encode_key_payload(&payload)?;
            let verifying_key = VerifyingKey(encoded.clone());
            let circuit = ConsensusCircuitDef::new(header.circuit);
            return Ok((proof_bytes, verifying_key, circuit));
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = witness;
            Err(BackendError::Unsupported("consensus proving"))
        }
    }

    fn verify_tx(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        public_inputs: &TxPublicInputs,
    ) -> BackendResult<bool> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(vk.as_slice(), SupportedCircuit::Transaction)?;
            let parameters = payload.parameters.clone();
            let decoded = decode_tx_proof(proof)?;
            let expected_fields = rebuild_tx_public_inputs(&parameters, public_inputs);
            let commitment =
                ensure_proof_integrity("transaction", &parameters, &decoded, &expected_fields)?;
            if field_to_padded_bytes(&commitment) != public_inputs.transaction_commitment {
                return Err(BackendError::Failure(
                    "transaction commitment digest mismatch".into(),
                ));
            }
            let verifier = NodeVerifier::with_parameters(parameters);
            verifier
                .verify_transaction_proof(&decoded)
                .map_err(|err| BackendError::Failure(err.to_string()))?;
            return Ok(true);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (vk, proof, public_inputs);
            Err(BackendError::Unsupported("transaction verification"))
        }
    }

    fn verify_identity(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        public_inputs: &IdentityPublicInputs,
    ) -> BackendResult<()> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(vk.as_slice(), SupportedCircuit::Identity)?;
            let parameters = payload.parameters.clone();
            let decoded = decode_identity_proof(proof)?;
            let expected_fields = rebuild_identity_public_inputs(&parameters, public_inputs);
            ensure_proof_integrity("identity", &parameters, &decoded, &expected_fields)?;
            let verifier = NodeVerifier::with_parameters(parameters);
            let chain_proof = ChainProof::Stwo(decoded.clone());
            verifier
                .verify_identity(&chain_proof)
                .map_err(|err| BackendError::Failure(err.to_string()))
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (vk, proof, public_inputs);
            Err(BackendError::Unsupported("identity verification"))
        }
    }

    fn verify_state(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        public_inputs: &StatePublicInputs,
    ) -> BackendResult<()> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(vk.as_slice(), SupportedCircuit::State)?;
            let parameters = payload.parameters.clone();
            let decoded = decode_state_proof(proof)?;
            let expected_fields = rebuild_state_public_inputs(&parameters, public_inputs);
            ensure_proof_integrity("state", &parameters, &decoded, &expected_fields)?;
            let verifier = NodeVerifier::with_parameters(parameters);
            let chain_proof = ChainProof::Stwo(decoded.clone());
            verifier
                .verify_state(&chain_proof)
                .map_err(|err| BackendError::Failure(err.to_string()))
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (vk, proof, public_inputs);
            Err(BackendError::Unsupported("state verification"))
        }
    }

    fn verify_pruning(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        public_inputs: &PruningPublicInputs,
    ) -> BackendResult<()> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(vk.as_slice(), SupportedCircuit::Pruning)?;
            let parameters = payload.parameters.clone();
            let decoded = decode_pruning_proof(proof)?;
            let expected_fields = rebuild_pruning_public_inputs(&parameters, public_inputs);
            ensure_proof_integrity("pruning", &parameters, &decoded, &expected_fields)?;
            let verifier = NodeVerifier::with_parameters(parameters);
            let chain_proof = ChainProof::Stwo(decoded.clone());
            verifier
                .verify_pruning(&chain_proof)
                .map_err(|err| BackendError::Failure(err.to_string()))
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (vk, proof, public_inputs);
            Err(BackendError::Unsupported("pruning verification"))
        }
    }

    fn verify_recursive(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        public_inputs: &RecursivePublicInputs,
    ) -> BackendResult<()> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(vk.as_slice(), SupportedCircuit::Recursive)?;
            let parameters = payload.parameters.clone();
            let decoded = decode_recursive_proof(proof)?;
            let expected_fields = rebuild_recursive_public_inputs(&parameters, public_inputs);
            ensure_proof_integrity("recursive", &parameters, &decoded, &expected_fields)?;
            let verifier = NodeVerifier::with_parameters(parameters);
            let chain_proof = ChainProof::Stwo(decoded.clone());
            verifier
                .verify_recursive(&chain_proof)
                .map_err(|err| BackendError::Failure(err.to_string()))
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (vk, proof, public_inputs);
            Err(BackendError::Unsupported("recursive verification"))
        }
    }

    fn verify_uptime(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        public_inputs: &UptimePublicInputs,
    ) -> BackendResult<()> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(vk.as_slice(), SupportedCircuit::Uptime)?;
            let parameters = payload.parameters.clone();
            let decoded = decode_uptime_proof(proof)?;
            let expected_fields = rebuild_uptime_public_inputs(&parameters, public_inputs);
            let commitment =
                ensure_proof_integrity("uptime", &parameters, &decoded, &expected_fields)?;
            if field_to_padded_bytes(&commitment) != public_inputs.commitment {
                return Err(BackendError::Failure(
                    "uptime commitment digest mismatch".into(),
                ));
            }
            let verifier = NodeVerifier::with_parameters(parameters);
            let chain_proof = ChainProof::Stwo(decoded.clone());
            verifier
                .verify_uptime(&chain_proof)
                .map_err(|err| BackendError::Failure(err.to_string()))
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (vk, proof, public_inputs);
            Err(BackendError::Unsupported("uptime verification"))
        }
    }

    fn verify_consensus(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        circuit: &ConsensusCircuitDef,
        public_inputs: &ConsensusPublicInputs,
    ) -> BackendResult<()> {
        #[cfg(feature = "official")]
        {
            let payload = key_payload_for(vk.as_slice(), SupportedCircuit::Consensus)?;
            let parameters = payload.parameters.clone();
            let (header, decoded) = decode_consensus_proof(proof)?;
            if !header.circuit.eq_ignore_ascii_case(&circuit.identifier) {
                return Err(BackendError::Failure(
                    "consensus proof circuit identifier mismatch".into(),
                ));
            }
            let expected_fields = rebuild_consensus_public_inputs(&parameters, public_inputs);
            ensure_proof_integrity("consensus", &parameters, &decoded, &expected_fields)?;
            let verifier = NodeVerifier::with_parameters(parameters);
            let chain_proof = ChainProof::Stwo(decoded.clone());
            verifier
                .verify_consensus(&chain_proof)
                .map_err(|err| BackendError::Failure(err.to_string()))
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (vk, proof, circuit, public_inputs);
            Err(BackendError::Unsupported("consensus verification"))
        }
    }
}
#[cfg(feature = "official")]
fn rebuild_tx_public_inputs(
    parameters: &StarkParameters,
    inputs: &TxPublicInputs,
) -> Vec<FieldElement> {
    fn digest_chunks(parameters: &StarkParameters, digest: &[u8; 32]) -> Vec<FieldElement> {
        digest
            .chunks(8)
            .map(|chunk| parameters.element_from_bytes(chunk))
            .collect()
    }

    let mut fields = digest_chunks(parameters, &inputs.utxo_root);
    fields.extend(digest_chunks(parameters, &inputs.transaction_commitment));
    fields
}

#[cfg(feature = "official")]
fn field_to_padded_bytes(value: &FieldElement) -> [u8; 32] {
    let repr = value.to_bytes();
    let mut bytes = [0u8; 32];
    let offset = bytes.len().saturating_sub(repr.len());
    bytes[offset..offset + repr.len()].copy_from_slice(&repr);
    bytes
}

#[cfg(feature = "official")]
fn key_payload_for(bytes: &[u8], expected: SupportedCircuit) -> BackendResult<KeyPayload> {
    let payload = decode_key_payload(bytes)?;
    payload.ensure_kind(expected)?;
    Ok(payload)
}

#[cfg(feature = "official")]
fn keygen_for_circuit(
    identifier: &str,
    expected: SupportedCircuit,
) -> BackendResult<(ProvingKey, VerifyingKey)> {
    let _ = decode_circuit_identifier(identifier, expected)?;
    let parameters = StarkParameters::blueprint_default();
    let payload = KeyPayload::new(expected, parameters);
    let encoded = encode_key_payload(&payload)?;
    Ok((ProvingKey(encoded.clone()), VerifyingKey(encoded)))
}

#[cfg(feature = "official")]
fn canonical_identifier(identifier: &str) -> BackendResult<String> {
    if identifier.trim().is_empty() {
        return Err(BackendError::Failure(
            "circuit identifier cannot be empty".into(),
        ));
    }

    #[derive(serde::Deserialize)]
    struct Identifier<'a> {
        #[serde(borrow)]
        circuit: &'a str,
    }

    if identifier.trim_start().starts_with('{') {
        serde_json::from_str::<Identifier>(identifier)
            .map(|value| value.circuit.to_string())
            .map_err(|err| {
                BackendError::Failure(format!(
                    "invalid circuit identifier '{}': {err}",
                    identifier
                ))
            })
    } else {
        Ok(identifier.to_string())
    }
}

#[cfg(feature = "official")]
fn decode_circuit_identifier(
    identifier: &str,
    expected: SupportedCircuit,
) -> BackendResult<String> {
    let parsed = canonical_identifier(identifier)?;
    let circuit = SupportedCircuit::from_identifier(&parsed)?;
    if circuit == expected {
        Ok(parsed)
    } else {
        Err(BackendError::Failure(format!(
            "key payload expected {:?} circuit, found '{}'",
            expected, parsed
        )))
    }
}

#[cfg(feature = "official")]
fn ensure_proof_integrity(
    context: &str,
    parameters: &StarkParameters,
    proof: &crate::official::proof::StarkProof,
    expected_fields: &[FieldElement],
) -> BackendResult<FieldElement> {
    let expected_inputs: Vec<String> = expected_fields.iter().map(FieldElement::to_hex).collect();
    if proof.public_inputs != expected_inputs {
        return Err(BackendError::Failure(format!(
            "{context} public inputs mismatch"
        )));
    }
    let hasher = parameters.poseidon_hasher();
    let commitment = hasher.hash(expected_fields);
    if proof.commitment != commitment.to_hex() {
        return Err(BackendError::Failure(format!(
            "{context} commitment mismatch"
        )));
    }
    if proof.commitment_proof.to_official().is_none() {
        return Err(BackendError::Failure(format!(
            "missing commitment proof data for {context}"
        )));
    }
    if proof.fri_proof.to_official().is_none() {
        return Err(BackendError::Failure(format!(
            "missing fri proof data for {context}"
        )));
    }
    Ok(commitment)
}

#[cfg(feature = "official")]
fn element_from_bytes(parameters: &StarkParameters, bytes: &[u8]) -> FieldElement {
    if bytes.is_empty() {
        parameters.element_from_u64(0)
    } else {
        parameters.element_from_bytes(bytes)
    }
}

#[cfg(feature = "official")]
fn rebuild_identity_public_inputs(
    parameters: &StarkParameters,
    inputs: &IdentityPublicInputs,
) -> Vec<FieldElement> {
    vec![
        element_from_bytes(parameters, &inputs.wallet_address),
        element_from_bytes(parameters, &inputs.vrf_tag),
        element_from_bytes(parameters, &inputs.identity_root),
        element_from_bytes(parameters, &inputs.state_root),
    ]
}

#[cfg(feature = "official")]
fn rebuild_state_public_inputs(
    parameters: &StarkParameters,
    inputs: &StatePublicInputs,
) -> Vec<FieldElement> {
    vec![
        element_from_bytes(parameters, &inputs.previous_state_root),
        element_from_bytes(parameters, &inputs.new_state_root),
        parameters.element_from_u64(inputs.transaction_count),
    ]
}

#[cfg(feature = "official")]
fn rebuild_pruning_public_inputs(
    parameters: &StarkParameters,
    inputs: &PruningPublicInputs,
) -> Vec<FieldElement> {
    vec![
        element_from_bytes(parameters, &inputs.previous_tx_root),
        element_from_bytes(parameters, &inputs.pruned_tx_root),
        parameters.element_from_u64(inputs.removed_transactions),
    ]
}

#[cfg(feature = "official")]
fn rebuild_recursive_public_inputs(
    parameters: &StarkParameters,
    inputs: &RecursivePublicInputs,
) -> Vec<FieldElement> {
    let previous = inputs
        .previous_commitment
        .map(|bytes| element_from_bytes(parameters, &bytes))
        .unwrap_or_else(|| element_from_bytes(parameters, &[]));
    vec![
        previous,
        element_from_bytes(parameters, &inputs.aggregated_commitment),
        parameters.element_from_u64(inputs.transaction_commitments),
    ]
}

#[cfg(feature = "official")]
fn rebuild_uptime_public_inputs(
    parameters: &StarkParameters,
    inputs: &UptimePublicInputs,
) -> Vec<FieldElement> {
    vec![
        element_from_bytes(parameters, &inputs.wallet_address),
        parameters.element_from_u64(inputs.node_clock),
        parameters.element_from_u64(inputs.epoch),
        element_from_bytes(parameters, &inputs.head_hash),
        parameters.element_from_u64(inputs.window_start),
        parameters.element_from_u64(inputs.window_end),
        element_from_bytes(parameters, &inputs.commitment),
    ]
}

#[cfg(feature = "official")]
fn rebuild_consensus_public_inputs(
    parameters: &StarkParameters,
    inputs: &ConsensusPublicInputs,
) -> Vec<FieldElement> {
    vec![
        element_from_bytes(parameters, &inputs.block_hash),
        parameters.element_from_u64(inputs.round),
        element_from_bytes(parameters, &inputs.leader_proposal),
        parameters.element_from_u64(inputs.quorum_threshold),
    ]
}
#[cfg(all(test, feature = "official", feature = "scaffold"))]
mod tests {
    use super::io::{
        decode_consensus_proof, decode_consensus_witness, decode_identity_proof,
        decode_identity_witness, decode_pruning_proof, decode_pruning_witness,
        decode_recursive_proof, decode_recursive_witness, decode_state_proof, decode_state_witness,
        decode_tx_proof, decode_uptime_proof, decode_uptime_witness, encode_consensus_proof,
        encode_tx_proof,
    };
    use super::keys::{decode_key_payload, encode_key_payload, KeyPayload, SupportedCircuit};
    use super::*;
    use crate::crypto::address_from_public_key;
    use crate::identity_tree::{IdentityCommitmentTree, IDENTITY_TREE_DEPTH};
    use crate::official::circuit::consensus::{ConsensusWitness, VotePower};
    use crate::official::circuit::identity::IdentityWitness;
    use crate::official::circuit::pruning::PruningWitness;
    use crate::official::circuit::recursive::RecursiveWitness;
    use crate::official::circuit::state::StateWitness;
    use crate::official::circuit::string_to_field;
    use crate::official::circuit::transaction::TransactionWitness;
    use crate::official::circuit::uptime::UptimeWitness;
    use crate::official::params::{FieldElement, StarkParameters};
    use crate::official::proof::ProofPayload;
    use crate::reputation::{ReputationWeights, Tier};
    use crate::state::compute_merkle_root;
    use crate::types::{Account, Stake, Transaction, UptimeProof};
    use crate::vrf::VRF_PROOF_LENGTH;
    use ed25519_dalek::{Keypair, Signer};
    use prover_backend_interface::{
        ConsensusCircuitDef, ConsensusPublicInputs, IdentityPublicInputs, ProofSystemKind,
        PruningPublicInputs, RecursivePublicInputs, StatePublicInputs, TxPublicInputs,
        UptimePublicInputs, VerifyingKey, WitnessBytes, WitnessHeader,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn key_payload_roundtrip() {
        let payload = KeyPayload::new(
            SupportedCircuit::Transaction,
            StarkParameters::blueprint_default(),
        );
        let encoded = encode_key_payload(&payload).expect("payload serialises");
        let decoded = decode_key_payload(&encoded).expect("payload roundtrips");
        assert_eq!(payload, decoded);
    }

    #[test]
    fn rejects_unknown_circuit_ids() {
        let mut payload = KeyPayload::new(
            SupportedCircuit::Transaction,
            StarkParameters::blueprint_default(),
        );
        payload.circuit = "unsupported".into();
        let encoded = encode_key_payload(&payload).expect("payload serialises");
        let error = decode_key_payload(&encoded).expect_err("unknown circuit is rejected");
        assert!(
            matches!(error, BackendError::Failure(message) if message.contains("unsupported circuit"))
        );
    }

    #[test]
    fn rejects_empty_identifiers() {
        let result = decode_circuit_identifier("", SupportedCircuit::Transaction);
        assert!(
            matches!(result, Err(BackendError::Failure(message)) if message.contains("cannot be empty"))
        );
    }

    #[test]
    fn transaction_proof_round_trip_from_witness_fixture() {
        let backend = StwoBackend::new();
        let proving_key = proving_key(SupportedCircuit::Transaction);
        let witness = sample_transaction_witness();
        let witness_bytes = encode_tx_witness(&witness);

        let proof_bytes = backend
            .prove_tx(&proving_key, &witness_bytes)
            .expect("proving should succeed for valid witness");
        let proof = decode_tx_proof(&proof_bytes).expect("proof decodes");

        match &proof.payload {
            ProofPayload::Transaction(decoded) => {
                assert_eq!(decoded, &witness, "witness payload should round-trip");
            }
            other => panic!("unexpected payload variant: {other:?}"),
        }

        assert!(
            proof.commitment_proof.to_official().is_some(),
            "commitment proof should be preserved"
        );
        assert!(
            proof.fri_proof.to_official().is_some(),
            "fri transcript should be preserved"
        );
    }

    #[test]
    fn identity_proof_round_trip() {
        let backend = StwoBackend::new();
        let proving_key = proving_key(SupportedCircuit::Identity);
        let witness = sample_identity_witness();
        let witness_bytes = encode_identity_witness(&witness);

        let proof_bytes = backend
            .prove_identity(&proving_key, &witness_bytes)
            .expect("identity proving succeeds");
        let proof = decode_identity_proof(&proof_bytes).expect("proof decodes");

        match &proof.payload {
            ProofPayload::Identity(decoded) => assert_eq!(decoded, &witness),
            other => panic!("unexpected payload variant: {other:?}"),
        }

        backend
            .verify_identity(
                &verifying_key(SupportedCircuit::Identity),
                &proof_bytes,
                &identity_public_inputs(&witness),
            )
            .expect("identity verification succeeds");
    }

    #[test]
    fn state_proof_round_trip() {
        let backend = StwoBackend::new();
        let proving_key = proving_key(SupportedCircuit::State);
        let witness = sample_state_witness();
        let witness_bytes = encode_state_witness(&witness);

        let proof_bytes = backend
            .prove_state(&proving_key, &witness_bytes)
            .expect("state proving succeeds");
        let proof = decode_state_proof(&proof_bytes).expect("proof decodes");

        match &proof.payload {
            ProofPayload::State(decoded) => {
                assert_eq!(decoded.prev_state_root, witness.prev_state_root)
            }
            other => panic!("unexpected payload variant: {other:?}"),
        }

        backend
            .verify_state(
                &verifying_key(SupportedCircuit::State),
                &proof_bytes,
                &state_public_inputs(&witness),
            )
            .expect("state verification succeeds");
    }

    #[test]
    fn pruning_proof_round_trip() {
        let backend = StwoBackend::new();
        let proving_key = proving_key(SupportedCircuit::Pruning);
        let witness = sample_pruning_witness();
        let witness_bytes = encode_pruning_witness(&witness);

        let proof_bytes = backend
            .prove_pruning(&proving_key, &witness_bytes)
            .expect("pruning proving succeeds");
        let proof = decode_pruning_proof(&proof_bytes).expect("proof decodes");

        match &proof.payload {
            ProofPayload::Pruning(decoded) => {
                assert_eq!(decoded.removed_transactions, witness.removed_transactions)
            }
            other => panic!("unexpected payload variant: {other:?}"),
        }

        backend
            .verify_pruning(
                &verifying_key(SupportedCircuit::Pruning),
                &proof_bytes,
                &pruning_public_inputs(&witness),
            )
            .expect("pruning verification succeeds");
    }

    #[test]
    fn recursive_proof_round_trip() {
        let backend = StwoBackend::new();
        let proving_key = proving_key(SupportedCircuit::Recursive);
        let witness = sample_recursive_witness();
        let witness_bytes = encode_recursive_witness(&witness);

        let proof_bytes = backend
            .prove_recursive(&proving_key, &witness_bytes)
            .expect("recursive proving succeeds");
        let proof = decode_recursive_proof(&proof_bytes).expect("proof decodes");

        match &proof.payload {
            ProofPayload::Recursive(decoded) => {
                assert_eq!(decoded.aggregated_commitment, witness.aggregated_commitment)
            }
            other => panic!("unexpected payload variant: {other:?}"),
        }

        backend
            .verify_recursive(
                &verifying_key(SupportedCircuit::Recursive),
                &proof_bytes,
                &recursive_public_inputs(&witness),
            )
            .expect("recursive verification succeeds");
    }

    #[test]
    fn uptime_proof_round_trip() {
        let backend = StwoBackend::new();
        let proving_key = proving_key(SupportedCircuit::Uptime);
        let witness = sample_uptime_witness();
        let witness_bytes = encode_uptime_witness(&witness);

        let proof_bytes = backend
            .prove_uptime(&proving_key, &witness_bytes)
            .expect("uptime proving succeeds");
        let proof = decode_uptime_proof(&proof_bytes).expect("proof decodes");

        match &proof.payload {
            ProofPayload::Uptime(decoded) => assert_eq!(decoded.commitment, witness.commitment),
            other => panic!("unexpected payload variant: {other:?}"),
        }

        backend
            .verify_uptime(
                &verifying_key(SupportedCircuit::Uptime),
                &proof_bytes,
                &uptime_public_inputs(&witness),
            )
            .expect("uptime verification succeeds");
    }

    #[test]
    fn consensus_proof_round_trip() {
        let backend = StwoBackend::new();
        let witness = sample_consensus_witness();
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "consensus");
        let witness_bytes =
            WitnessBytes::encode(&header, &witness).expect("consensus witness encodes");

        let (proof_bytes, verifying_key, circuit) = backend
            .prove_consensus(&witness_bytes)
            .expect("consensus proving succeeds");
        assert_eq!(circuit.identifier, "consensus");

        let (_header, decoded_witness) =
            decode_consensus_witness(&witness_bytes).expect("witness decodes");
        assert_eq!(decoded_witness.block_hash, witness.block_hash);

        let (_proof_header, proof) = decode_consensus_proof(&proof_bytes).expect("proof decodes");
        match &proof.payload {
            ProofPayload::Consensus(decoded) => {
                assert_eq!(decoded.quorum_threshold, witness.quorum_threshold)
            }
            other => panic!("unexpected payload variant: {other:?}"),
        }

        backend
            .verify_consensus(
                &verifying_key,
                &proof_bytes,
                &consensus_public_inputs(&witness),
            )
            .expect("consensus verification succeeds");
    }

    #[test]
    fn transaction_prover_failures_map_to_backend_errors() {
        let backend = StwoBackend::new();
        let proving_key = proving_key(SupportedCircuit::Transaction);
        let mut witness = sample_transaction_witness();
        witness.sender_account.nonce = witness.signed_tx.payload.nonce;
        let witness_bytes = encode_tx_witness(&witness);

        let err = backend
            .prove_tx(&proving_key, &witness_bytes)
            .expect_err("invalid witness should fail proving");
        match err {
            BackendError::Failure(message) => {
                assert!(
                    message.contains("nonce"),
                    "unexpected failure message: {message}"
                );
            }
            other => panic!("unexpected backend error variant: {other:?}"),
        }
    }

    // TODO: consolidate transaction-specific coverage with the generalized circuit matrix above.
    fn proving_key(circuit: SupportedCircuit) -> ProvingKey {
        ProvingKey(key_payload_bytes(circuit))
    }

    fn verifying_key(circuit: SupportedCircuit) -> VerifyingKey {
        VerifyingKey(key_payload_bytes(circuit))
    }

    fn key_payload_bytes(circuit: SupportedCircuit) -> Vec<u8> {
        let payload = KeyPayload::new(circuit, StarkParameters::blueprint_default());
        encode_key_payload(&payload).expect("payload serialises")
    }

    fn encode_tx_witness(witness: &TransactionWitness) -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "tx");
        WitnessBytes::encode(&header, witness).expect("witness encodes")
    }

    fn encode_identity_witness(witness: &IdentityWitness) -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "identity");
        WitnessBytes::encode(&header, witness).expect("witness encodes")
    }

    fn encode_state_witness(witness: &StateWitness) -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "state");
        WitnessBytes::encode(&header, witness).expect("witness encodes")
    }

    fn encode_pruning_witness(witness: &PruningWitness) -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "pruning");
        WitnessBytes::encode(&header, witness).expect("witness encodes")
    }

    fn encode_recursive_witness(witness: &RecursiveWitness) -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "recursive");
        WitnessBytes::encode(&header, witness).expect("witness encodes")
    }

    fn encode_uptime_witness(witness: &UptimeWitness) -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "uptime");
        WitnessBytes::encode(&header, witness).expect("witness encodes")
    }

    fn sample_transaction_witness() -> TransactionWitness {
        let mut rng = StdRng::seed_from_u64(0xdead_beef_u64);
        let keypair = Keypair::generate(&mut rng);
        let sender = address_from_public_key(&keypair.public);
        let receiver = hex::encode([0x33u8; 32]);
        let payload = Transaction {
            from: sender.clone(),
            to: receiver.clone(),
            amount: 75,
            fee: 5,
            nonce: 3,
            memo: Some("backend-roundtrip".into()),
            timestamp: 1_717_171_717,
        };
        let signature = keypair.sign(&payload.canonical_bytes());
        let signed_tx =
            crate::types::SignedTransaction::new(payload.clone(), signature, &keypair.public);

        let mut sender_account = Account::new(
            sender,
            payload
                .amount
                .saturating_add(payload.fee as u128)
                .saturating_add(1_000),
            Stake::default(),
        );
        sender_account.nonce = payload.nonce - 1;
        sender_account.reputation.tier = Tier::Tl3;
        sender_account.reputation.last_decay_timestamp = payload.timestamp;
        sender_account.reputation.zsi.validated = true;
        sender_account.reputation.timetokes.last_decay_timestamp = payload.timestamp;

        let mut receiver_account = Account::new(receiver, 500, Stake::default());
        receiver_account.reputation.tier = Tier::Tl2;
        receiver_account.reputation.last_decay_timestamp = payload.timestamp;
        receiver_account.reputation.zsi.validated = true;
        receiver_account.reputation.timetokes.last_decay_timestamp = payload.timestamp;

        TransactionWitness {
            signed_tx,
            sender_account,
            receiver_account: Some(receiver_account),
            required_tier: Tier::Tl1,
            reputation_weights: ReputationWeights::default(),
        }
    }

    fn sample_identity_witness() -> IdentityWitness {
        let parameters = StarkParameters::blueprint_default();
        let wallet_pk_bytes = [0x11u8; 32];
        let wallet_pk = hex::encode(wallet_pk_bytes);
        let wallet_addr = hex::encode(<[u8; 32]>::from(crate::proof_backend::Blake2sHasher::hash(
            &wallet_pk_bytes,
        )));
        let vrf_tag = "55".repeat(VRF_PROOF_LENGTH);
        let epoch_nonce = hex::encode([0x22u8; 32]);
        let state_root = hex::encode([0x33u8; 32]);

        let tree = IdentityCommitmentTree::new(IDENTITY_TREE_DEPTH);
        let proof = tree.proof_for(&wallet_addr);
        let identity_leaf = proof.leaf.clone();
        let identity_path = proof.siblings;
        let identity_root = tree.root_hex();

        let hasher = parameters.poseidon_hasher();
        let commitment = hasher
            .hash(&[
                string_to_field(&parameters, &wallet_addr),
                string_to_field(&parameters, &vrf_tag),
                string_to_field(&parameters, &identity_root),
                string_to_field(&parameters, &state_root),
            ])
            .to_hex();

        IdentityWitness {
            wallet_pk,
            wallet_addr,
            vrf_tag,
            epoch_nonce,
            state_root,
            identity_root,
            initial_reputation: 0,
            commitment,
            identity_leaf,
            identity_path,
        }
    }

    fn sample_state_witness() -> StateWitness {
        let mut before = vec![Account::new(
            hex::encode([0x44u8; 32]),
            1_000,
            Stake::default(),
        )];
        before[0].reputation.zsi.validated = true;
        let mut after = before.clone();
        let prev_state_root = state_root_for(&before);
        let new_state_root = state_root_for(&after);

        StateWitness {
            prev_state_root,
            new_state_root,
            identities: Vec::new(),
            transactions: Vec::new(),
            accounts_before: before,
            accounts_after: after,
            required_tier: Tier::Tl1,
            reputation_weights: ReputationWeights::default(),
        }
    }

    fn sample_pruning_witness() -> PruningWitness {
        let original = vec![hex::encode([0x55u8; 32]), hex::encode([0x66u8; 32])];
        let removed = vec![original[0].clone()];
        let previous_tx_root = merkle_root(&original);
        let pruned_tx_root = merkle_root(&original[1..].to_vec());

        PruningWitness {
            previous_tx_root,
            pruned_tx_root,
            original_transactions: original,
            removed_transactions: removed,
        }
    }

    fn sample_recursive_witness() -> RecursiveWitness {
        let parameters = StarkParameters::blueprint_default();
        let identity_commitments = vec![parameters.element_from_u64(11).to_hex()];
        let tx_commitments = vec![parameters.element_from_u64(22).to_hex()];
        let uptime_commitments = vec![parameters.element_from_u64(33).to_hex()];
        let consensus_commitments = vec![parameters.element_from_u64(44).to_hex()];
        let pruning_commitment = parameters.element_from_u64(55).to_hex();
        let state_commitment = parameters.element_from_u64(66).to_hex();
        let global_state_root = parameters.element_from_u64(77).to_hex();
        let utxo_root = parameters.element_from_u64(88).to_hex();
        let reputation_root = parameters.element_from_u64(99).to_hex();
        let timetoke_root = parameters.element_from_u64(111).to_hex();
        let zsi_root = parameters.element_from_u64(122).to_hex();
        let proof_root = parameters.element_from_u64(133).to_hex();
        let block_height = 9;

        let mut witness = RecursiveWitness {
            previous_commitment: None,
            aggregated_commitment: String::new(),
            identity_commitments,
            tx_commitments,
            uptime_commitments,
            consensus_commitments,
            state_commitment,
            global_state_root,
            utxo_root,
            reputation_root,
            timetoke_root,
            zsi_root,
            proof_root,
            pruning_commitment,
            block_height,
        };

        let aggregated = recursive_aggregate(&parameters, &witness);
        witness.aggregated_commitment = aggregated.to_hex();
        witness
    }

    fn sample_uptime_witness() -> UptimeWitness {
        let wallet_address = hex::encode([0x77u8; 32]);
        let window_start = 10;
        let window_end = 20;
        let commitment_bytes =
            UptimeProof::commitment_bytes(&wallet_address, window_start, window_end);
        UptimeWitness {
            wallet_address,
            node_clock: 42,
            epoch: 3,
            head_hash: hex::encode([0x88u8; 32]),
            window_start,
            window_end,
            commitment: hex::encode(commitment_bytes),
        }
    }

    fn sample_consensus_witness() -> ConsensusWitness {
        let block_hash = hex::encode([0x99u8; 32]);
        let votes = vec![
            VotePower {
                voter: "validator-1".into(),
                weight: 10,
            },
            VotePower {
                voter: "validator-2".into(),
                weight: 8,
            },
        ];
        ConsensusWitness {
            block_hash: block_hash.clone(),
            round: 5,
            leader_proposal: block_hash,
            quorum_threshold: 12,
            pre_votes: votes.clone(),
            pre_commits: votes.clone(),
            commit_votes: votes,
        }
    }

    fn identity_public_inputs(witness: &IdentityWitness) -> IdentityPublicInputs {
        IdentityPublicInputs {
            wallet_address: hex_to_array(&witness.wallet_addr),
            vrf_tag: hex::decode(&witness.vrf_tag).expect("vrf tag decodes"),
            identity_root: hex_to_array(&witness.identity_root),
            state_root: hex_to_array(&witness.state_root),
        }
    }

    fn state_public_inputs(witness: &StateWitness) -> StatePublicInputs {
        StatePublicInputs {
            previous_state_root: hex_to_array(&witness.prev_state_root),
            new_state_root: hex_to_array(&witness.new_state_root),
            transaction_count: witness.transactions.len() as u64,
        }
    }

    fn pruning_public_inputs(witness: &PruningWitness) -> PruningPublicInputs {
        PruningPublicInputs {
            previous_tx_root: hex_to_array(&witness.previous_tx_root),
            pruned_tx_root: hex_to_array(&witness.pruned_tx_root),
            removed_transactions: witness.removed_transactions.len() as u64,
        }
    }

    fn recursive_public_inputs(witness: &RecursiveWitness) -> RecursivePublicInputs {
        let parameters = StarkParameters::blueprint_default();
        let previous = witness
            .previous_commitment
            .as_ref()
            .map(|value| field_to_padded_bytes(&string_to_field(&parameters, value)));
        RecursivePublicInputs {
            previous_commitment: previous,
            aggregated_commitment: field_to_padded_bytes(&string_to_field(
                &parameters,
                &witness.aggregated_commitment,
            )),
            transaction_commitments: witness.tx_commitments.len() as u64,
        }
    }

    fn uptime_public_inputs(witness: &UptimeWitness) -> UptimePublicInputs {
        UptimePublicInputs {
            wallet_address: hex_to_array(&witness.wallet_address),
            node_clock: witness.node_clock,
            epoch: witness.epoch,
            head_hash: hex_to_array(&witness.head_hash),
            window_start: witness.window_start,
            window_end: witness.window_end,
            commitment: hex_to_array(&witness.commitment),
        }
    }

    fn consensus_public_inputs(witness: &ConsensusWitness) -> ConsensusPublicInputs {
        ConsensusPublicInputs {
            block_hash: hex_to_array(&witness.block_hash),
            round: witness.round,
            leader_proposal: hex_to_array(&witness.leader_proposal),
            quorum_threshold: witness.quorum_threshold,
        }
    }

    fn recursive_aggregate(
        parameters: &StarkParameters,
        witness: &RecursiveWitness,
    ) -> FieldElement {
        let hasher = parameters.poseidon_hasher();
        let zero = FieldElement::zero(parameters.modulus());
        let previous = witness
            .previous_commitment
            .as_ref()
            .map(|value| string_to_field(parameters, value))
            .unwrap_or_else(|| FieldElement::zero(parameters.modulus()));
        let pruning = string_to_field(parameters, &witness.pruning_commitment);
        let mut commitments = witness.identity_commitments.clone();
        commitments.extend(witness.tx_commitments.clone());
        commitments.extend(witness.uptime_commitments.clone());
        commitments.extend(witness.consensus_commitments.clone());

        let mut activity = zero.clone();
        for commitment in commitments {
            let element = string_to_field(parameters, &commitment);
            activity = hasher.hash(&[activity.clone(), element, zero.clone()]);
        }

        let state_digest = hasher.hash(&[
            string_to_field(parameters, &witness.state_commitment),
            string_to_field(parameters, &witness.global_state_root),
            string_to_field(parameters, &witness.utxo_root),
            string_to_field(parameters, &witness.reputation_root),
            string_to_field(parameters, &witness.timetoke_root),
            string_to_field(parameters, &witness.zsi_root),
            string_to_field(parameters, &witness.proof_root),
            parameters.element_from_u64(witness.block_height),
        ]);

        hasher.hash(&[previous, state_digest, pruning, activity])
    }

    fn state_root_for(accounts: &[Account]) -> String {
        let mut sorted = accounts.to_vec();
        sorted.sort_by(|a, b| a.address.cmp(&b.address));
        let mut leaves = sorted
            .iter()
            .map(|account| {
                let bytes = serde_json::to_vec(account).expect("serialize account");
                <[u8; 32]>::from(crate::proof_backend::Blake2sHasher::hash(bytes.as_slice()))
            })
            .collect::<Vec<_>>();
        hex::encode(compute_merkle_root(&mut leaves))
    }

    fn merkle_root(hashes: &[String]) -> String {
        let mut leaves = hashes
            .iter()
            .map(|hash| hex_to_array::<32>(hash))
            .collect::<Vec<_>>();
        hex::encode(compute_merkle_root(&mut leaves))
    }

    fn hex_to_array<const N: usize>(value: &str) -> [u8; N] {
        let bytes = hex::decode(value).expect("hex decodes");
        assert_eq!(bytes.len(), N, "hex string must encode {N} bytes");
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        array
    }
}
