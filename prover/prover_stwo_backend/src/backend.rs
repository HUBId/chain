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

#[cfg(feature = "official")]
use prover_backend_interface::crash_reports::CrashContextGuard;
use prover_backend_interface::crash_reports::CrashReportHook;
use prover_backend_interface::{
    BackendError, BackendResult, ConsensusCircuitDef, ConsensusPublicInputs,
    ConsensusVrfPublicEntry, IdentityCircuitDef, IdentityPublicInputs, ProofBackend, ProofBytes,
    ProvingKey, PruningCircuitDef, PruningPublicInputs, RecursiveCircuitDef, RecursivePublicInputs,
    SecurityLevel, StateCircuitDef, StatePublicInputs, TxCircuitDef, TxPublicInputs,
    UptimeCircuitDef, UptimePublicInputs, VerifyingKey, WitnessBytes,
};

#[cfg(feature = "official")]
use crate::official::aggregation::pruning_fold_from_canonical_bytes;
#[cfg(feature = "official")]
use crate::official::circuit::consensus::{parse_vrf_entries, ConsensusCircuit, ConsensusWitness};
#[cfg(feature = "official")]
use crate::official::circuit::string_to_field;
#[cfg(feature = "official")]
use crate::official::params::{FieldElement, StarkParameters};
#[cfg(feature = "official")]
use crate::official::proof::ProofPayload;
#[cfg(feature = "official")]
use crate::official::verifier::NodeVerifier;
#[cfg(feature = "official")]
use crate::proof_system::ProofVerifier;
#[cfg(feature = "official")]
use crate::types::ChainProof;
#[cfg(feature = "official")]
use crate::vrf::VRF_PREOUTPUT_LENGTH;
#[cfg(feature = "official")]
use keys::{decode_key_payload, encode_key_payload, KeyPayload, SupportedCircuit};
#[cfg(feature = "official")]
use rpp_pruning::{DIGEST_LENGTH, DOMAIN_TAG_LENGTH};
use std::sync::OnceLock;

#[cfg(feature = "official")]
const POSEIDON_VRF_DOMAIN: &[u8] = b"chain.vrf.poseidon";

/// Thin adapter exposing the STWO integration through the shared backend
/// interface.  The concrete proving routines are wired in lazily to keep the
/// nightly-only dependencies isolated from stable crates.
#[derive(Debug, Default)]
pub struct StwoBackend;

impl StwoBackend {
    pub fn new() -> Self {
        install_crash_reporter();
        Self
    }
}

#[cfg(feature = "official")]
fn crash_guard_for(circuit: impl Into<String>) -> CrashContextGuard {
    install_crash_reporter();
    CrashContextGuard::enter("stwo", circuit)
}

fn install_crash_reporter() {
    static HOOK: OnceLock<Option<CrashReportHook>> = OnceLock::new();
    HOOK.get_or_init(|| CrashReportHook::install_from_env("prover-stwo"));
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
            let _crash_guard = crash_guard_for(circuit.identifier.clone());
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
            let _crash_guard = crash_guard_for(circuit.identifier.clone());
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
            let _crash_guard = crash_guard_for(circuit.identifier.clone());
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
            let _crash_guard = crash_guard_for(circuit.identifier.clone());
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
            let _crash_guard = crash_guard_for(circuit.identifier.clone());
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
            let _crash_guard = crash_guard_for(circuit.identifier.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(header.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
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
            let _crash_guard = crash_guard_for(payload.circuit.clone());
            let (header, decoded) = decode_consensus_proof(proof)?;
            if !header.circuit.eq_ignore_ascii_case(&circuit.identifier) {
                return Err(BackendError::Failure(
                    "consensus proof circuit identifier mismatch".into(),
                ));
            }
            let witness = match &decoded.payload {
                ProofPayload::Consensus(witness) => witness,
                _ => {
                    return Err(BackendError::Failure(
                        "consensus proof payload missing witness".into(),
                    ))
                }
            };
            let entry_count = public_inputs.vrf_entries.len();
            if entry_count != witness.vrf_entries.len() {
                return Err(BackendError::Failure(
                    "consensus VRF entry count mismatch public inputs".into(),
                ));
            }

            for (index, (public_entry, witness_entry)) in public_inputs
                .vrf_entries
                .iter()
                .zip(&witness.vrf_entries)
                .enumerate()
            {
                let index = index + 1;
                let witness_randomness: [u8; 32] = hex::decode(&witness_entry.randomness)
                    .map_err(|err| {
                        BackendError::Failure(format!(
                            "consensus witness VRF entry #{index} randomness not valid hex: {err}"
                        ))
                    })?
                    .try_into()
                    .map_err(|_| {
                        BackendError::Failure(format!(
                            "consensus witness VRF entry #{index} randomness has incorrect length"
                        ))
                    })?;
                if witness_randomness != public_entry.randomness {
                    return Err(BackendError::Failure(format!(
                        "consensus VRF entry #{index} randomness mismatch public inputs"
                    )));
                }

                let witness_pre_output: [u8; VRF_PREOUTPUT_LENGTH] =
                    hex::decode(&witness_entry.pre_output)
                        .map_err(|err| {
                            BackendError::Failure(format!(
                        "consensus witness VRF entry #{index} pre-output not valid hex: {err}"
                    ))
                        })?
                        .try_into()
                        .map_err(|_| {
                            BackendError::Failure(format!(
                        "consensus witness VRF entry #{index} pre-output has incorrect length"
                    ))
                        })?;
                if witness_pre_output != public_entry.pre_output {
                    return Err(BackendError::Failure(format!(
                        "consensus VRF entry #{index} pre-output mismatch public inputs"
                    )));
                }

                let witness_proof = hex::decode(&witness_entry.proof).map_err(|err| {
                    BackendError::Failure(format!(
                        "consensus witness VRF entry #{index} proof not valid hex: {err}"
                    ))
                })?;
                if witness_proof != public_entry.proof {
                    return Err(BackendError::Failure(format!(
                        "consensus VRF entry #{index} proof mismatch public inputs"
                    )));
                }

                let witness_public_key: [u8; 32] = hex::decode(&witness_entry.public_key)
                    .map_err(|err| {
                        BackendError::Failure(format!(
                            "consensus witness VRF entry #{index} public key not valid hex: {err}"
                        ))
                    })?
                    .try_into()
                    .map_err(|_| {
                        BackendError::Failure(format!(
                            "consensus witness VRF entry #{index} public key has incorrect length"
                        ))
                    })?;
                if witness_public_key != public_entry.public_key {
                    return Err(BackendError::Failure(format!(
                        "consensus VRF entry #{index} public key mismatch public inputs"
                    )));
                }

                let witness_last_block: [u8; 32] =
                    hex::decode(&witness_entry.input.last_block_header)
                        .map_err(|err| {
                            BackendError::Failure(format!(
                        "consensus witness VRF entry #{index} Poseidon header not valid hex: {err}"
                    ))
                        })?
                        .try_into()
                        .map_err(|_| {
                            BackendError::Failure(format!(
                        "consensus witness VRF entry #{index} Poseidon header has incorrect length"
                    ))
                        })?;
                if witness_last_block != public_entry.poseidon_last_block_header {
                    return Err(BackendError::Failure(format!(
                        "consensus VRF entry #{index} poseidon last block header mismatch public inputs"
                    )));
                }

                if witness_entry.input.epoch != public_entry.poseidon_epoch {
                    return Err(BackendError::Failure(format!(
                        "consensus VRF entry #{index} poseidon epoch mismatch public inputs"
                    )));
                }

                let witness_tier_seed: [u8; 32] = hex::decode(&witness_entry.input.tier_seed)
                    .map_err(|err| {
                        BackendError::Failure(format!(
                            "consensus witness VRF entry #{index} Poseidon tier seed not valid hex: {err}"
                        ))
                    })?
                    .try_into()
                    .map_err(|_| {
                        BackendError::Failure(format!(
                            "consensus witness VRF entry #{index} Poseidon tier seed has incorrect length"
                        ))
                    })?;
                if witness_tier_seed != public_entry.poseidon_tier_seed {
                    return Err(BackendError::Failure(format!(
                        "consensus VRF entry #{index} poseidon tier seed mismatch public inputs"
                    )));
                }

                let digest_field = parameters.poseidon_hasher().hash(&[
                    parameters.element_from_bytes(POSEIDON_VRF_DOMAIN),
                    string_to_field(&parameters, &witness_entry.input.last_block_header),
                    parameters.element_from_u64(witness_entry.input.epoch),
                    string_to_field(&parameters, &witness_entry.input.tier_seed),
                ]);
                if field_to_padded_bytes(&digest_field) != public_entry.poseidon_digest {
                    return Err(BackendError::Failure(format!(
                        "consensus VRF entry #{index} poseidon digest mismatch public inputs"
                    )));
                }
            }
            let expected_fields =
                rebuild_consensus_public_inputs(&parameters, public_inputs, witness);
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
    witness: &ConsensusWitness,
) -> Vec<FieldElement> {
    let mut fields = vec![
        element_from_bytes(parameters, &inputs.block_hash),
        parameters.element_from_u64(inputs.round),
        element_from_bytes(parameters, &inputs.leader_proposal),
        parameters.element_from_u64(inputs.epoch),
        parameters.element_from_u64(inputs.slot),
        parameters.element_from_u64(inputs.quorum_threshold),
        element_from_bytes(parameters, &inputs.quorum_bitmap_root),
        element_from_bytes(parameters, &inputs.quorum_signature_root),
    ];
    for entry in &inputs.vrf_entries {
        fields.push(element_from_bytes(parameters, &entry.randomness));
        fields.push(element_from_bytes(parameters, &entry.derived_randomness));
        fields.push(element_from_bytes(parameters, &entry.pre_output));
        fields.push(element_from_bytes(parameters, &entry.proof));
        fields.push(element_from_bytes(parameters, &entry.public_key));
        fields.push(element_from_bytes(parameters, &entry.poseidon_digest));
        fields.push(element_from_bytes(
            parameters,
            &entry.poseidon_last_block_header,
        ));
        fields.push(parameters.element_from_u64(entry.poseidon_epoch));
        fields.push(element_from_bytes(parameters, &entry.poseidon_tier_seed));
    }
    for digest in &inputs.witness_commitments {
        fields.push(element_from_bytes(parameters, digest));
    }
    for digest in &inputs.reputation_roots {
        fields.push(element_from_bytes(parameters, digest));
    }
    let entry_len = inputs.vrf_entries.len() as u64;
    fields.push(parameters.element_from_u64(entry_len));
    fields.push(parameters.element_from_u64(inputs.witness_commitments.len() as u64));
    fields.push(parameters.element_from_u64(inputs.reputation_roots.len() as u64));
    fields.push(element_from_bytes(parameters, &inputs.vrf_output_binding));
    fields.push(element_from_bytes(parameters, &inputs.vrf_proof_binding));
    fields.push(element_from_bytes(
        parameters,
        &inputs.witness_commitment_binding,
    ));
    fields.push(element_from_bytes(
        parameters,
        &inputs.reputation_root_binding,
    ));
    fields.push(element_from_bytes(
        parameters,
        &inputs.quorum_bitmap_binding,
    ));
    fields.push(element_from_bytes(
        parameters,
        &inputs.quorum_signature_binding,
    ));
    fields
}
#[cfg(all(test, feature = "official"))]
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
    use crate::identity_tree::IDENTITY_TREE_DEPTH;
    use crate::official::circuit::consensus::{
        ConsensusCircuit, ConsensusVrfPoseidonInput, ConsensusVrfWitnessEntry, ConsensusWitness,
        VotePower,
    };
    use crate::official::circuit::identity::IdentityWitness;
    use crate::official::circuit::pruning::PruningWitness;
    use crate::official::circuit::recursive::{PrefixedDigest, RecursiveWitness};
    use crate::official::circuit::state::StateWitness;
    use crate::official::circuit::string_to_field;
    use crate::official::circuit::transaction::TransactionWitness;
    use crate::official::circuit::uptime::UptimeWitness;
    use crate::official::params::{FieldElement, StarkParameters};
    use crate::official::proof::ProofPayload;
    use crate::reputation::{ReputationWeights, Tier};
    use crate::state::compute_merkle_root;
    use crate::types::{Account, Stake, Transaction, UptimeProof};
    use crate::vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey as DalekVerifyingKey};
    use prover_backend_interface::{
        ConsensusCircuitDef, ConsensusPublicInputs, IdentityPublicInputs, ProofSystemKind,
        PruningPublicInputs, RecursivePublicInputs, StatePublicInputs, TxPublicInputs,
        UptimePublicInputs, VerifyingKey, WitnessBytes, WitnessHeader,
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use rpp_pruning::{
        TaggedDigest, COMMITMENT_TAG, DIGEST_LENGTH, DOMAIN_TAG_LENGTH, ENVELOPE_TAG,
        PROOF_SEGMENT_TAG,
    };

    const EMPTY_LEAF_DOMAIN: &[u8] = b"rpp-zsi-empty-leaf";
    const NODE_DOMAIN: &[u8] = b"rpp-zsi-node";

    #[derive(Clone)]
    enum CircuitFixture {
        Transaction(TransactionWitness),
        Identity(IdentityWitness),
        State(StateWitness),
        Pruning(PruningWitness),
        Recursive(RecursiveWitness),
        Uptime(UptimeWitness),
        Consensus(ConsensusWitness),
    }

    impl CircuitFixture {
        fn matrix() -> Vec<Self> {
            vec![
                Self::Transaction(sample_transaction_witness()),
                Self::Identity(sample_identity_witness()),
                Self::State(sample_state_witness()),
                Self::Pruning(sample_pruning_witness()),
                Self::Recursive(sample_recursive_witness()),
                Self::Uptime(sample_uptime_witness()),
                Self::Consensus(sample_consensus_witness()),
            ]
        }

        fn name(&self) -> &'static str {
            match self {
                CircuitFixture::Transaction(_) => "transaction",
                CircuitFixture::Identity(_) => "identity",
                CircuitFixture::State(_) => "state",
                CircuitFixture::Pruning(_) => "pruning",
                CircuitFixture::Recursive(_) => "recursive",
                CircuitFixture::Uptime(_) => "uptime",
                CircuitFixture::Consensus(_) => "consensus",
            }
        }

        fn circuit(&self) -> SupportedCircuit {
            match self {
                CircuitFixture::Transaction(_) => SupportedCircuit::Transaction,
                CircuitFixture::Identity(_) => SupportedCircuit::Identity,
                CircuitFixture::State(_) => SupportedCircuit::State,
                CircuitFixture::Pruning(_) => SupportedCircuit::Pruning,
                CircuitFixture::Recursive(_) => SupportedCircuit::Recursive,
                CircuitFixture::Uptime(_) => SupportedCircuit::Uptime,
                CircuitFixture::Consensus(_) => SupportedCircuit::Consensus,
            }
        }

        fn witness_bytes(&self) -> WitnessBytes {
            match self {
                CircuitFixture::Transaction(witness) => encode_tx_witness(witness),
                CircuitFixture::Identity(witness) => encode_identity_witness(witness),
                CircuitFixture::State(witness) => encode_state_witness(witness),
                CircuitFixture::Pruning(witness) => encode_pruning_witness(witness),
                CircuitFixture::Recursive(witness) => encode_recursive_witness(witness),
                CircuitFixture::Uptime(witness) => encode_uptime_witness(witness),
                CircuitFixture::Consensus(witness) => encode_consensus_witness(witness),
            }
        }

        fn expected_public_inputs(
            &self,
            proof: &ProofPayload,
            raw_inputs: &[String],
        ) -> CircuitPublicInputs {
            match (self, proof) {
                (CircuitFixture::Transaction(_), ProofPayload::Transaction(_)) => {
                    let inputs = tx_public_inputs_from_fields(raw_inputs);
                    CircuitPublicInputs::Transaction(inputs)
                }
                (CircuitFixture::Identity(witness), ProofPayload::Identity(_)) => {
                    CircuitPublicInputs::Identity(identity_public_inputs(witness))
                }
                (CircuitFixture::State(witness), ProofPayload::State(_)) => {
                    CircuitPublicInputs::State(state_public_inputs(witness))
                }
                (CircuitFixture::Pruning(witness), ProofPayload::Pruning(_)) => {
                    CircuitPublicInputs::Pruning(pruning_public_inputs(witness))
                }
                (CircuitFixture::Recursive(witness), ProofPayload::Recursive(_)) => {
                    CircuitPublicInputs::Recursive(recursive_public_inputs(witness))
                }
                (CircuitFixture::Uptime(witness), ProofPayload::Uptime(_)) => {
                    CircuitPublicInputs::Uptime(uptime_public_inputs(witness))
                }
                (CircuitFixture::Consensus(witness), ProofPayload::Consensus(_)) => {
                    CircuitPublicInputs::Consensus(consensus_public_inputs(witness))
                }
                (fixture, payload) => panic!(
                    "fixture '{}' expected matching proof payload, found {payload:?}",
                    fixture.name(),
                ),
            }
        }

        fn tamper_public_inputs(&self, inputs: &mut CircuitPublicInputs) {
            match (self, inputs) {
                (CircuitFixture::Transaction(_), CircuitPublicInputs::Transaction(inputs)) => {
                    flip_first_byte(&mut inputs.transaction_commitment)
                }
                (CircuitFixture::Identity(_), CircuitPublicInputs::Identity(inputs)) => {
                    flip_first_byte(&mut inputs.wallet_address)
                }
                (CircuitFixture::State(_), CircuitPublicInputs::State(inputs)) => {
                    flip_first_byte(&mut inputs.new_state_root)
                }
                (CircuitFixture::Pruning(_), CircuitPublicInputs::Pruning(inputs)) => {
                    inputs.removed_transactions += 1;
                }
                (CircuitFixture::Recursive(_), CircuitPublicInputs::Recursive(inputs)) => {
                    inputs.transaction_commitments =
                        inputs.transaction_commitments.saturating_add(1);
                }
                (CircuitFixture::Uptime(_), CircuitPublicInputs::Uptime(inputs)) => {
                    flip_first_byte(&mut inputs.commitment)
                }
                (CircuitFixture::Consensus(_), CircuitPublicInputs::Consensus(inputs)) => {
                    if let Some(entry) = inputs.vrf_entries.first_mut() {
                        if let Some(byte) = entry.randomness.first_mut() {
                            *byte ^= 0xff;
                        }
                    }
                }
                _ => panic!(
                    "public input variant does not match fixture {}",
                    self.name()
                ),
            }
        }

        fn malformed_witness(&self) -> WitnessBytes {
            match self {
                CircuitFixture::Transaction(witness) => {
                    let mut malformed = witness.clone();
                    malformed.sender_account.nonce = malformed.signed_tx.payload.nonce;
                    encode_tx_witness(&malformed)
                }
                CircuitFixture::Identity(witness) => {
                    let mut malformed = witness.clone();
                    flip_hex_string(&mut malformed.commitment);
                    encode_identity_witness(&malformed)
                }
                CircuitFixture::State(witness) => {
                    let mut malformed = witness.clone();
                    malformed.new_state_root = malformed.prev_state_root.clone();
                    encode_state_witness(&malformed)
                }
                CircuitFixture::Pruning(witness) => {
                    let mut malformed = witness.clone();
                    flip_hex_string(&mut malformed.pruning_fold);
                    encode_pruning_witness(&malformed)
                }
                CircuitFixture::Recursive(witness) => {
                    let mut malformed = witness.clone();
                    flip_hex_string(&mut malformed.aggregated_commitment);
                    encode_recursive_witness(&malformed)
                }
                CircuitFixture::Uptime(witness) => {
                    let mut malformed = witness.clone();
                    flip_hex_string(&mut malformed.commitment);
                    encode_uptime_witness(&malformed)
                }
                CircuitFixture::Consensus(witness) => {
                    let mut malformed = witness.clone();
                    if let Some(entry) = malformed.vrf_entries.first_mut() {
                        entry.proof = "zz".into();
                    }
                    encode_consensus_witness(&malformed)
                }
            }
        }
    }

    #[derive(Debug)]
    enum CircuitPublicInputs {
        Transaction(TxPublicInputs),
        Identity(IdentityPublicInputs),
        State(StatePublicInputs),
        Pruning(PruningPublicInputs),
        Recursive(RecursivePublicInputs),
        Uptime(UptimePublicInputs),
        Consensus(ConsensusPublicInputs),
    }

    fn flip_first_byte(bytes: &mut [u8; 32]) {
        if let Some(first) = bytes.first_mut() {
            *first ^= 0x01;
        }
    }

    fn flip_hex_string(value: &mut String) {
        if value.is_empty() {
            value.push_str("01");
            return;
        }

        let mut bytes = hex::decode(value).expect("hex string decodes");
        if let Some(first) = bytes.first_mut() {
            *first ^= 0x01;
        } else {
            bytes.push(1);
        }
        *value = hex::encode(bytes);
    }

    fn address_from_public_key(public_key: &DalekVerifyingKey) -> String {
        let hash: [u8; 32] =
            crate::proof_backend::Blake2sHasher::hash(public_key.as_bytes()).into();
        hex::encode(hash)
    }

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
    fn circuit_matrix_round_trips() {
        let backend = StwoBackend::new();

        for fixture in CircuitFixture::matrix() {
            match fixture.clone() {
                CircuitFixture::Transaction(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Transaction);
                    let witness_bytes = encode_tx_witness(&witness);
                    let proof_bytes = backend
                        .prove_tx(&proving_key, &witness_bytes)
                        .expect("transaction proving succeeds");
                    let proof = decode_tx_proof(&proof_bytes).expect("transaction proof decodes");

                    match &proof.payload {
                        ProofPayload::Transaction(decoded) => assert_eq!(decoded, &witness),
                        other => panic!("unexpected payload variant: {other:?}"),
                    }

                    assert!(
                        proof.commitment_proof.to_official().is_some(),
                        "transaction commitment proof should be present"
                    );
                    assert!(
                        proof.fri_proof.to_official().is_some(),
                        "transaction FRI proof should be present"
                    );

                    let inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    match &inputs {
                        CircuitPublicInputs::Transaction(inputs) => {
                            let verified = backend
                                .verify_tx(
                                    &verifying_key(SupportedCircuit::Transaction),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect("transaction verification succeeds");
                            assert!(verified, "transaction verification should return true");
                        }
                        other => panic!(
                            "transaction fixture produced unexpected public inputs: {other:?}"
                        ),
                    }
                }
                CircuitFixture::Identity(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Identity);
                    let witness_bytes = encode_identity_witness(&witness);
                    let proof_bytes = backend
                        .prove_identity(&proving_key, &witness_bytes)
                        .expect("identity proving succeeds");
                    let proof =
                        decode_identity_proof(&proof_bytes).expect("identity proof decodes");

                    match &proof.payload {
                        ProofPayload::Identity(decoded) => assert_eq!(decoded, &witness),
                        other => panic!("unexpected payload variant: {other:?}"),
                    }

                    let inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    match &inputs {
                        CircuitPublicInputs::Identity(inputs) => {
                            backend
                                .verify_identity(
                                    &verifying_key(SupportedCircuit::Identity),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect("identity verification succeeds");
                        }
                        other => {
                            panic!("identity fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::State(witness) => {
                    let proving_key = proving_key(SupportedCircuit::State);
                    let witness_bytes = encode_state_witness(&witness);
                    let proof_bytes = backend
                        .prove_state(&proving_key, &witness_bytes)
                        .expect("state proving succeeds");
                    let proof = decode_state_proof(&proof_bytes).expect("state proof decodes");

                    match &proof.payload {
                        ProofPayload::State(decoded) => {
                            assert_eq!(decoded.prev_state_root, witness.prev_state_root)
                        }
                        other => panic!("unexpected payload variant: {other:?}"),
                    }

                    let inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    match &inputs {
                        CircuitPublicInputs::State(inputs) => {
                            backend
                                .verify_state(
                                    &verifying_key(SupportedCircuit::State),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect("state verification succeeds");
                        }
                        other => {
                            panic!("state fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::Pruning(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Pruning);
                    let witness_bytes = encode_pruning_witness(&witness);
                    let proof_bytes = backend
                        .prove_pruning(&proving_key, &witness_bytes)
                        .expect("pruning proving succeeds");
                    let proof = decode_pruning_proof(&proof_bytes).expect("pruning proof decodes");

                    match &proof.payload {
                        ProofPayload::Pruning(decoded) => {
                            assert_eq!(decoded.removed_transactions, witness.removed_transactions)
                        }
                        other => panic!("unexpected payload variant: {other:?}"),
                    }

                    let inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    match &inputs {
                        CircuitPublicInputs::Pruning(inputs) => {
                            backend
                                .verify_pruning(
                                    &verifying_key(SupportedCircuit::Pruning),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect("pruning verification succeeds");
                        }
                        other => {
                            panic!("pruning fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::Recursive(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Recursive);
                    let witness_bytes = encode_recursive_witness(&witness);
                    let decoded_witness = decode_recursive_witness(&witness_bytes)
                        .expect("recursive witness decodes");
                    assert_eq!(
                        decoded_witness.pruning_binding_digest,
                        witness.pruning_binding_digest
                    );
                    assert_eq!(
                        decoded_witness.pruning_segment_commitments,
                        witness.pruning_segment_commitments
                    );

                    let proof_bytes = backend
                        .prove_recursive(&proving_key, &witness_bytes)
                        .expect("recursive proving succeeds");
                    let proof =
                        decode_recursive_proof(&proof_bytes).expect("recursive proof decodes");

                    match &proof.payload {
                        ProofPayload::Recursive(decoded) => {
                            assert_eq!(decoded.aggregated_commitment, witness.aggregated_commitment)
                        }
                        other => panic!("unexpected payload variant: {other:?}"),
                    }

                    let inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    match &inputs {
                        CircuitPublicInputs::Recursive(inputs) => {
                            backend
                                .verify_recursive(
                                    &verifying_key(SupportedCircuit::Recursive),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect("recursive verification succeeds");
                        }
                        other => {
                            panic!("recursive fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::Uptime(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Uptime);
                    let witness_bytes = encode_uptime_witness(&witness);
                    let proof_bytes = backend
                        .prove_uptime(&proving_key, &witness_bytes)
                        .expect("uptime proving succeeds");
                    let proof = decode_uptime_proof(&proof_bytes).expect("uptime proof decodes");

                    match &proof.payload {
                        ProofPayload::Uptime(decoded) => assert_eq!(decoded, &witness),
                        other => panic!("unexpected payload variant: {other:?}"),
                    }

                    let inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    match &inputs {
                        CircuitPublicInputs::Uptime(inputs) => {
                            backend
                                .verify_uptime(
                                    &verifying_key(SupportedCircuit::Uptime),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect("uptime verification succeeds");
                        }
                        other => {
                            panic!("uptime fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::Consensus(witness) => {
                    let witness_bytes = encode_consensus_witness(&witness);
                    let (proof_bytes, verifying_key, circuit) = backend
                        .prove_consensus(&witness_bytes)
                        .expect("consensus proving succeeds");
                    let proof =
                        decode_consensus_proof(&proof_bytes).expect("consensus proof decodes");

                    match &proof.payload {
                        ProofPayload::Consensus(decoded) => assert_eq!(decoded, &witness),
                        other => panic!("unexpected payload variant: {other:?}"),
                    }

                    let inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    match &inputs {
                        CircuitPublicInputs::Consensus(inputs) => {
                            backend
                                .verify_consensus(&verifying_key, &proof_bytes, &circuit, inputs)
                                .expect("consensus verification succeeds");
                        }
                        other => {
                            panic!("consensus fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn circuit_matrix_rejects_public_input_tampering() {
        let backend = StwoBackend::new();

        for fixture in CircuitFixture::matrix() {
            match fixture.clone() {
                CircuitFixture::Transaction(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Transaction);
                    let witness_bytes = encode_tx_witness(&witness);
                    let proof_bytes = backend
                        .prove_tx(&proving_key, &witness_bytes)
                        .expect("transaction proving succeeds");
                    let proof = decode_tx_proof(&proof_bytes).expect("transaction proof decodes");

                    let mut inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    fixture.tamper_public_inputs(&mut inputs);
                    match &inputs {
                        CircuitPublicInputs::Transaction(inputs) => {
                            let err = backend
                                .verify_tx(
                                    &verifying_key(SupportedCircuit::Transaction),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect_err("tampered transaction inputs should fail");
                            assert!(matches!(err, BackendError::Failure(_)));
                        }
                        other => panic!(
                            "transaction fixture produced unexpected public inputs: {other:?}"
                        ),
                    }
                }
                CircuitFixture::Identity(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Identity);
                    let witness_bytes = encode_identity_witness(&witness);
                    let proof_bytes = backend
                        .prove_identity(&proving_key, &witness_bytes)
                        .expect("identity proving succeeds");
                    let proof =
                        decode_identity_proof(&proof_bytes).expect("identity proof decodes");

                    let mut inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    fixture.tamper_public_inputs(&mut inputs);
                    match &inputs {
                        CircuitPublicInputs::Identity(inputs) => {
                            let err = backend
                                .verify_identity(
                                    &verifying_key(SupportedCircuit::Identity),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect_err("tampered identity inputs should fail");
                            assert!(matches!(err, BackendError::Failure(_)));
                        }
                        other => {
                            panic!("identity fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::State(witness) => {
                    let proving_key = proving_key(SupportedCircuit::State);
                    let witness_bytes = encode_state_witness(&witness);
                    let proof_bytes = backend
                        .prove_state(&proving_key, &witness_bytes)
                        .expect("state proving succeeds");
                    let proof = decode_state_proof(&proof_bytes).expect("state proof decodes");

                    let mut inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    fixture.tamper_public_inputs(&mut inputs);
                    match &inputs {
                        CircuitPublicInputs::State(inputs) => {
                            let err = backend
                                .verify_state(
                                    &verifying_key(SupportedCircuit::State),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect_err("tampered state inputs should fail");
                            assert!(matches!(err, BackendError::Failure(_)));
                        }
                        other => {
                            panic!("state fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::Pruning(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Pruning);
                    let witness_bytes = encode_pruning_witness(&witness);
                    let proof_bytes = backend
                        .prove_pruning(&proving_key, &witness_bytes)
                        .expect("pruning proving succeeds");
                    let proof = decode_pruning_proof(&proof_bytes).expect("pruning proof decodes");

                    let mut inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    fixture.tamper_public_inputs(&mut inputs);
                    match &inputs {
                        CircuitPublicInputs::Pruning(inputs) => {
                            let err = backend
                                .verify_pruning(
                                    &verifying_key(SupportedCircuit::Pruning),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect_err("tampered pruning inputs should fail");
                            assert!(matches!(err, BackendError::Failure(_)));
                        }
                        other => {
                            panic!("pruning fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::Recursive(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Recursive);
                    let witness_bytes = encode_recursive_witness(&witness);
                    let proof_bytes = backend
                        .prove_recursive(&proving_key, &witness_bytes)
                        .expect("recursive proving succeeds");
                    let proof =
                        decode_recursive_proof(&proof_bytes).expect("recursive proof decodes");

                    let mut inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    fixture.tamper_public_inputs(&mut inputs);
                    match &inputs {
                        CircuitPublicInputs::Recursive(inputs) => {
                            let err = backend
                                .verify_recursive(
                                    &verifying_key(SupportedCircuit::Recursive),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect_err("tampered recursive inputs should fail");
                            assert!(matches!(err, BackendError::Failure(_)));
                        }
                        other => {
                            panic!("recursive fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::Uptime(witness) => {
                    let proving_key = proving_key(SupportedCircuit::Uptime);
                    let witness_bytes = encode_uptime_witness(&witness);
                    let proof_bytes = backend
                        .prove_uptime(&proving_key, &witness_bytes)
                        .expect("uptime proving succeeds");
                    let proof = decode_uptime_proof(&proof_bytes).expect("uptime proof decodes");

                    let mut inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    fixture.tamper_public_inputs(&mut inputs);
                    match &inputs {
                        CircuitPublicInputs::Uptime(inputs) => {
                            let err = backend
                                .verify_uptime(
                                    &verifying_key(SupportedCircuit::Uptime),
                                    &proof_bytes,
                                    inputs,
                                )
                                .expect_err("tampered uptime inputs should fail");
                            assert!(matches!(err, BackendError::Failure(_)));
                        }
                        other => {
                            panic!("uptime fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
                CircuitFixture::Consensus(witness) => {
                    let witness_bytes = encode_consensus_witness(&witness);
                    let (proof_bytes, verifying_key, circuit) = backend
                        .prove_consensus(&witness_bytes)
                        .expect("consensus proving succeeds");
                    let proof =
                        decode_consensus_proof(&proof_bytes).expect("consensus proof decodes");

                    let mut inputs =
                        fixture.expected_public_inputs(&proof.payload, &proof.public_inputs);
                    fixture.tamper_public_inputs(&mut inputs);
                    match &inputs {
                        CircuitPublicInputs::Consensus(inputs) => {
                            let err = backend
                                .verify_consensus(&verifying_key, &proof_bytes, &circuit, inputs)
                                .expect_err("tampered consensus inputs should fail");
                            assert!(matches!(err, BackendError::Failure(_)));
                        }
                        other => {
                            panic!("consensus fixture produced unexpected public inputs: {other:?}")
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn circuit_matrix_rejects_malformed_witnesses() {
        let backend = StwoBackend::new();

        for fixture in CircuitFixture::matrix() {
            let malformed = fixture.malformed_witness();
            match fixture.circuit() {
                SupportedCircuit::Transaction => {
                    let proving_key = proving_key(SupportedCircuit::Transaction);
                    let err = backend
                        .prove_tx(&proving_key, &malformed)
                        .expect_err("malformed transaction witness should fail");
                    match err {
                        BackendError::Failure(message) => assert!(
                            message.contains("nonce"),
                            "unexpected transaction failure message: {message}"
                        ),
                        other => panic!("unexpected backend error variant: {other:?}"),
                    }
                }
                SupportedCircuit::Identity => {
                    let proving_key = proving_key(SupportedCircuit::Identity);
                    let err = backend
                        .prove_identity(&proving_key, &malformed)
                        .expect_err("malformed identity witness should fail");
                    assert!(matches!(err, BackendError::Failure(_)));
                }
                SupportedCircuit::State => {
                    let proving_key = proving_key(SupportedCircuit::State);
                    let err = backend
                        .prove_state(&proving_key, &malformed)
                        .expect_err("malformed state witness should fail");
                    assert!(matches!(err, BackendError::Failure(_)));
                }
                SupportedCircuit::Pruning => {
                    let proving_key = proving_key(SupportedCircuit::Pruning);
                    let err = backend
                        .prove_pruning(&proving_key, &malformed)
                        .expect_err("malformed pruning witness should fail");
                    assert!(matches!(err, BackendError::Failure(_)));
                }
                SupportedCircuit::Recursive => {
                    let proving_key = proving_key(SupportedCircuit::Recursive);
                    let err = backend
                        .prove_recursive(&proving_key, &malformed)
                        .expect_err("malformed recursive witness should fail");
                    assert!(matches!(err, BackendError::Failure(_)));
                }
                SupportedCircuit::Uptime => {
                    let proving_key = proving_key(SupportedCircuit::Uptime);
                    let err = backend
                        .prove_uptime(&proving_key, &malformed)
                        .expect_err("malformed uptime witness should fail");
                    assert!(matches!(err, BackendError::Failure(_)));
                }
                SupportedCircuit::Consensus => {
                    let err = backend
                        .prove_consensus(&malformed)
                        .expect_err("malformed consensus witness should fail");
                    assert!(matches!(err, BackendError::Failure(_)));
                }
            }
        }
    }

    #[test]
    fn consensus_public_inputs_rebuild_matches_circuit_vector() {
        let parameters = StarkParameters::blueprint_default();
        let witness = sample_consensus_witness();
        let public_inputs = consensus_public_inputs(&witness);
        let rebuilt = rebuild_consensus_public_inputs(&parameters, &public_inputs, &witness);
        let circuit_inputs = ConsensusCircuit::public_inputs(&parameters, &witness)
            .expect("consensus circuit public inputs");

        assert_eq!(rebuilt, circuit_inputs);
    }

    #[test]
    fn consensus_verification_rejects_vrf_tampering() {
        let backend = StwoBackend::new();
        let mut witness = sample_consensus_witness();
        witness.vrf_entries = vec![ConsensusVrfWitnessEntry {
            randomness: "22".repeat(32),
            pre_output: "23".repeat(VRF_PREOUTPUT_LENGTH),
            proof: "33".repeat(VRF_PROOF_LENGTH),
            public_key: "24".repeat(32),
            input: ConsensusVrfPoseidonInput {
                last_block_header: witness.block_hash.clone(),
                epoch: witness.epoch,
                tier_seed: "25".repeat(32),
            },
        }];

        let header = WitnessHeader::new(ProofSystemKind::Stwo, "consensus");
        let witness_bytes =
            WitnessBytes::encode(&header, &witness).expect("consensus witness encodes");
        let (proof_bytes, verifying_key, circuit) = backend
            .prove_consensus(&witness_bytes)
            .expect("consensus proving succeeds");

        let mut public_inputs = consensus_public_inputs(&witness);
        public_inputs.vrf_entries[0].randomness[0] ^= 0xff;

        let err = backend
            .verify_consensus(&verifying_key, &proof_bytes, &circuit, &public_inputs)
            .expect_err("tampered vrf output should fail");
        assert!(matches!(err, BackendError::Failure(_)));
    }

    #[test]
    fn consensus_verification_rejects_swapped_vrf_proofs() {
        let backend = StwoBackend::new();
        let witness = sample_consensus_witness();
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "consensus");
        let witness_bytes =
            WitnessBytes::encode(&header, &witness).expect("consensus witness encodes");
        let (proof_bytes, verifying_key, circuit) = backend
            .prove_consensus(&witness_bytes)
            .expect("consensus proving succeeds");

        let mut public_inputs = consensus_public_inputs(&witness);
        let (first, rest) = public_inputs
            .vrf_entries
            .split_first_mut()
            .expect("at least one vrf entry");
        let second = rest
            .first_mut()
            .expect("second vrf entry available for swap");
        std::mem::swap(&mut first.proof, &mut second.proof);

        let err = backend
            .verify_consensus(&verifying_key, &proof_bytes, &circuit, &public_inputs)
            .expect_err("swapped vrf proofs should fail");
        assert!(matches!(err, BackendError::Failure(_)));
    }

    #[test]
    fn consensus_verification_rejects_corrupted_vrf_proof_bytes() {
        let backend = StwoBackend::new();
        let witness = sample_consensus_witness();
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "consensus");
        let witness_bytes =
            WitnessBytes::encode(&header, &witness).expect("consensus witness encodes");
        let (proof_bytes, verifying_key, circuit) = backend
            .prove_consensus(&witness_bytes)
            .expect("consensus proving succeeds");

        let mut public_inputs = consensus_public_inputs(&witness);
        let first = public_inputs
            .vrf_entries
            .first_mut()
            .expect("at least one vrf entry");
        if let Some(byte) = first.proof.first_mut() {
            *byte ^= 0x01;
        }

        let err = backend
            .verify_consensus(&verifying_key, &proof_bytes, &circuit, &public_inputs)
            .expect_err("corrupted vrf proof byte should fail");
        assert!(matches!(err, BackendError::Failure(_)));
    }

    #[test]
    fn consensus_verification_rejects_quorum_bitmap_tampering() {
        let backend = StwoBackend::new();
        let witness = sample_consensus_witness();
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "consensus");
        let witness_bytes =
            WitnessBytes::encode(&header, &witness).expect("consensus witness encodes");
        let (proof_bytes, verifying_key, circuit) = backend
            .prove_consensus(&witness_bytes)
            .expect("consensus proving succeeds");

        let mut public_inputs = consensus_public_inputs(&witness);
        public_inputs.quorum_bitmap_root[0] ^= 0x01;

        let err = backend
            .verify_consensus(&verifying_key, &proof_bytes, &circuit, &public_inputs)
            .expect_err("tampered quorum bitmap root should fail");
        assert!(matches!(err, BackendError::Failure(_)));
    }

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

    fn encode_consensus_witness(witness: &ConsensusWitness) -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "consensus");
        WitnessBytes::encode(&header, witness).expect("witness encodes")
    }

    fn tx_public_inputs_from_fields(fields: &[String]) -> TxPublicInputs {
        assert!(
            fields.len() >= 8,
            "transaction public inputs must encode at least eight field elements",
        );

        let mut utxo_root = [0u8; 32];
        let mut transaction_commitment = [0u8; 32];

        for (index, field) in fields.iter().take(4).enumerate() {
            let chunk = field_chunk_bytes(field);
            utxo_root[index * 8..(index + 1) * 8].copy_from_slice(&chunk);
        }

        for (index, field) in fields.iter().skip(4).take(4).enumerate() {
            let chunk = field_chunk_bytes(field);
            transaction_commitment[index * 8..(index + 1) * 8].copy_from_slice(&chunk);
        }

        TxPublicInputs {
            utxo_root,
            transaction_commitment,
        }
    }

    fn field_chunk_bytes(value: &str) -> [u8; 8] {
        let mut chunk = [0u8; 8];
        if value.is_empty() {
            return chunk;
        }

        let decoded = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
        let take = decoded.len().min(chunk.len());
        let start = chunk.len() - take;
        chunk[start..].copy_from_slice(&decoded[decoded.len() - take..]);
        chunk
    }

    fn sample_transaction_witness() -> TransactionWitness {
        let mut rng = StdRng::seed_from_u64(0xdead_beef_u64);
        let mut secret = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let sender = address_from_public_key(&verifying_key);
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
        let signature = signing_key.sign(&payload.canonical_bytes());
        let signed_tx =
            crate::types::SignedTransaction::new(payload.clone(), signature, &verifying_key);

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

        let defaults = identity_default_nodes();
        let identity_leaf = hex::encode(defaults[IDENTITY_TREE_DEPTH]);
        let identity_path = identity_siblings(&defaults, &wallet_addr);
        let identity_root = hex::encode(defaults[0]);

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

    fn sample_pruning_digests() -> (PrefixedDigest, Vec<PrefixedDigest>) {
        let binding = TaggedDigest::new(ENVELOPE_TAG, [0x44u8; DIGEST_LENGTH]).prefixed_bytes();
        let segments = vec![
            TaggedDigest::new(PROOF_SEGMENT_TAG, [0x56u8; DIGEST_LENGTH]).prefixed_bytes(),
            TaggedDigest::new(PROOF_SEGMENT_TAG, [0x57u8; DIGEST_LENGTH]).prefixed_bytes(),
        ];
        (binding, segments)
    }

    fn sample_pruning_witness() -> PruningWitness {
        let original = vec![hex::encode([0x55u8; 32]), hex::encode([0x66u8; 32])];
        let removed = vec![original[0].clone()];
        let previous_tx_root = merkle_root(&original);
        let pruned_tx_root = merkle_root(&original[1..].to_vec());

        let parameters = StarkParameters::blueprint_default();
        let hasher = parameters.poseidon_hasher();
        let (pruning_binding_digest, pruning_segment_commitments) = sample_pruning_digests();
        let accumulator = pruning_fold_from_canonical_bytes(
            &hasher,
            &parameters,
            &pruning_binding_digest,
            &pruning_segment_commitments,
        );

        PruningWitness {
            previous_tx_root,
            pruned_tx_root,
            original_transactions: original,
            removed_transactions: removed,
            pruning_binding_digest,
            pruning_segment_commitments,
            pruning_fold: accumulator.to_hex(),
        }
    }

    fn sample_recursive_witness() -> RecursiveWitness {
        let parameters = StarkParameters::blueprint_default();
        let identity_commitments = vec![parameters.element_from_u64(11).to_hex()];
        let tx_commitments = vec![parameters.element_from_u64(22).to_hex()];
        let uptime_commitments = vec![parameters.element_from_u64(33).to_hex()];
        let consensus_commitments = vec![parameters.element_from_u64(44).to_hex()];
        let state_commitment = parameters.element_from_u64(66).to_hex();
        let global_state_root = parameters.element_from_u64(77).to_hex();
        let utxo_root = parameters.element_from_u64(88).to_hex();
        let reputation_root = parameters.element_from_u64(99).to_hex();
        let timetoke_root = parameters.element_from_u64(111).to_hex();
        let zsi_root = parameters.element_from_u64(122).to_hex();
        let proof_root = parameters.element_from_u64(133).to_hex();
        let block_height = 9;
        let (pruning_binding_digest, pruning_segment_commitments) = sample_pruning_digests();

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
            pruning_binding_digest,
            pruning_segment_commitments,
            block_height,
        };

        let aggregated = recursive_aggregate(&parameters, &witness);
        witness.aggregated_commitment = aggregated.to_hex();
        witness
    }

    #[test]
    fn recursive_aggregate_depends_on_pruning_digests() {
        let parameters = StarkParameters::blueprint_default();
        let mut witness = sample_recursive_witness();
        let original = recursive_aggregate(&parameters, &witness);

        witness.pruning_binding_digest =
            TaggedDigest::new(ENVELOPE_TAG, [0x99; DIGEST_LENGTH]).prefixed_bytes();
        let mutated_binding = recursive_aggregate(&parameters, &witness);
        assert_ne!(
            original, mutated_binding,
            "binding digest must affect aggregate"
        );

        let mut witness = sample_recursive_witness();
        witness.pruning_segment_commitments[0] =
            TaggedDigest::new(PROOF_SEGMENT_TAG, [0x77; DIGEST_LENGTH]).prefixed_bytes();
        let mutated_segment = recursive_aggregate(&parameters, &witness);
        assert_ne!(
            original, mutated_segment,
            "segment commitments must affect aggregate"
        );
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
            epoch: 2,
            slot: 11,
            leader_proposal: block_hash.clone(),
            quorum_threshold: 12,
            pre_votes: votes.clone(),
            pre_commits: votes.clone(),
            commit_votes: votes,
            quorum_bitmap_root: "aa".repeat(32),
            quorum_signature_root: "bb".repeat(32),
            vrf_entries: vec![
                ConsensusVrfWitnessEntry {
                    randomness: "cc".repeat(32),
                    pre_output: "dd".repeat(VRF_PREOUTPUT_LENGTH),
                    proof: "ee".repeat(VRF_PROOF_LENGTH),
                    public_key: "ff".repeat(32),
                    input: ConsensusVrfPoseidonInput {
                        last_block_header: block_hash.clone(),
                        epoch: 2,
                        tier_seed: "11".repeat(32),
                    },
                },
                ConsensusVrfWitnessEntry {
                    randomness: "01".repeat(32),
                    pre_output: "02".repeat(VRF_PREOUTPUT_LENGTH),
                    proof: "03".repeat(VRF_PROOF_LENGTH),
                    public_key: "04".repeat(32),
                    input: ConsensusVrfPoseidonInput {
                        last_block_header: block_hash,
                        epoch: 2,
                        tier_seed: "05".repeat(32),
                    },
                },
            ],
            witness_commitments: vec!["12".repeat(32)],
            reputation_roots: vec!["13".repeat(32)],
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
        let parameters = StarkParameters::blueprint_default();
        let hasher = parameters.poseidon_hasher();
        let block_hash_field = string_to_field(&parameters, &witness.block_hash);
        let verified_outputs =
            parse_vrf_entries(witness).expect("consensus witness contains verified VRF outputs");
        let bindings = ConsensusCircuit::compute_binding_values(
            &parameters,
            &hasher,
            &block_hash_field,
            witness,
            &verified_outputs,
        )
        .expect("consensus VRF bindings");

        let vrf_entries = witness
            .vrf_entries
            .iter()
            .zip(verified_outputs.iter())
            .map(|(entry, output)| {
                let randomness = output.output.randomness;
                let derived_randomness = output.derived_randomness;
                let pre_output = output.output.preoutput;
                let proof = output.output.proof.to_vec();
                let public_key = hex_to_array(&entry.public_key);
                let last_block_header = hex_to_array(&entry.input.last_block_header);
                let epoch = entry.input.epoch;
                let tier_seed = hex_to_array(&entry.input.tier_seed);

                ConsensusVrfPublicEntry {
                    randomness,
                    derived_randomness,
                    pre_output,
                    proof,
                    public_key,
                    poseidon_digest: output.poseidon_digest,
                    poseidon_last_block_header: last_block_header,
                    poseidon_epoch: epoch,
                    poseidon_tier_seed: tier_seed,
                }
            })
            .collect();

        ConsensusPublicInputs {
            block_hash: hex_to_array(&witness.block_hash),
            round: witness.round,
            epoch: witness.epoch,
            slot: witness.slot,
            leader_proposal: hex_to_array(&witness.leader_proposal),
            quorum_threshold: witness.quorum_threshold,
            quorum_bitmap_root: hex_to_array(&witness.quorum_bitmap_root),
            quorum_signature_root: hex_to_array(&witness.quorum_signature_root),
            vrf_entries,
            witness_commitments: witness
                .witness_commitments
                .iter()
                .map(|value| hex_to_array(value))
                .collect(),
            reputation_roots: witness
                .reputation_roots
                .iter()
                .map(|value| hex_to_array(value))
                .collect(),
            vrf_output_binding: field_to_padded_bytes(&bindings.vrf_output),
            vrf_proof_binding: field_to_padded_bytes(&bindings.vrf_proof),
            witness_commitment_binding: field_to_padded_bytes(&bindings.witness_commitment),
            reputation_root_binding: field_to_padded_bytes(&bindings.reputation_root),
            quorum_bitmap_binding: field_to_padded_bytes(&bindings.quorum_bitmap),
            quorum_signature_binding: field_to_padded_bytes(&bindings.quorum_signature),
        }
    }

    fn identity_default_nodes() -> Vec<[u8; 32]> {
        let mut defaults = vec![[0u8; 32]; IDENTITY_TREE_DEPTH + 1];
        defaults[IDENTITY_TREE_DEPTH] = domain_hash(EMPTY_LEAF_DOMAIN, &[]);
        for level in (0..IDENTITY_TREE_DEPTH).rev() {
            let child = defaults[level + 1];
            defaults[level] = hash_children(&child, &child);
        }
        defaults
    }

    fn identity_siblings(defaults: &[[u8; 32]], wallet_addr: &str) -> Vec<String> {
        let mut siblings = Vec::with_capacity(IDENTITY_TREE_DEPTH);
        let mut index = derive_index(wallet_addr);
        for level in (0..IDENTITY_TREE_DEPTH).rev() {
            let sibling = defaults[level + 1];
            siblings.push(hex::encode(sibling));
            index /= 2;
        }
        siblings
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
        let pruning_fold = pruning_fold_from_canonical_bytes(
            &hasher,
            parameters,
            &witness.pruning_binding_digest,
            &witness.pruning_segment_commitments,
        );
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

        hasher.hash(&[previous, state_digest, pruning_fold, activity])
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

    fn domain_hash(label: &[u8], bytes: &[u8]) -> [u8; 32] {
        let mut data = Vec::with_capacity(label.len() + bytes.len());
        data.extend_from_slice(label);
        data.extend_from_slice(bytes);
        crate::proof_backend::Blake2sHasher::hash(&data).into()
    }

    fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(left);
        data.extend_from_slice(right);
        domain_hash(NODE_DOMAIN, &data)
    }

    fn derive_index(wallet_addr: &str) -> u64 {
        let hash: [u8; 32] =
            crate::proof_backend::Blake2sHasher::hash(wallet_addr.as_bytes()).into();
        u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) as u64
    }

    fn hex_to_array<const N: usize>(value: &str) -> [u8; N] {
        let bytes = hex::decode(value).expect("hex decodes");
        assert_eq!(bytes.len(), N, "hex string must encode {N} bytes");
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        array
    }

    fn hex_to_vec(value: &str) -> Vec<u8> {
        hex::decode(value).expect("hex decodes")
    }
}
