use crate::proof_backend::{Blake2sHasher, ProofBytes, ProvingKey, WitnessBytes};
use prover_backend_interface::{BackendError, BackendResult, IdentityPublicInputs, ProofBackend};
use serde::{Deserialize, Serialize};

use super::bind::ZsiBinder;
use super::verify;

pub(crate) fn hash_bytes(input: &[u8]) -> [u8; 32] {
    Blake2sHasher::hash(input).into()
}

pub fn hash_hex(input: impl AsRef<[u8]>) -> String {
    hex::encode(hash_bytes(input.as_ref()))
}

/// Compact representation of a lifecycle proof artefact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleProof {
    pub backend: String,
    pub operation: String,
    pub witness_digest: String,
    pub proof_commitment: String,
    pub raw_proof: Vec<u8>,
}

impl LifecycleProof {
    fn new(operation: &str, backend: &str, witness: &[u8], proof: &ProofBytes) -> Self {
        let witness_digest = hash_hex(witness);
        let proof_commitment = hash_hex(proof.as_slice());
        Self {
            backend: backend.to_string(),
            operation: operation.to_string(),
            witness_digest,
            proof_commitment,
            raw_proof: proof.clone().into_inner(),
        }
    }
}

/// Generate a lifecycle proof for the provided witness and inputs.
pub fn generate<B: ProofBackend>(
    backend: &B,
    binder: &ZsiBinder,
    witness: WitnessBytes,
    inputs: IdentityPublicInputs,
) -> BackendResult<Option<LifecycleProof>> {
    match backend.prove_identity(&ProvingKey(Vec::new()), &witness) {
        Ok(proof) => {
            let proof_bytes = binder.encode_proof(&proof)?;
            verify::identity(backend, &proof_bytes, &inputs)?;
            Ok(Some(LifecycleProof::new(
                binder.operation().as_ref(),
                backend.name(),
                witness.as_slice(),
                &proof_bytes,
            )))
        }
        Err(BackendError::Unsupported(_)) => Ok(None),
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prover_backend_interface::{ProofBackend, ProofHeader, ProofSystemKind, ProvingKey};

    struct DummyBackend;

    impl ProofBackend for DummyBackend {
        fn name(&self) -> &'static str {
            "dummy"
        }

        fn prove_identity(
            &self,
            _pk: &ProvingKey,
            _witness: &WitnessBytes,
        ) -> BackendResult<ProofBytes> {
            Ok(ProofBytes::encode(
                &ProofHeader::new(ProofSystemKind::Mock, "dummy"),
                &vec![1u8, 2, 3],
            )?)
        }
    }

    #[test]
    fn lifecycle_proof_updates_digests_on_changes() {
        let backend = DummyBackend;
        let binder = ZsiBinder::new(&backend, ZsiOperation::Issue);
        let witness = binder.encode_witness(&"alice").expect("witness");
        let inputs = IdentityPublicInputs {
            wallet_address: [0u8; 32],
            vrf_tag: vec![],
            identity_root: [0u8; 32],
            state_root: [0u8; 32],
        };
        let proof_bytes = backend
            .prove_identity(&ProvingKey(Vec::new()), &witness)
            .expect("mock proof");
        let encoded = binder.encode_proof(&proof_bytes).expect("encode proof");

        let proof = LifecycleProof::new("issue", backend.name(), witness.as_slice(), &encoded);
        let mutated_witness = b"bob".to_vec();
        let mutated = LifecycleProof::new("issue", backend.name(), &mutated_witness, &encoded);
        assert_ne!(proof.witness_digest, mutated.witness_digest);

        let alternate_raw = ProofBytes::encode(
            &ProofHeader::new(ProofSystemKind::Mock, "dummy"),
            &vec![9u8, 9, 9],
        )
        .expect("alt proof");
        let alternate_encoded = binder
            .encode_proof(&alternate_raw)
            .expect("encode alternate proof");
        let alternate = LifecycleProof::new(
            "issue",
            backend.name(),
            witness.as_slice(),
            &alternate_encoded,
        );
        assert_ne!(proof.proof_commitment, alternate.proof_commitment);

        // Verify helper still validates the proof via mock backend.
        super::verify::identity(&backend, &encoded, &inputs).expect("verify");
    }
}
