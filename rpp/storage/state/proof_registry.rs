use std::collections::BTreeMap;

use parking_lot::RwLock;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::rpp::ProofArtifact;
use crate::state::merkle::compute_merkle_root;

#[derive(Default)]
pub struct ProofRegistry {
    artifacts: RwLock<BTreeMap<Vec<u8>, ProofArtifact>>,
}

impl ProofRegistry {
    pub fn new() -> Self {
        Self {
            artifacts: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn register(&self, artifact: ProofArtifact) {
        let key = artifact.commitment.to_vec();
        self.artifacts.write().insert(key, artifact);
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .artifacts
            .read()
            .values()
            .map(|artifact| {
                let payload = serde_json::to_vec(artifact).expect("serialize proof artifact");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        if leaves.is_empty() {
            return Blake2sHasher::hash(b"rpp-proof-placeholder").into();
        }
        compute_merkle_root(&mut leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpp::{ProofArtifact, ProofModule};

    #[test]
    fn commitment_reflects_registered_artifacts() {
        let registry = ProofRegistry::new();
        let empty_commitment = registry.commitment();
        let placeholder: [u8; 32] = Blake2sHasher::hash(b"rpp-proof-placeholder").into();
        assert_eq!(empty_commitment, placeholder);

        let artifact = ProofArtifact {
            module: ProofModule::ConsensusWitness,
            commitment: [0xAB; 32],
            proof: vec![0x01, 0x02],
            verification_key: Some(vec![0xFF]),
        };
        registry.register(artifact);

        let updated = registry.commitment();
        assert_ne!(updated, placeholder);
        assert_ne!(updated, [0u8; 32]);
    }
}
