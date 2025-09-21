use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::consensus::evaluate_vrf;
use crate::errors::{ChainError, ChainResult};
use crate::identity_tree::{IDENTITY_TREE_DEPTH, IdentityCommitmentProof};
use crate::stwo::circuit::identity::IdentityWitness;
use crate::stwo::circuit::string_to_field;
use crate::stwo::params::StarkParameters;
use crate::stwo::proof::{ProofKind, ProofPayload};
use crate::types::{Address, ChainProof};

/// Zero-knowledge backed genesis declaration for a sovereign identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityGenesis {
    /// Hex-encoded Ed25519 public key that anchors the identity.
    pub wallet_pk: String,
    /// Wallet address derived from the public key commitment.
    pub wallet_addr: Address,
    /// VRF tag binding the registration to an epoch-specific nonce.
    pub vrf_tag: String,
    /// Epoch nonce used when deriving the VRF tag (hex-encoded 32 bytes).
    pub epoch_nonce: String,
    /// State root the claimant observed when constructing the proof.
    pub state_root: String,
    /// Identity commitment tree root observed when constructing the proof.
    pub identity_root: String,
    /// Initial reputation (must be zero for a fresh identity).
    pub initial_reputation: i64,
    /// Merkle proof showing the wallet slot was vacant when the proof was built.
    pub commitment_proof: IdentityCommitmentProof,
}

/// Complete declaration broadcast to the network, including the ZK proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityDeclaration {
    pub genesis: IdentityGenesis,
    pub proof: IdentityProof,
}

/// Minimal representation of a ZK proof binding the genesis inputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityProof {
    /// Blake2s commitment over the public inputs of the ZK circuit.
    pub commitment: String,
    /// Deterministic STARK proof attesting to the identity constraints.
    pub zk_proof: ChainProof,
}

impl IdentityGenesis {
    /// Validates the structural properties of the genesis declaration.
    pub fn verify_inputs(&self) -> ChainResult<()> {
        let public_key_bytes = self.public_key_bytes()?;
        self.verify_wallet_address(&public_key_bytes)?;
        self.verify_initial_reputation()?;
        self.verify_vrf_tag()?;
        self.verify_root_encoding(&self.state_root, "state root")?;
        self.verify_root_encoding(&self.identity_root, "identity root")?;
        self.verify_commitment_proof()?;
        Ok(())
    }

    /// Returns the commitment of the public key used by the ZSI profile.
    pub fn public_key_commitment(&self) -> ChainResult<String> {
        let pk_bytes = self.public_key_bytes()?;
        Ok(hex::encode::<[u8; 32]>(
            Blake2sHasher::hash(&pk_bytes).into(),
        ))
    }

    /// Hashes the declaration for inclusion inside Merkle structures.
    pub fn hash(&self) -> ChainResult<[u8; 32]> {
        let encoded = serde_json::to_vec(self).map_err(|err| {
            ChainError::Transaction(format!(
                "failed to serialize identity genesis for hashing: {err}"
            ))
        })?;
        Ok(Blake2sHasher::hash(&encoded).into())
    }

    pub fn expected_commitment(&self) -> ChainResult<String> {
        let parameters = StarkParameters::blueprint_default();
        let hasher = parameters.poseidon_hasher();
        let inputs = vec![
            string_to_field(&parameters, &self.wallet_addr),
            string_to_field(&parameters, &self.vrf_tag),
            string_to_field(&parameters, &self.identity_root),
            string_to_field(&parameters, &self.state_root),
        ];
        Ok(hasher.hash(&inputs).to_hex())
    }

    pub fn public_key_bytes(&self) -> ChainResult<Vec<u8>> {
        hex::decode(&self.wallet_pk).map_err(|err| {
            ChainError::Transaction(format!("invalid wallet public key encoding: {err}"))
        })
    }

    fn verify_wallet_address(&self, pk_bytes: &[u8]) -> ChainResult<()> {
        let expected: [u8; 32] = Blake2sHasher::hash(pk_bytes).into();
        let expected_addr = hex::encode(expected);
        if expected_addr != self.wallet_addr {
            return Err(ChainError::Transaction(
                "wallet address does not match provided public key".into(),
            ));
        }
        Ok(())
    }

    fn verify_initial_reputation(&self) -> ChainResult<()> {
        if self.initial_reputation != 0 {
            return Err(ChainError::Transaction(
                "identity genesis must start with zero reputation".into(),
            ));
        }
        Ok(())
    }

    fn epoch_seed(&self) -> ChainResult<[u8; 32]> {
        let bytes = hex::decode(&self.epoch_nonce).map_err(|err| {
            ChainError::Transaction(format!("invalid epoch nonce encoding: {err}"))
        })?;
        if bytes.len() != 32 {
            return Err(ChainError::Transaction(
                "epoch nonce must encode exactly 32 bytes".into(),
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(seed)
    }

    fn verify_vrf_tag(&self) -> ChainResult<()> {
        let seed = self.epoch_seed()?;
        let proof = evaluate_vrf(&seed, 0, &self.wallet_addr, 0, None);
        if proof.proof != self.vrf_tag {
            return Err(ChainError::Transaction(
                "VRF tag does not match the provided wallet and epoch".into(),
            ));
        }
        Ok(())
    }

    fn verify_root_encoding(&self, value: &str, label: &str) -> ChainResult<()> {
        let bytes = hex::decode(value)
            .map_err(|err| ChainError::Transaction(format!("invalid {label} encoding: {err}")))?;
        if bytes.len() != 32 {
            return Err(ChainError::Transaction(format!(
                "{label} must encode exactly 32 bytes"
            )));
        }
        Ok(())
    }

    fn verify_commitment_proof(&self) -> ChainResult<()> {
        if self.commitment_proof.siblings.len() != IDENTITY_TREE_DEPTH {
            return Err(ChainError::Transaction(
                "identity commitment proof has invalid path length".into(),
            ));
        }
        if !self.commitment_proof.is_vacant()? {
            return Err(ChainError::Transaction(
                "identity slot must be vacant for genesis".into(),
            ));
        }
        let root = self.commitment_proof.compute_root(&self.wallet_addr)?;
        if root != self.identity_root {
            return Err(ChainError::Transaction(
                "identity commitment proof does not match advertised root".into(),
            ));
        }
        Ok(())
    }
}

impl IdentityDeclaration {
    /// Fully verifies the declaration, including the embedded proof.
    pub fn verify(&self) -> ChainResult<()> {
        self.genesis.verify_inputs()?;
        let expected_commitment = self.genesis.expected_commitment()?;
        self.proof.verify(&self.genesis, &expected_commitment)
    }

    /// Convenience accessor returning the proof commitment.
    pub fn commitment(&self) -> &str {
        &self.proof.commitment
    }

    /// Hashes the declaration for inclusion in Merkle accumulators.
    pub fn hash(&self) -> ChainResult<[u8; 32]> {
        let encoded = serde_json::to_vec(self).map_err(|err| {
            ChainError::Transaction(format!(
                "failed to serialize identity declaration for hashing: {err}"
            ))
        })?;
        Ok(Blake2sHasher::hash(&encoded).into())
    }

    /// Builds the witness representation used by the identity circuit.
    pub fn witness(&self) -> ChainResult<IdentityWitness> {
        Ok(IdentityWitness {
            wallet_pk: self.genesis.wallet_pk.clone(),
            wallet_addr: self.genesis.wallet_addr.clone(),
            vrf_tag: self.genesis.vrf_tag.clone(),
            epoch_nonce: self.genesis.epoch_nonce.clone(),
            state_root: self.genesis.state_root.clone(),
            identity_root: self.genesis.identity_root.clone(),
            initial_reputation: self.genesis.initial_reputation,
            commitment: self.proof.commitment.clone(),
            identity_leaf: self.genesis.commitment_proof.leaf.clone(),
            identity_path: self.genesis.commitment_proof.siblings.clone(),
        })
    }
}

impl IdentityProof {
    pub fn verify(&self, genesis: &IdentityGenesis, expected_commitment: &str) -> ChainResult<()> {
        if self.commitment != expected_commitment {
            return Err(ChainError::Transaction(
                "identity proof commitment mismatch".into(),
            ));
        }
        let stark_proof = self.zk_proof.expect_stwo()?;
        if stark_proof.commitment != self.commitment {
            return Err(ChainError::Transaction(
                "embedded proof commitment does not match declared commitment".into(),
            ));
        }
        if stark_proof.kind != ProofKind::Identity {
            return Err(ChainError::Transaction(
                "embedded proof is not an identity proof".into(),
            ));
        }
        match &stark_proof.payload {
            ProofPayload::Identity(witness) => {
                if witness.wallet_pk != genesis.wallet_pk
                    || witness.wallet_addr != genesis.wallet_addr
                    || witness.vrf_tag != genesis.vrf_tag
                    || witness.epoch_nonce != genesis.epoch_nonce
                    || witness.state_root != genesis.state_root
                    || witness.identity_root != genesis.identity_root
                    || witness.initial_reputation != genesis.initial_reputation
                    || witness.commitment != self.commitment
                    || witness.identity_leaf != genesis.commitment_proof.leaf
                    || witness.identity_path != genesis.commitment_proof.siblings
                {
                    return Err(ChainError::Transaction(
                        "identity witness does not match declaration".into(),
                    ));
                }
                Ok(())
            }
            _ => Err(ChainError::Transaction(
                "identity proof payload mismatch".into(),
            )),
        }
    }
}
