use std::collections::{BTreeSet, HashMap, HashSet};

use crate::proof_backend::Blake2sHasher;
use serde::{Deserialize, Serialize};

use crate::consensus::{BftVoteKind, SignedBftVote};
use crate::crypto::{vrf_public_key_from_hex, VrfPublicKey};
use crate::errors::{ChainError, ChainResult};
use crate::identity_tree::{IdentityCommitmentProof, IDENTITY_TREE_DEPTH};
use crate::stwo::circuit::identity::IdentityWitness;
use crate::stwo::circuit::string_to_field;
use crate::stwo::params::StarkParameters;
use crate::stwo::proof::{ProofKind, ProofPayload};
use crate::types::{Address, ChainProof};
use crate::vrf::{self, PoseidonVrfInput, VrfProof};

/// Zero-knowledge backed genesis declaration for a sovereign identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityGenesis {
    /// Hex-encoded Ed25519 public key that anchors the identity.
    pub wallet_pk: String,
    /// Wallet address derived from the public key commitment.
    pub wallet_addr: Address,
    /// VRF public key used to validate the registration proof.
    pub vrf_public_key: String,
    /// VRF proof binding the registration to an epoch-specific nonce.
    pub vrf_proof: VrfProof,
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
        self.verify_vrf_proof()?;
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
            string_to_field(&parameters, self.vrf_tag()),
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

    fn verify_vrf_proof(&self) -> ChainResult<()> {
        let seed = self.epoch_seed()?;
        let public_key = self.vrf_public_key()?;
        let output = self
            .vrf_proof
            .to_vrf_output()
            .map_err(|err| ChainError::Crypto(format!("invalid VRF proof encoding: {err}")))?;
        let tier_seed = vrf::derive_tier_seed(&self.wallet_addr, 0);
        let input = PoseidonVrfInput::new(seed, 0, tier_seed);
        vrf::verify_vrf(&input, &public_key, &output)
            .map_err(|err| ChainError::Crypto(format!("VRF proof verification failed: {err}")))
    }

    fn vrf_public_key(&self) -> ChainResult<VrfPublicKey> {
        vrf_public_key_from_hex(&self.vrf_public_key)
    }

    pub fn vrf_tag(&self) -> &str {
        &self.vrf_proof.proof
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
            vrf_tag: self.genesis.vrf_tag().to_string(),
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
                    || witness.vrf_tag != genesis.vrf_tag()
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

pub const IDENTITY_ATTESTATION_QUORUM: usize = 3;
pub const IDENTITY_ATTESTATION_GOSSIP_MIN: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestedIdentityRequest {
    pub declaration: IdentityDeclaration,
    pub attested_votes: Vec<SignedBftVote>,
    pub gossip_confirmations: Vec<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationOutcome {
    pub identity_hash: String,
    pub approved_votes: Vec<SignedBftVote>,
    pub gossip_confirmations: Vec<Address>,
    pub slashable_validators: Vec<Address>,
}

impl AttestedIdentityRequest {
    pub fn identity_hash(&self) -> ChainResult<String> {
        Ok(hex::encode(self.declaration.hash()?))
    }

    pub fn verify(
        &self,
        expected_height: u64,
        quorum_threshold: usize,
        min_gossip: usize,
    ) -> ChainResult<AttestationOutcome> {
        self.declaration.verify()?;
        let identity_hash = self.identity_hash()?;
        let mut slashable = HashSet::new();
        let mut unique_votes: HashMap<Address, SignedBftVote> = HashMap::new();
        for vote in &self.attested_votes {
            let voter = vote.vote.voter.clone();
            if vote.verify().is_err() {
                slashable.insert(voter);
                continue;
            }
            if vote.vote.block_hash != identity_hash {
                slashable.insert(voter);
                continue;
            }
            if vote.vote.height != expected_height {
                slashable.insert(voter);
                continue;
            }
            if vote.vote.kind != BftVoteKind::PreCommit {
                slashable.insert(voter);
                continue;
            }
            unique_votes
                .entry(vote.vote.voter.clone())
                .or_insert_with(|| vote.clone());
        }
        if unique_votes.len() < quorum_threshold {
            return Err(ChainError::Transaction(
                "insufficient quorum power for identity attestation".into(),
            ));
        }
        let mut gossip = BTreeSet::new();
        for address in &self.gossip_confirmations {
            gossip.insert(address.clone());
        }
        if gossip.len() < min_gossip {
            return Err(ChainError::Transaction(
                "insufficient gossip confirmations for identity attestation".into(),
            ));
        }
        let mut approved_votes: Vec<SignedBftVote> = unique_votes.into_values().collect();
        approved_votes.sort_by(|a, b| a.vote.voter.cmp(&b.vote.voter));
        let mut gossip_confirmations: Vec<Address> = gossip.into_iter().collect();
        gossip_confirmations.sort();
        let mut slashable_validators: Vec<Address> = slashable.into_iter().collect();
        slashable_validators.sort();
        Ok(AttestationOutcome {
            identity_hash,
            approved_votes,
            gossip_confirmations,
            slashable_validators,
        })
    }
}
