use std::time::{SystemTime, UNIX_EPOCH};

use std::str::FromStr;

use ed25519_dalek::{PublicKey, Signature};
use malachite::Natural;
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::consensus::{ConsensusCertificate, VrfProof, verify_vrf};
use crate::crypto::{signature_from_hex, signature_to_hex, verify_signature};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::compute_merkle_root;
use crate::stwo::verifier::NodeVerifier;

use super::{Address, BlockStarkProofs, SignedTransaction};

const PRUNING_WITNESS_DOMAIN: &[u8] = b"rpp-pruning-proof";
const RECURSIVE_ANCHOR_SEED: &[u8] = b"rpp-recursive-anchor";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub previous_hash: String,
    pub tx_root: String,
    pub state_root: String,
    pub total_stake: String,
    pub randomness: String,
    pub vrf_proof: String,
    pub timestamp: u64,
    pub proposer: Address,
}

impl BlockHeader {
    pub fn new(
        height: u64,
        previous_hash: String,
        tx_root: String,
        state_root: String,
        total_stake: String,
        randomness: String,
        vrf_proof: String,
        proposer: Address,
    ) -> Self {
        Self {
            height,
            previous_hash,
            tx_root,
            state_root,
            total_stake,
            randomness,
            vrf_proof,
            proposer,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializing block header")
    }

    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes();
        Blake2sHasher::hash(bytes.as_slice()).into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProofSystem {
    Stwo,
    Plonky3,
}

impl Default for ProofSystem {
    fn default() -> Self {
        ProofSystem::Stwo
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningProof {
    pub pruned_height: u64,
    pub previous_block_hash: String,
    pub previous_state_root: String,
    pub pruned_tx_root: String,
    pub resulting_state_root: String,
    pub witness_commitment: String,
}

impl PruningProof {
    fn witness(
        pruned_height: u64,
        previous_block_hash: &str,
        previous_state_root: &str,
        pruned_tx_root: &str,
        resulting_state_root: &str,
    ) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(PRUNING_WITNESS_DOMAIN);
        data.extend_from_slice(&pruned_height.to_be_bytes());
        data.extend_from_slice(previous_block_hash.as_bytes());
        data.extend_from_slice(previous_state_root.as_bytes());
        data.extend_from_slice(pruned_tx_root.as_bytes());
        data.extend_from_slice(resulting_state_root.as_bytes());
        hex::encode::<[u8; 32]>(Blake2sHasher::hash(&data).into())
    }

    pub fn new(
        pruned_height: u64,
        previous_block_hash: String,
        previous_state_root: String,
        pruned_tx_root: String,
        resulting_state_root: String,
    ) -> Self {
        let witness_commitment = Self::witness(
            pruned_height,
            &previous_block_hash,
            &previous_state_root,
            &pruned_tx_root,
            &resulting_state_root,
        );
        Self {
            pruned_height,
            previous_block_hash,
            previous_state_root,
            pruned_tx_root,
            resulting_state_root,
            witness_commitment,
        }
    }

    pub fn genesis(state_root: &str) -> Self {
        Self::new(
            0,
            hex::encode([0u8; 32]),
            state_root.to_string(),
            hex::encode([0u8; 32]),
            state_root.to_string(),
        )
    }

    pub fn from_previous(previous: Option<&Block>, current_header: &BlockHeader) -> Self {
        match previous {
            Some(block) => Self::new(
                block.header.height,
                block.hash.clone(),
                block.header.state_root.clone(),
                block.header.tx_root.clone(),
                current_header.state_root.clone(),
            ),
            None => Self::genesis(&current_header.state_root),
        }
    }

    pub fn verify(
        &self,
        previous: Option<&Block>,
        current_header: &BlockHeader,
    ) -> ChainResult<()> {
        if self.resulting_state_root != current_header.state_root {
            return Err(ChainError::Crypto(
                "pruning proof state root mismatch".into(),
            ));
        }
        if current_header.height == 0 {
            if self.pruned_height != 0 {
                return Err(ChainError::Crypto(
                    "genesis pruning proof references non-zero height".into(),
                ));
            }
        } else if current_header.height != self.pruned_height.saturating_add(1) {
            return Err(ChainError::Crypto("pruning proof height mismatch".into()));
        }
        if self.previous_block_hash != current_header.previous_hash {
            return Err(ChainError::Crypto(
                "pruning proof previous hash does not match header".into(),
            ));
        }
        if self.witness_commitment
            != Self::witness(
                self.pruned_height,
                &self.previous_block_hash,
                &self.previous_state_root,
                &self.pruned_tx_root,
                &self.resulting_state_root,
            )
        {
            return Err(ChainError::Crypto(
                "pruning proof commitment invalid".into(),
            ));
        }
        if let Some(previous_block) = previous {
            if previous_block.header.height != self.pruned_height {
                return Err(ChainError::Crypto(
                    "pruning proof references incorrect block height".into(),
                ));
            }
            if previous_block.hash != self.previous_block_hash {
                return Err(ChainError::Crypto(
                    "pruning proof references incorrect block hash".into(),
                ));
            }
            if previous_block.header.state_root != self.previous_state_root {
                return Err(ChainError::Crypto(
                    "pruning proof previous state root mismatch".into(),
                ));
            }
            if previous_block.header.tx_root != self.pruned_tx_root {
                return Err(ChainError::Crypto(
                    "pruning proof transaction commitment mismatch".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveProof {
    pub system: ProofSystem,
    pub proof_commitment: String,
    pub previous_proof_commitment: String,
    pub previous_chain_commitment: String,
    pub chain_commitment: String,
}

impl RecursiveProof {
    pub fn anchor() -> String {
        hex::encode::<[u8; 32]>(Blake2sHasher::hash(RECURSIVE_ANCHOR_SEED).into())
    }

    fn fold_chain(previous_chain: &str, header: &BlockHeader, pruning: &PruningProof) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(previous_chain.as_bytes());
        data.extend_from_slice(&header.hash());
        data.extend_from_slice(pruning.witness_commitment.as_bytes());
        data.extend_from_slice(header.state_root.as_bytes());
        hex::encode::<[u8; 32]>(Blake2sHasher::hash(&data).into())
    }

    fn fold_proof(chain_commitment: &str, previous_proof: &str) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(chain_commitment.as_bytes());
        data.extend_from_slice(previous_proof.as_bytes());
        hex::encode::<[u8; 32]>(Blake2sHasher::hash(&data).into())
    }

    pub fn genesis(header: &BlockHeader, pruning: &PruningProof) -> Self {
        let anchor = Self::anchor();
        let chain_commitment = Self::fold_chain(&anchor, header, pruning);
        let proof_commitment = Self::fold_proof(&chain_commitment, &anchor);
        Self {
            system: ProofSystem::default(),
            proof_commitment,
            previous_proof_commitment: anchor.clone(),
            previous_chain_commitment: anchor,
            chain_commitment,
        }
    }

    pub fn extend(previous: &RecursiveProof, header: &BlockHeader, pruning: &PruningProof) -> Self {
        let chain_commitment = Self::fold_chain(&previous.chain_commitment, header, pruning);
        let proof_commitment = Self::fold_proof(&chain_commitment, &previous.proof_commitment);
        Self {
            system: previous.system.clone(),
            proof_commitment,
            previous_proof_commitment: previous.proof_commitment.clone(),
            previous_chain_commitment: previous.chain_commitment.clone(),
            chain_commitment,
        }
    }

    pub fn verify(
        &self,
        header: &BlockHeader,
        pruning: &PruningProof,
        previous: Option<&RecursiveProof>,
    ) -> ChainResult<()> {
        if header.height == 0 {
            let anchor = Self::anchor();
            if self.previous_chain_commitment != anchor || self.previous_proof_commitment != anchor
            {
                return Err(ChainError::Crypto("recursive proof anchor mismatch".into()));
            }
        }

        if let Some(previous_proof) = previous {
            if self.previous_chain_commitment != previous_proof.chain_commitment {
                return Err(ChainError::Crypto(
                    "recursive proof does not link to previous chain commitment".into(),
                ));
            }
            if self.previous_proof_commitment != previous_proof.proof_commitment {
                return Err(ChainError::Crypto(
                    "recursive proof does not link to previous proof commitment".into(),
                ));
            }
        }

        let base_chain = previous
            .map(|proof| proof.chain_commitment.as_str())
            .unwrap_or(&self.previous_chain_commitment);
        let expected_chain = Self::fold_chain(base_chain, header, pruning);
        if expected_chain != self.chain_commitment {
            return Err(ChainError::Crypto(
                "recursive proof chain commitment mismatch".into(),
            ));
        }

        let proof_seed = previous
            .map(|proof| proof.proof_commitment.as_str())
            .unwrap_or(&self.previous_proof_commitment);
        let expected_proof = Self::fold_proof(&self.chain_commitment, proof_seed);
        if expected_proof != self.proof_commitment {
            return Err(ChainError::Crypto(
                "recursive proof commitment mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<SignedTransaction>,
    pub pruning_proof: PruningProof,
    pub recursive_proof: RecursiveProof,
    pub stark: BlockStarkProofs,
    pub signature: String,
    pub consensus: ConsensusCertificate,
    pub hash: String,
}

impl Block {
    pub fn new(
        header: BlockHeader,
        transactions: Vec<SignedTransaction>,
        pruning_proof: PruningProof,
        recursive_proof: RecursiveProof,
        stark: BlockStarkProofs,
        signature: Signature,
        consensus: ConsensusCertificate,
    ) -> Self {
        let hash = header.hash();
        Self {
            header,
            transactions,
            pruning_proof,
            recursive_proof,
            stark,
            signature: signature_to_hex(&signature),
            consensus,
            hash: hex::encode(hash),
        }
    }

    pub fn verify_signature(&self, public_key: &PublicKey) -> ChainResult<()> {
        let signature = signature_from_hex(&self.signature)?;
        verify_signature(public_key, &self.header.canonical_bytes(), &signature)
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.header.hash()
    }

    pub fn verify(&self, previous: Option<&Block>) -> ChainResult<()> {
        let mut tx_hashes = Vec::with_capacity(self.transactions.len());
        for tx in &self.transactions {
            tx.verify()?;
            tx_hashes.push(tx.hash());
        }
        let computed_root = compute_merkle_root(&mut tx_hashes);
        if hex::encode(computed_root) != self.header.tx_root {
            return Err(ChainError::Crypto("transaction root mismatch".into()));
        }

        if let Some(prev_block) = previous {
            if self.header.height != prev_block.header.height + 1 {
                return Err(ChainError::Crypto(
                    "invalid block height progression".into(),
                ));
            }
            if self.header.previous_hash != prev_block.hash {
                return Err(ChainError::Crypto("invalid previous block hash".into()));
            }
        }

        self.pruning_proof.verify(previous, &self.header)?;
        let previous_proof = previous.map(|block| &block.recursive_proof);
        self.recursive_proof
            .verify(&self.header, &self.pruning_proof, previous_proof)?;

        let verifier = NodeVerifier::new();
        let expected_previous_commitment =
            previous.map(|block| block.stark.recursive_proof.commitment.as_str());
        verifier.verify_bundle(
            &self.stark.transaction_proofs,
            &self.stark.state_proof,
            &self.stark.pruning_proof,
            &self.stark.recursive_proof,
            expected_previous_commitment,
        )?;

        if self.transactions.len() != self.stark.transaction_proofs.len() {
            return Err(ChainError::Crypto(
                "transaction/proof count mismatch in block".into(),
            ));
        }

        for (tx, proof) in self
            .transactions
            .iter()
            .zip(self.stark.transaction_proofs.iter())
        {
            match &proof.payload {
                crate::stwo::proof::ProofPayload::Transaction(witness)
                    if &witness.signed_tx == tx => {}
                _ => {
                    return Err(ChainError::Crypto(
                        "transaction proof payload does not match transaction".into(),
                    ));
                }
            }
        }

        self.verify_consensus(previous)?;
        Ok(())
    }

    fn verify_consensus(&self, previous: Option<&Block>) -> ChainResult<()> {
        let seed_bytes = if let Some(prev) = previous {
            hex::decode(&prev.hash).map_err(|err| {
                ChainError::Crypto(format!("invalid previous hash encoding: {err}"))
            })?
        } else {
            vec![0u8; 32]
        };
        if seed_bytes.len() != 32 {
            return Err(ChainError::Crypto("invalid VRF seed length".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let randomness = parse_natural(&self.header.randomness)?;
        let proof = VrfProof {
            randomness,
            proof: self.header.vrf_proof.clone(),
        };
        if !verify_vrf(&seed, self.header.height, &self.header.proposer, &proof) {
            return Err(ChainError::Crypto("invalid VRF proof".into()));
        }

        let total = parse_natural(&self.consensus.total_power)?;
        let quorum = parse_natural(&self.consensus.quorum_threshold)?;
        let prevote = parse_natural(&self.consensus.pre_vote_power)?;
        let precommit = parse_natural(&self.consensus.pre_commit_power)?;
        let commit = parse_natural(&self.consensus.commit_power)?;

        if prevote < quorum {
            return Err(ChainError::Crypto(
                "insufficient pre-vote power for quorum".into(),
            ));
        }
        if precommit < quorum {
            return Err(ChainError::Crypto(
                "insufficient pre-commit power for quorum".into(),
            ));
        }
        if commit < quorum {
            return Err(ChainError::Crypto(
                "insufficient commit power for quorum".into(),
            ));
        }
        if total < quorum {
            return Err(ChainError::Crypto("invalid quorum configuration".into()));
        }
        Ok(())
    }
}

fn parse_natural(value: &str) -> ChainResult<Natural> {
    Natural::from_str(value).map_err(|_| ChainError::Crypto("invalid natural encoding".into()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockMetadata {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
}

impl From<&Block> for BlockMetadata {
    fn from(block: &Block) -> Self {
        Self {
            height: block.header.height,
            hash: block.hash.clone(),
            timestamp: block.header.timestamp,
        }
    }
}
