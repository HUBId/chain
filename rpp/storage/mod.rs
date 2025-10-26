use std::collections::HashSet;
use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use storage_firewood::api::StateUpdate;
use storage_firewood::kv::FirewoodKv;
use storage_firewood::pruning::{FirewoodPruner, PruningProof as FirewoodPruningProof};

use crate::errors::{ChainError, ChainResult};
use crate::rpp::UtxoOutpoint;
use crate::state::StoredUtxo;
use crate::types::{Account, Block, BlockMetadata, PruningProof, StoredBlock};

pub const STORAGE_SCHEMA_VERSION: u32 = 1;

const PREFIX_BLOCK: u8 = b'b';
const PREFIX_ACCOUNT: u8 = b'a';
const PREFIX_METADATA: u8 = b'm';
const TIP_HEIGHT_KEY: &[u8] = b"tip_height";
const TIP_HASH_KEY: &[u8] = b"tip_hash";
const TIP_TIMESTAMP_KEY: &[u8] = b"tip_timestamp";
const TIP_METADATA_KEY: &[u8] = b"tip_metadata";
const BLOCK_METADATA_PREFIX: &[u8] = b"block_metadata/";
const PRUNING_PROOF_PREFIX: &[u8] = b"pruning_proofs/";
pub(crate) const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";
const WALLET_UTXO_SNAPSHOT_KEY: &[u8] = b"wallet_utxo_snapshot";

const SCHEMA_ACCOUNTS: &str = "accounts";

#[derive(Clone, Debug)]
pub struct StateTransitionReceipt {
    pub previous_root: [u8; 32],
    pub new_root: [u8; 32],
    pub pruning_proof: Option<FirewoodPruningProof>,
}

pub struct Storage {
    kv: Arc<Mutex<FirewoodKv>>,
    pruner: Arc<Mutex<FirewoodPruner>>,
}

impl Storage {
    pub fn open(path: &Path) -> ChainResult<Self> {
        let kv = FirewoodKv::open(path)?;
        let storage = Self {
            kv: Arc::new(Mutex::new(kv)),
            pruner: Arc::new(Mutex::new(FirewoodPruner::new(8))),
        };
        storage.ensure_schema_supported()?;
        Ok(storage)
    }

    fn ensure_schema_supported(&self) -> ChainResult<()> {
        let version = self.read_schema_version()?;
        match version {
            Some(version) if version > STORAGE_SCHEMA_VERSION => Err(ChainError::Config(format!(
                "database schema version {version} is newer than supported {STORAGE_SCHEMA_VERSION}"
            ))),
            Some(version) if version < STORAGE_SCHEMA_VERSION => {
                Err(ChainError::MigrationRequired {
                    found: version,
                    required: STORAGE_SCHEMA_VERSION,
                })
            }
            Some(_) => Ok(()),
            None => {
                if self.is_empty()? {
                    self.write_schema_version(STORAGE_SCHEMA_VERSION)?;
                    Ok(())
                } else {
                    Err(ChainError::MigrationRequired {
                        found: 0,
                        required: STORAGE_SCHEMA_VERSION,
                    })
                }
            }
        }
    }

    fn is_empty(&self) -> ChainResult<bool> {
        let kv = self.kv.lock();
        if kv.scan_prefix(&[PREFIX_BLOCK]).next().is_some() {
            return Ok(false);
        }
        if kv.scan_prefix(&[PREFIX_ACCOUNT]).next().is_some() {
            return Ok(false);
        }
        if kv.get(&metadata_key(TIP_HEIGHT_KEY)).is_some() {
            return Ok(false);
        }
        Ok(true)
    }

    fn read_schema_version(&self) -> ChainResult<Option<u32>> {
        let kv = self.kv.lock();
        Self::read_schema_version_raw(&kv)
    }

    pub fn schema_version(&self) -> ChainResult<u32> {
        Ok(self
            .read_schema_version()?
            .unwrap_or(STORAGE_SCHEMA_VERSION))
    }

    fn write_schema_version(&self, version: u32) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        Self::write_schema_version_raw(&mut kv, version)
    }

    pub(crate) fn write_schema_version_raw(kv: &mut FirewoodKv, version: u32) -> ChainResult<()> {
        kv.put(
            metadata_key(SCHEMA_VERSION_KEY),
            version.to_be_bytes().to_vec(),
        );
        kv.commit()?;
        Ok(())
    }

    pub(crate) fn read_schema_version_raw(kv: &FirewoodKv) -> ChainResult<Option<u32>> {
        match kv.get(&metadata_key(SCHEMA_VERSION_KEY)) {
            Some(bytes) => {
                let bytes: [u8; 4] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ChainError::Config("invalid schema version encoding".into()))?;
                Ok(Some(u32::from_be_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn open_db(path: &Path) -> ChainResult<FirewoodKv> {
        FirewoodKv::open(path).map_err(ChainError::from)
    }

    pub fn state_root(&self) -> ChainResult<[u8; 32]> {
        let kv = self.kv.lock();
        Ok(kv.root_hash())
    }

    pub fn read_metadata_blob(&self, key: &[u8]) -> ChainResult<Option<Vec<u8>>> {
        let kv = self.kv.lock();
        Ok(kv.get(&metadata_key(key)))
    }

    pub fn write_metadata_blob(&self, key: &[u8], value: Vec<u8>) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        kv.put(metadata_key(key), value);
        kv.commit()?;
        Ok(())
    }

    pub fn delete_metadata_blob(&self, key: &[u8]) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        kv.delete(&metadata_key(key));
        kv.commit()?;
        Ok(())
    }

    pub fn persist_pruning_proof(&self, height: u64, proof: &PruningProof) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        let data = bincode::serialize(proof)?;
        kv.put(metadata_key(&pruning_proof_suffix(height)), data);
        kv.commit()?;
        Ok(())
    }

    pub fn load_pruning_proof(&self, height: u64) -> ChainResult<Option<PruningProof>> {
        let kv = self.kv.lock();
        let key = metadata_key(&pruning_proof_suffix(height));
        Ok(match kv.get(&key) {
            Some(bytes) => Some(bincode::deserialize(&bytes)?),
            None => None,
        })
    }

    pub fn persist_utxo_snapshot(
        &self,
        snapshot: &[(UtxoOutpoint, StoredUtxo)],
    ) -> ChainResult<()> {
        let encoded = bincode::serialize(snapshot)?;
        self.write_metadata_blob(WALLET_UTXO_SNAPSHOT_KEY, encoded)
    }

    pub fn load_utxo_snapshot(&self) -> ChainResult<Option<Vec<(UtxoOutpoint, StoredUtxo)>>> {
        let maybe_bytes = self.read_metadata_blob(WALLET_UTXO_SNAPSHOT_KEY)?;
        let Some(bytes) = maybe_bytes else {
            return Ok(None);
        };
        let snapshot = bincode::deserialize(&bytes)?;
        Ok(Some(snapshot))
    }

    fn schema_key(&self, schema: &str, key: Vec<u8>) -> ChainResult<Vec<u8>> {
        match schema {
            SCHEMA_ACCOUNTS => {
                let mut namespaced = Vec::with_capacity(1 + key.len());
                namespaced.push(PREFIX_ACCOUNT);
                namespaced.extend_from_slice(&key);
                Ok(namespaced)
            }
            other => Err(ChainError::Config(format!(
                "unsupported firewood schema '{}'",
                other
            ))),
        }
    }

    pub fn apply_state_updates(
        &self,
        block_height: Option<u64>,
        updates: Vec<StateUpdate>,
    ) -> ChainResult<StateTransitionReceipt> {
        let previous_root = self.state_root()?;
        if updates.is_empty() {
            let pruning_proof = block_height.and_then(|height| {
                let mut pruner = self.pruner.lock();
                let proof = pruner.prune_block(height, previous_root);
                Some(proof)
            });
            return Ok(StateTransitionReceipt {
                previous_root,
                new_root: previous_root,
                pruning_proof,
            });
        }

        let mut kv = self.kv.lock();
        for update in updates {
            let key = self.schema_key(&update.schema, update.key)?;
            if let Some(value) = update.value {
                kv.put(key, value);
            } else {
                kv.delete(&key);
            }
        }
        let new_root = kv.commit()?;
        drop(kv);
        let pruning_proof = block_height.map(|height| {
            let mut pruner = self.pruner.lock();
            pruner.prune_block(height, new_root)
        });
        Ok(StateTransitionReceipt {
            previous_root,
            new_root,
            pruning_proof,
        })
    }

    pub fn apply_account_snapshot(
        &self,
        block_height: Option<u64>,
        accounts: &[Account],
    ) -> ChainResult<StateTransitionReceipt> {
        let previous_root = self.state_root()?;
        let mut kv = self.kv.lock();
        let existing_keys: Vec<Vec<u8>> = kv
            .scan_prefix(&[PREFIX_ACCOUNT])
            .map(|(key, _)| key)
            .collect();
        let allowed: HashSet<String> = accounts
            .iter()
            .map(|account| account.address.clone())
            .collect();
        for key in existing_keys {
            if key.len() < 2 {
                continue;
            }
            if let Ok(address) = String::from_utf8(key[1..].to_vec()) {
                if !allowed.contains(&address) {
                    kv.delete(&key);
                }
            }
        }
        for account in accounts {
            let data = bincode::serialize(account)?;
            kv.put(account_key(&account.address), data);
        }
        let new_root = kv.commit()?;
        drop(kv);
        let pruning_proof = block_height.map(|height| {
            let mut pruner = self.pruner.lock();
            pruner.prune_block(height, new_root)
        });
        Ok(StateTransitionReceipt {
            previous_root,
            new_root,
            pruning_proof,
        })
    }

    pub fn store_block(&self, block: &Block, metadata: &BlockMetadata) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        let key = block_key(block.header.height);
        let record = StoredBlock::from_block(block);
        let data = bincode::serialize(&record)?;
        kv.put(key, data);
        let mut metadata = metadata.clone();
        Self::hydrate_metadata_from_block(block, &mut metadata);
        kv.put(
            metadata_key(TIP_HEIGHT_KEY),
            block.header.height.to_be_bytes().to_vec(),
        );
        kv.put(metadata_key(TIP_HASH_KEY), block.hash.as_bytes().to_vec());
        kv.put(
            metadata_key(TIP_TIMESTAMP_KEY),
            block.header.timestamp.to_be_bytes().to_vec(),
        );
        let encoded_metadata = bincode::serialize(&metadata)?;
        kv.put(metadata_key(TIP_METADATA_KEY), encoded_metadata.clone());
        kv.put(
            metadata_key(&block_metadata_suffix(block.header.height)),
            encoded_metadata,
        );
        kv.commit()?;
        Ok(())
    }

    pub fn read_block(&self, height: u64) -> ChainResult<Option<Block>> {
        let kv = self.kv.lock();
        let key = block_key(height);
        match kv.get(&key) {
            Some(value) => {
                let record: StoredBlock = bincode::deserialize(&value)?;
                Ok(Some(record.into_block()))
            }
            None => Ok(None),
        }
    }

    pub fn read_block_metadata(&self, height: u64) -> ChainResult<Option<BlockMetadata>> {
        let suffix = block_metadata_suffix(height);
        let key = metadata_key(&suffix);
        let maybe_bytes = {
            let kv = self.kv.lock();
            kv.get(&key)
        };
        if let Some(bytes) = maybe_bytes {
            let mut metadata: BlockMetadata = bincode::deserialize(&bytes)?;
            if metadata.height == 0 {
                metadata.height = height;
            }
            self.populate_metadata_from_block(height, &mut metadata)?;
            return Ok(Some(metadata));
        }
        if let Some(record) = self.read_block_record(height)? {
            let block = record.into_block();
            let mut metadata = BlockMetadata::from(&block);
            metadata.height = block.header.height;
            metadata.hash = block.hash.clone();
            metadata.timestamp = block.header.timestamp;
            Self::hydrate_metadata_from_block(&block, &mut metadata);
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn read_block_record(&self, height: u64) -> ChainResult<Option<StoredBlock>> {
        let kv = self.kv.lock();
        let key = block_key(height);
        match kv.get(&key) {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn load_blockchain(&self) -> ChainResult<Vec<Block>> {
        let kv = self.kv.lock();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[PREFIX_BLOCK]).collect();
        drop(kv);
        let mut blocks = Vec::new();
        for (_key, value) in entries {
            let record: StoredBlock = bincode::deserialize(&value)?;
            blocks.push(record.into_block());
        }
        blocks.sort_by_key(|block| block.header.height);
        Ok(blocks)
    }

    pub(crate) fn load_block_records_from(&self, start: u64) -> ChainResult<Vec<StoredBlock>> {
        let kv = self.kv.lock();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[PREFIX_BLOCK]).collect();
        drop(kv);
        let mut records = Vec::new();
        for (key, value) in entries {
            if key.len() != 1 + 8 {
                continue;
            }
            let height = u64::from_be_bytes(
                key[1..]
                    .try_into()
                    .map_err(|_| ChainError::Config("invalid block height encoding".into()))?,
            );
            if height < start {
                continue;
            }
            let record: StoredBlock = bincode::deserialize(&value)?;
            records.push(record);
        }
        records.sort_by_key(|record| record.height());
        Ok(records)
    }

    pub fn prune_block_payload(&self, height: u64) -> ChainResult<bool> {
        let mut kv = self.kv.lock();
        let key = block_key(height);
        let Some(value) = kv.get(&key) else {
            return Ok(false);
        };
        let mut record: StoredBlock = bincode::deserialize(&value)?;
        if record.payload.is_none() {
            return Ok(false);
        }
        record.prune_payload();
        let data = bincode::serialize(&record)?;
        kv.put(key, data);
        kv.commit()?;
        Ok(true)
    }

    pub fn persist_account(&self, account: &Account) -> ChainResult<()> {
        let update = StateUpdate {
            schema: SCHEMA_ACCOUNTS.to_string(),
            key: account.address.as_bytes().to_vec(),
            value: Some(bincode::serialize(account)?),
        };
        let _ = self.apply_state_updates(None, vec![update])?;
        Ok(())
    }

    pub fn read_account(&self, address: &str) -> ChainResult<Option<Account>> {
        let kv = self.kv.lock();
        match kv.get(&account_key(address)) {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn load_accounts(&self) -> ChainResult<Vec<Account>> {
        let kv = self.kv.lock();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[PREFIX_ACCOUNT]).collect();
        drop(kv);
        let mut accounts = Vec::new();
        for (_key, value) in entries {
            accounts.push(bincode::deserialize::<Account>(&value)?);
        }
        accounts.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(accounts)
    }

    pub fn tip(&self) -> ChainResult<Option<BlockMetadata>> {
        let kv = self.kv.lock();
        if let Some(metadata) = kv.get(&metadata_key(TIP_METADATA_KEY)) {
            let mut metadata: BlockMetadata = bincode::deserialize(&metadata)?;
            drop(kv);
            self.populate_metadata_from_block(metadata.height, &mut metadata)?;
            return Ok(Some(metadata));
        }

        let Some(height_bytes) = kv.get(&metadata_key(TIP_HEIGHT_KEY)) else {
            return Ok(None);
        };
        let hash_bytes = kv
            .get(&metadata_key(TIP_HASH_KEY))
            .ok_or_else(|| ChainError::Config("missing tip hash".into()))?;
        let timestamp_bytes = kv
            .get(&metadata_key(TIP_TIMESTAMP_KEY))
            .ok_or_else(|| ChainError::Config("missing tip timestamp".into()))?;
        let height = u64::from_be_bytes(
            height_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ChainError::Config("invalid tip height encoding".into()))?,
        );
        let hash = String::from_utf8(hash_bytes.to_vec())
            .map_err(|err| ChainError::Config(format!("invalid tip hash encoding: {err}")))?;
        let timestamp = u64::from_be_bytes(
            timestamp_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ChainError::Config("invalid tip timestamp encoding".into()))?,
        );

        let block_bytes = kv
            .get(&block_key(height))
            .ok_or_else(|| ChainError::Config("missing tip block record".into()))?;
        let record: StoredBlock = bincode::deserialize(&block_bytes)?;
        let block = record.into_block();
        let mut metadata = BlockMetadata::from(&block);
        metadata.height = height;
        metadata.hash = hash;
        metadata.timestamp = timestamp;
        Self::hydrate_metadata_from_block(&block, &mut metadata);
        if metadata.proof_hash.is_empty() {
            metadata.proof_hash = block.header.proof_root;
        }
        Ok(Some(metadata))
    }
}

impl Storage {
    fn populate_metadata_from_block(
        &self,
        height: u64,
        metadata: &mut BlockMetadata,
    ) -> ChainResult<()> {
        if let Some(record) = self.read_block_record(height)? {
            let block = record.into_block();
            Self::hydrate_metadata_from_block(&block, metadata);
        }
        Ok(())
    }

    fn hydrate_metadata_from_block(block: &Block, metadata: &mut BlockMetadata) {
        if metadata.height == 0 {
            metadata.height = block.header.height;
        }
        if metadata.hash.is_empty() {
            metadata.hash = block.hash.clone();
        }
        if metadata.timestamp == 0 {
            metadata.timestamp = block.header.timestamp;
        }
        if metadata.proof_hash.is_empty() {
            metadata.proof_hash = block.header.proof_root.clone();
        }
        if metadata.previous_state_root.is_empty() {
            metadata.previous_state_root = block.pruning_proof.snapshot_state_root_hex();
        }
        if metadata.new_state_root.is_empty() {
            metadata.new_state_root = block.header.state_root.clone();
        }
        if metadata.pruning.is_none() {
            metadata.pruning = Some(block.pruning_proof.envelope_metadata());
        }
    }
}

impl Clone for Storage {
    fn clone(&self) -> Self {
        Self {
            kv: self.kv.clone(),
            pruner: self.pruner.clone(),
        }
    }
}

fn block_key(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 8);
    key.push(PREFIX_BLOCK);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn account_key(address: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + address.len());
    key.push(PREFIX_ACCOUNT);
    key.extend_from_slice(address.as_bytes());
    key
}

fn metadata_key(suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + suffix.len());
    key.push(PREFIX_METADATA);
    key.extend_from_slice(suffix);
    key
}

fn block_metadata_suffix(height: u64) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(BLOCK_METADATA_PREFIX.len() + 8);
    suffix.extend_from_slice(BLOCK_METADATA_PREFIX);
    suffix.extend_from_slice(&height.to_be_bytes());
    suffix
}

fn pruning_proof_suffix(height: u64) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(PRUNING_PROOF_PREFIX.len() + 8);
    suffix.extend_from_slice(PRUNING_PROOF_PREFIX);
    suffix.extend_from_slice(&height.to_be_bytes());
    suffix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ConsensusCertificate;
    use crate::reputation::Tier;
    use crate::rpp::{ModuleWitnessBundle, ProofArtifact};
    use crate::state::merkle::compute_merkle_root;
    use crate::stwo::circuit::{
        pruning::PruningWitness, recursive::RecursiveWitness, state::StateWitness, ExecutionTrace,
    };
    use crate::stwo::proof::{
        CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
    };
    use crate::types::{
        Block, BlockHeader, BlockMetadata, BlockProofBundle, ChainProof, PruningProof,
        RecursiveProof,
    };
    use ed25519_dalek::Signature;
    use hex;
    use tempfile::tempdir;

    fn dummy_state_proof() -> StarkProof {
        StarkProof {
            kind: ProofKind::State,
            commitment: "11".repeat(32),
            public_inputs: Vec::new(),
            payload: ProofPayload::State(StateWitness {
                prev_state_root: "22".repeat(32),
                new_state_root: "33".repeat(32),
                identities: Vec::new(),
                transactions: Vec::new(),
                accounts_before: Vec::new(),
                accounts_after: Vec::new(),
                required_tier: Tier::Tl0,
                reputation_weights: crate::reputation::ReputationWeights::default(),
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    fn dummy_pruning_proof() -> StarkProof {
        StarkProof {
            kind: ProofKind::Pruning,
            commitment: "44".repeat(32),
            public_inputs: Vec::new(),
            payload: ProofPayload::Pruning(PruningWitness {
                previous_tx_root: "55".repeat(32),
                pruned_tx_root: "66".repeat(32),
                original_transactions: Vec::new(),
                removed_transactions: Vec::new(),
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    fn dummy_recursive_proof(
        previous_commitment: Option<String>,
        aggregated_commitment: String,
        header: &BlockHeader,
        pruning: &PruningProof,
    ) -> StarkProof {
        let previous_commitment = previous_commitment.or_else(|| Some(RecursiveProof::anchor()));
        StarkProof {
            kind: ProofKind::Recursive,
            commitment: aggregated_commitment.clone(),
            public_inputs: Vec::new(),
            payload: ProofPayload::Recursive(RecursiveWitness {
                previous_commitment,
                aggregated_commitment,
                identity_commitments: Vec::new(),
                tx_commitments: Vec::new(),
                uptime_commitments: Vec::new(),
                consensus_commitments: Vec::new(),
                state_commitment: header.state_root.clone(),
                global_state_root: header.state_root.clone(),
                utxo_root: header.utxo_root.clone(),
                reputation_root: header.reputation_root.clone(),
                timetoke_root: header.timetoke_root.clone(),
                zsi_root: header.zsi_root.clone(),
                proof_root: header.proof_root.clone(),
                pruning_commitment: pruning.binding_digest_hex(),
                block_height: header.height,
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    fn make_block(height: u64, previous: Option<&Block>) -> Block {
        let previous_hash = previous
            .map(|block| block.hash.clone())
            .unwrap_or_else(|| hex::encode([0u8; 32]));
        let mut tx_leaves: Vec<[u8; 32]> = Vec::new();
        let tx_root = hex::encode(compute_merkle_root(&mut tx_leaves));
        let state_root = hex::encode([height as u8 + 2; 32]);
        let utxo_root = hex::encode([height as u8 + 3; 32]);
        let reputation_root = hex::encode([height as u8 + 4; 32]);
        let timetoke_root = hex::encode([height as u8 + 5; 32]);
        let zsi_root = hex::encode([height as u8 + 6; 32]);
        let proof_root = hex::encode([height as u8 + 7; 32]);
        let header = BlockHeader::new(
            height,
            previous_hash,
            tx_root,
            state_root,
            utxo_root,
            reputation_root,
            timetoke_root,
            zsi_root,
            proof_root,
            "0".to_string(),
            height.to_string(),
            format!("vrfpk{:02}", height),
            format!("preout{:02}", height),
            format!("vrf{:02}", height),
            format!("proposer{:02}", height),
            Tier::Tl3.to_string(),
            height,
        );
        let pruning_proof = PruningProof::from_previous(previous, &header);
        let aggregated_commitment = hex::encode([height as u8 + 8; 32]);
        let previous_recursive_commitment =
            previous.map(|block| block.recursive_proof.commitment.clone());
        let recursive_stark = dummy_recursive_proof(
            previous_recursive_commitment.clone(),
            aggregated_commitment.clone(),
            &header,
            &pruning_proof,
        );
        let recursive_chain_proof = ChainProof::Stwo(recursive_stark.clone());
        let recursive_proof = match previous {
            Some(prev) => RecursiveProof::extend(
                &prev.recursive_proof,
                &header,
                &pruning_proof,
                &recursive_chain_proof,
            )
            .expect("recursive extend"),
            None => RecursiveProof::genesis(&header, &pruning_proof, &recursive_chain_proof)
                .expect("recursive genesis"),
        };
        let state_stark = dummy_state_proof();
        let pruning_stark = dummy_pruning_proof();
        let module_witnesses = ModuleWitnessBundle::default();
        let proof_artifacts = module_witnesses
            .expected_artifacts()
            .expect("expected artifacts")
            .into_iter()
            .map(|(module, commitment, payload)| ProofArtifact {
                module,
                commitment,
                proof: payload,
                verification_key: None,
            })
            .collect();
        let stark_bundle = BlockProofBundle::new(
            Vec::new(),
            ChainProof::Stwo(state_stark),
            ChainProof::Stwo(pruning_stark),
            recursive_chain_proof,
        );
        let signature = Signature::from_bytes(&[0u8; 64]).expect("signature bytes");
        let mut consensus = ConsensusCertificate::genesis();
        consensus.round = height;
        Block::new(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            module_witnesses,
            proof_artifacts,
            pruning_proof,
            recursive_proof,
            stark_bundle,
            signature,
            consensus,
            None,
        )
    }

    #[test]
    fn tip_metadata_persists_receipt_fields() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let genesis = make_block(0, None);
        let mut metadata = BlockMetadata::from(&genesis);
        metadata.previous_state_root = "aa".repeat(32);
        metadata.new_state_root = "bb".repeat(32);
        metadata.proof_hash = "dd".repeat(32);
        storage
            .store_block(&genesis, &metadata)
            .expect("store genesis");
        drop(storage);

        let reopened = Storage::open(temp_dir.path()).expect("reopen storage");
        let tip = reopened.tip().expect("tip").expect("metadata");
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, genesis.hash);
        assert_eq!(tip.previous_state_root, metadata.previous_state_root);
        assert_eq!(tip.new_state_root, metadata.new_state_root);
        assert_eq!(tip.proof_hash, metadata.proof_hash);
        assert_eq!(tip.pruning, metadata.pruning);
        assert_eq!(tip.recursive_commitment, metadata.recursive_commitment);
        assert_eq!(tip.recursive_anchor, metadata.recursive_anchor);
    }

    #[test]
    fn tip_metadata_falls_back_when_serialized_entry_missing() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let genesis = make_block(0, None);
        let metadata = BlockMetadata::from(&genesis);
        storage
            .store_block(&genesis, &metadata)
            .expect("store genesis");
        {
            let mut kv = storage.kv.lock();
            kv.delete(&metadata_key(TIP_METADATA_KEY));
            kv.commit().expect("commit deletion");
        }
        let tip = storage.tip().expect("tip").expect("metadata");
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, genesis.hash);
        assert_eq!(tip.timestamp, genesis.header.timestamp);
        assert_eq!(
            tip.previous_state_root,
            genesis.pruning_proof.snapshot_state_root_hex()
        );
        assert_eq!(tip.new_state_root, genesis.header.state_root);
        assert_eq!(tip.proof_hash, genesis.header.proof_root);
        let pruning = tip.pruning_metadata().expect("pruning metadata");
        assert_eq!(
            pruning.binding_digest.as_str(),
            genesis.pruning_proof.binding_digest_hex()
        );
        assert_eq!(
            pruning.commitment.aggregate_commitment.as_str(),
            genesis.pruning_proof.aggregate_commitment_hex()
        );
        assert_eq!(pruning.schema_version, genesis.pruning_proof.schema_version());
        assert_eq!(
            pruning.parameter_version,
            genesis.pruning_proof.parameter_version()
        );
        assert_eq!(tip.recursive_commitment, genesis.recursive_proof.commitment);
    }

    #[test]
    fn block_metadata_roundtrip_with_backfill() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let genesis = make_block(0, None);
        let mut metadata = BlockMetadata::from(&genesis);
        metadata.proof_hash.clear();
        storage
            .store_block(&genesis, &metadata)
            .expect("store block");

        let loaded = storage
            .read_block_metadata(genesis.header.height)
            .expect("read metadata")
            .expect("metadata exists");
        assert_eq!(loaded.height, genesis.header.height);
        assert_eq!(loaded.hash, genesis.hash);
        assert_eq!(loaded.timestamp, genesis.header.timestamp);
        assert_eq!(loaded.proof_hash, genesis.header.proof_root);
        assert_eq!(
            loaded.previous_state_root,
            genesis.pruning_proof.snapshot_state_root_hex()
        );
        assert_eq!(loaded.new_state_root, genesis.header.state_root);
        let pruning = loaded.pruning_metadata().expect("pruning metadata");
        assert_eq!(
            pruning.binding_digest.as_str(),
            genesis.pruning_proof.binding_digest_hex()
        );
        assert_eq!(
            pruning.commitment.aggregate_commitment.as_str(),
            genesis.pruning_proof.aggregate_commitment_hex()
        );
        assert_eq!(pruning.schema_version, genesis.pruning_proof.schema_version());
        assert_eq!(
            pruning.parameter_version,
            genesis.pruning_proof.parameter_version()
        );
    }
}
