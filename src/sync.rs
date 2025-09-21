use std::fs;
use std::path::{Path, PathBuf};

use hex;
use serde::Serialize;

#[cfg(test)]
use crate::reputation::Tier;

use crate::errors::{ChainError, ChainResult};
use crate::rpp::GlobalStateCommitments;
use crate::storage::Storage;
use crate::types::StoredBlock;
use crate::types::{Block, BlockMetadata, BlockPayload};

/// Interface that provides raw block payloads required for reconstruction.
pub trait PayloadProvider {
    fn fetch_payload(&self, request: &ReconstructionRequest) -> ChainResult<BlockPayload>;
}

/// Summary describing the state snapshot that anchors a reconstruction plan.
#[derive(Clone, Debug, Serialize)]
pub struct SnapshotSummary {
    pub height: u64,
    pub block_hash: String,
    pub commitments: GlobalStateCommitments,
    pub chain_commitment: String,
}

/// Expectations for the payload data associated with a pruned block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PayloadExpectations {
    pub transaction_proofs: usize,
    pub transaction_witnesses: usize,
    pub timetoke_witnesses: usize,
    pub reputation_witnesses: usize,
    pub zsi_witnesses: usize,
    pub consensus_witnesses: usize,
}

impl PayloadExpectations {
    fn from_record(record: &StoredBlock) -> Self {
        let witnesses = &record.envelope.module_witnesses;
        Self {
            transaction_proofs: record.envelope.stark.transaction_proofs.len(),
            transaction_witnesses: witnesses.transactions.len(),
            timetoke_witnesses: witnesses.timetoke.len(),
            reputation_witnesses: witnesses.reputation.len(),
            zsi_witnesses: witnesses.zsi.len(),
            consensus_witnesses: witnesses.consensus.len(),
        }
    }
}

/// Request describing the data required to hydrate a pruned block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReconstructionRequest {
    pub height: u64,
    pub block_hash: String,
    pub tx_root: String,
    pub state_root: String,
    pub utxo_root: String,
    pub reputation_root: String,
    pub timetoke_root: String,
    pub zsi_root: String,
    pub proof_root: String,
    pub pruning_commitment: String,
    pub aggregated_commitment: String,
    pub previous_commitment: Option<String>,
    pub payload_expectations: PayloadExpectations,
}

impl ReconstructionRequest {
    fn from_record(record: &StoredBlock) -> ChainResult<Self> {
        let header = &record.envelope.header;
        Ok(Self {
            height: header.height,
            block_hash: record.hash().to_string(),
            tx_root: header.tx_root.clone(),
            state_root: header.state_root.clone(),
            utxo_root: header.utxo_root.clone(),
            reputation_root: header.reputation_root.clone(),
            timetoke_root: header.timetoke_root.clone(),
            zsi_root: header.zsi_root.clone(),
            proof_root: header.proof_root.clone(),
            pruning_commitment: record.pruning_commitment().to_string(),
            aggregated_commitment: record.aggregated_commitment()?,
            previous_commitment: record.previous_recursive_commitment()?,
            payload_expectations: PayloadExpectations::from_record(record),
        })
    }
}

/// Reconstruction plan summarising the work required to hydrate pruned history.
#[derive(Clone, Debug, Serialize)]
pub struct ReconstructionPlan {
    pub start_height: u64,
    pub tip: BlockMetadata,
    pub snapshot: SnapshotSummary,
    pub requests: Vec<ReconstructionRequest>,
}

impl ReconstructionPlan {
    pub fn is_fully_hydrated(&self) -> bool {
        self.requests.is_empty()
    }

    pub fn missing_heights(&self) -> Vec<u64> {
        self.requests.iter().map(|request| request.height).collect()
    }
}

/// Engine responsible for analysing storage and reconstructing pruned history.
pub struct ReconstructionEngine {
    storage: Storage,
    snapshot_dir: Option<PathBuf>,
}

impl ReconstructionEngine {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            snapshot_dir: None,
        }
    }

    pub fn with_snapshot_dir(storage: Storage, snapshot_dir: PathBuf) -> Self {
        Self {
            storage,
            snapshot_dir: Some(snapshot_dir),
        }
    }

    pub fn plan_from_height(&self, start_height: u64) -> ChainResult<ReconstructionPlan> {
        let tip = self
            .storage
            .tip()?
            .ok_or_else(|| ChainError::Config("blockchain tip not initialised".into()))?;
        if start_height > tip.height {
            return Err(ChainError::Config(
                "start height exceeds current tip".into(),
            ));
        }

        let mut records = self.storage.load_block_records_from(start_height)?;
        if records.is_empty() {
            return Err(ChainError::Config(
                "no blocks found for reconstruction".into(),
            ));
        }
        records.retain(|record| record.height() <= tip.height);
        if records.is_empty() {
            return Err(ChainError::Config(
                "no blocks available up to the tip".into(),
            ));
        }

        records.sort_by_key(|record| record.height());
        let anchor_record = &records[0];
        let snapshot = SnapshotSummary::from_record(anchor_record)?;
        let mut requests = Vec::new();
        for record in &records {
            if record.is_pruned() {
                requests.push(ReconstructionRequest::from_record(record)?);
            }
        }

        let plan = ReconstructionPlan {
            start_height: snapshot.height,
            tip,
            snapshot,
            requests,
        };
        Ok(plan)
    }

    pub fn full_plan(&self) -> ChainResult<ReconstructionPlan> {
        self.plan_from_height(0)
    }

    pub fn persist_plan(&self, plan: &ReconstructionPlan) -> ChainResult<Option<PathBuf>> {
        let Some(dir) = self.snapshot_dir.as_ref() else {
            return Ok(None);
        };
        let path = self.persist_plan_to(dir, plan)?;
        Ok(Some(path))
    }

    pub fn verify_proof_chain(&self) -> ChainResult<()> {
        let mut records = self.storage.load_block_records_from(0)?;
        if records.is_empty() {
            return Ok(());
        }
        records.sort_by_key(|record| record.height());
        let mut previous: Option<Block> = None;
        for record in records {
            let block = record.into_block();
            if let Some(prev_block) = previous.as_ref() {
                if block.header.height != prev_block.header.height + 1 {
                    return Err(ChainError::Crypto(
                        "invalid block height progression in proof chain".into(),
                    ));
                }
                if block.header.previous_hash != prev_block.hash {
                    return Err(ChainError::Crypto(
                        "invalid previous hash in proof chain".into(),
                    ));
                }
            }
            block
                .pruning_proof
                .verify(previous.as_ref(), &block.header)?;
            let previous_recursive = previous.as_ref().map(|prev| &prev.recursive_proof);
            block.recursive_proof.verify(
                &block.header,
                &block.pruning_proof,
                previous_recursive,
            )?;
            previous = Some(block);
        }
        Ok(())
    }

    pub fn reconstruct_block<P: PayloadProvider>(
        &self,
        height: u64,
        provider: &P,
    ) -> ChainResult<Block> {
        let tip = self
            .storage
            .tip()?
            .ok_or_else(|| ChainError::Config("blockchain tip not initialised".into()))?;
        if height > tip.height {
            return Err(ChainError::Config(
                "requested height exceeds current tip".into(),
            ));
        }
        let previous = if height == 0 {
            None
        } else {
            Some(self.storage.read_block(height - 1)?.ok_or_else(|| {
                ChainError::Config("missing previous block for reconstruction".into())
            })?)
        };
        let record = self
            .storage
            .read_block_record(height)?
            .ok_or_else(|| ChainError::Config("missing block in storage".into()))?;
        let block = self.hydrate_record(record, provider)?;
        block.verify_without_stark(previous.as_ref())?;
        Ok(block)
    }

    pub fn reconstruct_range<P: PayloadProvider>(
        &self,
        start_height: u64,
        end_height: u64,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        if end_height < start_height {
            return Err(ChainError::Config("invalid reconstruction range".into()));
        }
        let tip = self
            .storage
            .tip()?
            .ok_or_else(|| ChainError::Config("blockchain tip not initialised".into()))?;
        if end_height > tip.height {
            return Err(ChainError::Config(
                "reconstruction range exceeds current tip".into(),
            ));
        }
        let mut results = Vec::new();
        let mut previous = if start_height == 0 {
            None
        } else {
            Some(
                self.storage
                    .read_block(start_height - 1)?
                    .ok_or_else(|| ChainError::Config("missing block before range".into()))?,
            )
        };
        for height in start_height..=end_height {
            let record = self
                .storage
                .read_block_record(height)?
                .ok_or_else(|| ChainError::Config("missing block in storage".into()))?;
            let block = self.hydrate_record(record, provider)?;
            block.verify_without_stark(previous.as_ref())?;
            previous = Some(block.clone());
            results.push(block);
        }
        Ok(results)
    }

    pub fn execute_plan<P: PayloadProvider>(
        &self,
        plan: &ReconstructionPlan,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        let current_tip = self
            .storage
            .tip()?
            .ok_or_else(|| ChainError::Config("blockchain tip not initialised".into()))?;
        if current_tip.height != plan.tip.height || current_tip.hash != plan.tip.hash {
            return Err(ChainError::Config(
                "storage tip changed since plan creation".into(),
            ));
        }
        self.reconstruct_range(plan.start_height, plan.tip.height, provider)
    }

    fn hydrate_record<P: PayloadProvider>(
        &self,
        record: StoredBlock,
        provider: &P,
    ) -> ChainResult<Block> {
        if !record.is_pruned() {
            return Ok(record.into_block());
        }
        let request = ReconstructionRequest::from_record(&record)?;
        let payload = provider.fetch_payload(&request)?;
        Ok(record.into_block_with_payload(payload))
    }

    fn persist_plan_to(&self, dir: &Path, plan: &ReconstructionPlan) -> ChainResult<PathBuf> {
        fs::create_dir_all(dir)?;
        let filename = format!("snapshot-{}.json", plan.snapshot.height);
        let path = dir.join(filename);
        let encoded = serde_json::to_vec_pretty(plan).map_err(|err| {
            ChainError::Config(format!("failed to encode reconstruction plan: {err}"))
        })?;
        fs::write(&path, encoded)?;
        Ok(path)
    }
}

impl SnapshotSummary {
    fn from_record(record: &StoredBlock) -> ChainResult<Self> {
        let header = &record.envelope.header;
        Ok(Self {
            height: header.height,
            block_hash: record.hash().to_string(),
            commitments: GlobalStateCommitments {
                global_state_root: decode_digest(&header.state_root)?,
                utxo_root: decode_digest(&header.utxo_root)?,
                reputation_root: decode_digest(&header.reputation_root)?,
                timetoke_root: decode_digest(&header.timetoke_root)?,
                zsi_root: decode_digest(&header.zsi_root)?,
                proof_root: decode_digest(&header.proof_root)?,
            },
            chain_commitment: record.envelope.recursive_proof.chain_commitment.clone(),
        })
    }
}

fn decode_digest(value: &str) -> ChainResult<[u8; 32]> {
    let bytes = hex::decode(value)
        .map_err(|err| ChainError::Config(format!("invalid commitment encoding: {err}")))?;
    if bytes.len() != 32 {
        return Err(ChainError::Config(
            "commitment must encode exactly 32 bytes".into(),
        ));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ConsensusCertificate;
    use crate::rpp::{ModuleWitnessBundle, ProofArtifact};
    use crate::state::merkle::compute_merkle_root;
    use crate::stwo::circuit::ExecutionTrace;
    use crate::stwo::circuit::{
        pruning::PruningWitness, recursive::RecursiveWitness, state::StateWitness,
    };
    use crate::stwo::proof::{FriProof, ProofKind, ProofPayload, StarkProof};
    use crate::types::{BlockHeader, PruningProof, RecursiveProof};
    use ed25519_dalek::Signature;
    use std::collections::HashMap;
    use tempfile::tempdir;

    struct MemoryProvider {
        payloads: HashMap<u64, BlockPayload>,
    }

    impl MemoryProvider {
        fn new(payloads: HashMap<u64, BlockPayload>) -> Self {
            Self { payloads }
        }
    }

    impl PayloadProvider for MemoryProvider {
        fn fetch_payload(&self, request: &ReconstructionRequest) -> ChainResult<BlockPayload> {
            self.payloads
                .get(&request.height)
                .cloned()
                .ok_or_else(|| ChainError::Config("missing payload for requested height".into()))
        }
    }

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
                required_tier: crate::reputation::Tier::Tl0,
                reputation_weights: crate::reputation::ReputationWeights::default(),
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            fri_proof: FriProof {
                commitments: Vec::new(),
                challenges: Vec::new(),
            },
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
            fri_proof: FriProof {
                commitments: Vec::new(),
                challenges: Vec::new(),
            },
        }
    }

    fn dummy_recursive_proof(
        previous_commitment: Option<String>,
        aggregated_commitment: String,
        block_height: u64,
    ) -> StarkProof {
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
                state_commitment: "77".repeat(32),
                global_state_root: "11".repeat(32),
                utxo_root: "22".repeat(32),
                reputation_root: "33".repeat(32),
                timetoke_root: "44".repeat(32),
                zsi_root: "55".repeat(32),
                proof_root: "66".repeat(32),
                pruning_commitment: "88".repeat(32),
                block_height,
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            fri_proof: FriProof {
                commitments: Vec::new(),
                challenges: Vec::new(),
            },
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
            format!("vrf{:02}", height),
            format!("proposer{:02}", height),
            Tier::Tl3.to_string(),
            height,
        );
        let pruning_proof = PruningProof::from_previous(previous, &header);
        let recursive_proof = match previous {
            Some(prev) => RecursiveProof::extend(&prev.recursive_proof, &header, &pruning_proof),
            None => RecursiveProof::genesis(&header, &pruning_proof),
        };
        let previous_recursive_commitment = previous.map(|block| {
            block
                .stark
                .recursive_proof
                .expect_stwo()
                .expect("recursive proof")
                .commitment
                .clone()
        });
        let recursive_stark = dummy_recursive_proof(
            previous_recursive_commitment,
            recursive_proof.chain_commitment.clone(),
            height,
        );
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
        let stark_bundle = crate::types::BlockProofBundle::new(
            Vec::new(),
            crate::types::ChainProof::Stwo(state_stark),
            crate::types::ChainProof::Stwo(pruning_stark),
            crate::types::ChainProof::Stwo(recursive_stark),
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
    fn reconstruction_plan_detects_pruned_blocks() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let genesis = make_block(0, None);
        let mut payloads = HashMap::new();
        payloads.insert(0, BlockPayload::from_block(&genesis));
        storage.store_block(&genesis).expect("store genesis");

        let block_one = make_block(1, Some(&genesis));
        payloads.insert(1, BlockPayload::from_block(&block_one));
        storage.store_block(&block_one).expect("store block one");
        storage
            .prune_block_payload(1)
            .expect("prune block one payload");

        let engine = ReconstructionEngine::new(storage.clone());
        let plan = engine.plan_from_height(0).expect("plan reconstruction");
        assert_eq!(plan.start_height, 0);
        assert_eq!(plan.tip.height, 1);
        assert_eq!(plan.requests.len(), 1);
        assert_eq!(plan.requests[0].height, 1);
        assert!(plan.snapshot.commitments.global_state_root != [0u8; 32]);

        engine.verify_proof_chain().expect("verify chain");

        let provider = MemoryProvider::new(payloads);
        let hydrated = engine
            .execute_plan(&plan, &provider)
            .expect("execute reconstruction plan");
        assert_eq!(hydrated.len(), 2);
        assert!(!hydrated[1].pruned);
        assert_eq!(hydrated[1].header.height, 1);
    }
}
