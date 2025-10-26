use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose, Engine as _};
use hex;
use serde::Serialize;

#[cfg(test)]
use crate::reputation::Tier;

use crate::crypto::public_key_from_hex;
use crate::errors::{ChainError, ChainResult};
#[cfg(feature = "backend-plonky3")]
use crate::plonky3::circuit::transaction::TransactionWitness as Plonky3TransactionWitness;
use crate::proof_backend::ProofBytes;
use crate::proof_system::ProofVerifierRegistry;
use crate::rpp::GlobalStateCommitments;
use crate::storage::Storage;
use crate::stwo::circuit::transaction::TransactionWitness;
use crate::stwo::proof::ProofPayload;
use crate::types::StoredBlock;
use crate::types::{
    Block, BlockMetadata, BlockPayload, ChainProof, ProofSystem, RecursiveProof, SignedTransaction,
    TransactionProofBundle,
};
use blake3::Hash;
use rpp_p2p::{
    LightClientHead, LightClientSync, NetworkBlockMetadata, NetworkGlobalStateCommitments,
    NetworkLightClientUpdate, NetworkPayloadExpectations, NetworkReconstructionRequest,
    NetworkSnapshotSummary, NetworkStateSyncChunk, NetworkStateSyncPlan, PipelineError,
    RecursiveProofVerifier, SnapshotChunk, SnapshotChunkStream, SnapshotStore,
    TransactionProofVerifier,
};

pub fn stream_state_sync_chunks(
    store: &SnapshotStore,
    root: &Hash,
) -> Result<SnapshotChunkStream, PipelineError> {
    store.stream(root)
}

pub fn state_sync_chunk_by_index(
    store: &SnapshotStore,
    root: &Hash,
    index: u64,
) -> Result<SnapshotChunk, PipelineError> {
    store.chunk(root, index)
}

pub fn subscribe_light_client_heads(
    client: &LightClientSync,
) -> tokio::sync::watch::Receiver<Option<LightClientHead>> {
    client.subscribe_light_client_heads()
}

pub fn latest_light_client_head(client: &LightClientSync) -> Option<LightClientHead> {
    client.latest_head()
}

#[derive(Clone, Debug)]
pub struct RuntimeRecursiveProofVerifier {
    registry: ProofVerifierRegistry,
}

impl Default for RuntimeRecursiveProofVerifier {
    fn default() -> Self {
        Self {
            registry: ProofVerifierRegistry::default(),
        }
    }
}

impl RuntimeRecursiveProofVerifier {
    pub fn new(registry: ProofVerifierRegistry) -> Self {
        Self { registry }
    }
}

impl RecursiveProofVerifier for RuntimeRecursiveProofVerifier {
    fn verify_recursive(
        &self,
        proof: &[u8],
        expected_commitment: &str,
        previous_commitment: Option<&str>,
    ) -> Result<(), PipelineError> {
        let artifact: ChainProof = serde_json::from_slice(proof).map_err(|err| {
            PipelineError::SnapshotVerification(format!("invalid recursive proof payload: {err}"))
        })?;
        let system = match &artifact {
            ChainProof::Stwo(_) => ProofSystem::Stwo,
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => ProofSystem::Plonky3,
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => ProofSystem::RppStark,
        };
        let recursive = RecursiveProof::from_parts(
            system,
            expected_commitment.to_string(),
            previous_commitment.map(|value| value.to_string()),
            artifact.clone(),
        )
        .map_err(|err| PipelineError::SnapshotVerification(err.to_string()))?;
        if let Some(expected) = previous_commitment {
            match recursive.previous_commitment.as_deref() {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(PipelineError::SnapshotVerification(format!(
                        "previous commitment mismatch (expected {expected}, got {actual})"
                    )));
                }
                None => {
                    return Err(PipelineError::SnapshotVerification(
                        "recursive proof missing previous commitment".into(),
                    ));
                }
            }
        }
        if previous_commitment.is_none() {
            if let Some(actual) = recursive.previous_commitment.as_deref() {
                if actual != RecursiveProof::anchor() {
                    return Err(PipelineError::SnapshotVerification(
                        "unexpected previous commitment for genesis proof".into(),
                    ));
                }
            }
        }
        self.registry
            .verify_recursive(&artifact)
            .map_err(|err| PipelineError::SnapshotVerification(err.to_string()))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeTransactionProofVerifier {
    registry: ProofVerifierRegistry,
}

impl Default for RuntimeTransactionProofVerifier {
    fn default() -> Self {
        Self {
            registry: ProofVerifierRegistry::default(),
        }
    }
}

impl RuntimeTransactionProofVerifier {
    pub fn new(registry: ProofVerifierRegistry) -> Self {
        Self { registry }
    }

    fn verify_bundle(&self, payload: &[u8]) -> Result<(), PipelineError> {
        let bundle: TransactionProofBundle = serde_json::from_slice(payload).map_err(|err| {
            PipelineError::Validation(format!("invalid transaction proof payload: {err}"))
        })?;

        bundle
            .transaction
            .verify()
            .map_err(|err| PipelineError::Validation(format!("invalid transaction: {err}")))?;

        self.verify_proof_artifact(&bundle)?;
        Self::ensure_witness_consistency(&bundle)?;
        Ok(())
    }

    fn verify_proof_artifact(&self, bundle: &TransactionProofBundle) -> Result<(), PipelineError> {
        match (bundle.stwo_proof_bytes(), bundle.stwo_public_inputs()) {
            (Some(bytes), Some(inputs)) => {
                let proof_bytes = ProofBytes(bytes.clone());
                self.registry
                    .verify_stwo_proof_bytes(&proof_bytes, inputs)
                    .map_err(|err| {
                        PipelineError::Validation(format!(
                            "transaction proof byte verification failed: {err}"
                        ))
                    })?
            }
            (None, None) => self
                .registry
                .verify_transaction(&bundle.proof)
                .map_err(|err| {
                    PipelineError::Validation(format!(
                        "transaction proof verification failed: {err}"
                    ))
                })?,
            _ => {
                return Err(PipelineError::Validation(
                    "stwo proof bytes must include matching public inputs".into(),
                ));
            }
        }
        Ok(())
    }

    fn ensure_witness_matches_transaction(
        witness: &TransactionWitness,
        transaction: &SignedTransaction,
    ) -> Result<(), PipelineError> {
        if &witness.signed_tx != transaction {
            return Err(PipelineError::Validation(
                "transaction witness does not match signed transaction".into(),
            ));
        }
        Ok(())
    }

    fn ensure_optional_witness(
        bundle: &TransactionProofBundle,
        witness: &TransactionWitness,
    ) -> Result<(), PipelineError> {
        Self::ensure_witness_matches_transaction(witness, &bundle.transaction)?;
        if let Some(explicit) = &bundle.witness {
            if explicit != witness {
                return Err(PipelineError::Validation(
                    "transaction witness payload mismatch".into(),
                ));
            }
        }
        Ok(())
    }

    fn ensure_witness_consistency(bundle: &TransactionProofBundle) -> Result<(), PipelineError> {
        if let Some(witness) = &bundle.witness {
            Self::ensure_witness_matches_transaction(witness, &bundle.transaction)?;
        }

        if let Some(payload) = &bundle.proof_payload {
            match payload {
                ProofPayload::Transaction(witness) => {
                    Self::ensure_optional_witness(bundle, witness)?;
                }
                other => {
                    return Err(PipelineError::Validation(format!(
                        "unexpected proof payload variant for transaction gossip: {other:?}",
                    )));
                }
            }
        }

        match &bundle.proof {
            ChainProof::Stwo(stark) => match &stark.payload {
                ProofPayload::Transaction(witness) => {
                    Self::ensure_optional_witness(bundle, witness)?;
                    if let Some(payload) = &bundle.proof_payload {
                        if let ProofPayload::Transaction(payload_witness) = payload {
                            if payload_witness != witness {
                                return Err(PipelineError::Validation(
                                    "proof payload differs from embedded witness".into(),
                                ));
                            }
                        }
                    }
                }
                other => {
                    return Err(PipelineError::Validation(format!(
                        "stwo transaction proof missing witness payload: {other:?}"
                    )));
                }
            },
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(value) => {
                let witness_value = value
                    .get("public_inputs")
                    .and_then(|inputs| inputs.get("witness"))
                    .cloned()
                    .ok_or_else(|| {
                        PipelineError::Validation(
                            "plonky3 transaction proof missing witness payload".into(),
                        )
                    })?;
                let witness: Plonky3TransactionWitness = serde_json::from_value(witness_value)
                    .map_err(|err| {
                        PipelineError::Validation(format!(
                            "failed to decode plonky3 transaction witness: {err}"
                        ))
                    })?;
                if witness.transaction != bundle.transaction {
                    return Err(PipelineError::Validation(
                        "plonky3 transaction witness does not match signed transaction".into(),
                    ));
                }
                if bundle.witness.is_some() {
                    return Err(PipelineError::Validation(
                        "raw transaction witness not supported for plonky3 proofs".into(),
                    ));
                }
            }
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => {
                if bundle.witness.is_some() || bundle.proof_payload.is_some() {
                    return Err(PipelineError::Validation(
                        "rpp-stark proofs must omit transaction witnesses".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}

impl TransactionProofVerifier for RuntimeTransactionProofVerifier {
    fn verify(&self, payload: &[u8]) -> Result<(), PipelineError> {
        self.verify_bundle(payload)
    }
}
use ed25519_dalek::PublicKey;

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
    pub pruning_schema_version: u16,
    pub pruning_parameter_version: u16,
    pub payload_expectations: PayloadExpectations,
}

impl ReconstructionRequest {
    fn from_record(record: &StoredBlock) -> ChainResult<Self> {
        let header = &record.envelope.header;
        let pruning = record.pruning_metadata();
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
            pruning_commitment: pruning.binding_digest.as_str().to_string(),
            aggregated_commitment: record.aggregated_commitment()?,
            previous_commitment: record.previous_recursive_commitment()?,
            pruning_schema_version: pruning.schema_version,
            pruning_parameter_version: pruning.parameter_version,
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

#[derive(Clone, Debug, Serialize)]
pub struct StateSyncChunk {
    pub start_height: u64,
    pub end_height: u64,
    pub requests: Vec<ReconstructionRequest>,
}

impl StateSyncChunk {
    fn from_requests(requests: Vec<ReconstructionRequest>) -> Self {
        let start_height = requests.first().map(|req| req.height).unwrap_or(0);
        let end_height = requests
            .last()
            .map(|req| req.height)
            .unwrap_or(start_height);
        Self {
            start_height,
            end_height,
            requests,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LightClientUpdate {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub recursive_proof: ChainProof,
}

#[derive(Clone, Debug, Serialize)]
pub struct StateSyncPlan {
    pub snapshot: SnapshotSummary,
    pub tip: BlockMetadata,
    pub chunks: Vec<StateSyncChunk>,
    pub light_client_updates: Vec<LightClientUpdate>,
}

impl StateSyncPlan {
    pub fn to_network_plan(&self) -> ChainResult<NetworkStateSyncPlan> {
        let snapshot = NetworkSnapshotSummary {
            height: self.snapshot.height,
            block_hash: self.snapshot.block_hash.clone(),
            commitments: encode_global_commitments(&self.snapshot.commitments),
            chain_commitment: self.snapshot.chain_commitment.clone(),
        };
        let chunks = self
            .chunks
            .iter()
            .map(|chunk| NetworkStateSyncChunk {
                start_height: chunk.start_height,
                end_height: chunk.end_height,
                requests: chunk
                    .requests
                    .iter()
                    .map(encode_reconstruction_request)
                    .collect(),
                proofs: Vec::new(),
            })
            .collect();
        let mut updates = Vec::with_capacity(self.light_client_updates.len());
        let mut previous_commitment = Some(self.snapshot.chain_commitment.clone());
        for update in &self.light_client_updates {
            let commitment = recursive_commitment(&update.recursive_proof)?;
            updates.push(NetworkLightClientUpdate {
                height: update.height,
                block_hash: update.block_hash.clone(),
                state_root: update.state_root.clone(),
                proof_commitment: commitment.clone(),
                previous_commitment: previous_commitment.clone(),
                recursive_proof: String::new(),
            });
            previous_commitment = Some(commitment);
        }
        Ok(NetworkStateSyncPlan {
            snapshot,
            tip: encode_block_metadata(&self.tip),
            chunks,
            light_client_updates: updates,
        })
    }

    pub fn chunk_messages(&self) -> ChainResult<Vec<NetworkStateSyncChunk>> {
        self.chunks.iter().map(encode_chunk).collect()
    }

    pub fn chunk_message_for(&self, start_height: u64) -> ChainResult<NetworkStateSyncChunk> {
        let chunk = self
            .chunks
            .iter()
            .find(|chunk| chunk.start_height == start_height)
            .ok_or_else(|| {
                ChainError::Config(format!(
                    "state sync chunk starting at {start_height} not found"
                ))
            })?;
        encode_chunk(chunk)
    }

    pub fn light_client_messages(&self) -> ChainResult<Vec<NetworkLightClientUpdate>> {
        let mut updates = Vec::with_capacity(self.light_client_updates.len());
        let mut previous_commitment = Some(self.snapshot.chain_commitment.clone());
        for update in &self.light_client_updates {
            let commitment = recursive_commitment(&update.recursive_proof)?;
            let proof_bytes = encode_recursive_proof(&update.recursive_proof)?;
            updates.push(NetworkLightClientUpdate {
                height: update.height,
                block_hash: update.block_hash.clone(),
                state_root: update.state_root.clone(),
                proof_commitment: commitment.clone(),
                previous_commitment: previous_commitment.clone(),
                recursive_proof: proof_bytes,
            });
            previous_commitment = Some(commitment);
        }
        Ok(updates)
    }
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

    pub fn state_sync_plan(&self, chunk_size: usize) -> ChainResult<StateSyncPlan> {
        if chunk_size == 0 {
            return Err(ChainError::Config(
                "state sync chunk size must be greater than zero".into(),
            ));
        }
        let plan = self.full_plan()?;
        let mut chunks = Vec::new();
        if !plan.requests.is_empty() {
            let mut buffer: Vec<ReconstructionRequest> = Vec::new();
            for request in plan.requests.iter().cloned() {
                buffer.push(request);
                if buffer.len() == chunk_size {
                    let chunk_requests = std::mem::take(&mut buffer);
                    chunks.push(StateSyncChunk::from_requests(chunk_requests));
                }
            }
            if !buffer.is_empty() {
                let remaining = std::mem::take(&mut buffer);
                chunks.push(StateSyncChunk::from_requests(remaining));
            }
        }
        let updates = self.light_client_feed(plan.start_height)?;
        Ok(StateSyncPlan {
            snapshot: plan.snapshot.clone(),
            tip: plan.tip.clone(),
            chunks,
            light_client_updates: updates,
        })
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

    pub fn light_client_feed(&self, start_height: u64) -> ChainResult<Vec<LightClientUpdate>> {
        let mut records = self.storage.load_block_records_from(start_height)?;
        records.sort_by_key(|record| record.height());
        let mut updates = Vec::new();
        for record in records {
            let header = &record.envelope.header;
            updates.push(LightClientUpdate {
                height: header.height,
                block_hash: record.hash().to_string(),
                state_root: header.state_root.clone(),
                recursive_proof: record.envelope.stark.recursive_proof.clone(),
            });
        }
        Ok(updates)
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
        let proposer_key = self.proposer_public_key(&block.header.proposer)?;
        block.verify_without_stark(previous.as_ref(), &proposer_key)?;
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
            let proposer_key = self.proposer_public_key(&block.header.proposer)?;
            block.verify_without_stark(previous.as_ref(), &proposer_key)?;
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

    fn proposer_public_key(&self, proposer: &str) -> ChainResult<PublicKey> {
        let account = self.storage.read_account(proposer)?.ok_or_else(|| {
            ChainError::Crypto("validator account missing for signature verification".into())
        })?;
        let key_hex = account.identity.wallet_public_key.ok_or_else(|| {
            ChainError::Crypto("validator wallet public key not registered".into())
        })?;
        public_key_from_hex(&key_hex)
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
            chain_commitment: record.envelope.recursive_proof.commitment.clone(),
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

fn encode_global_commitments(
    commitments: &GlobalStateCommitments,
) -> NetworkGlobalStateCommitments {
    NetworkGlobalStateCommitments {
        global_state_root: hex::encode(commitments.global_state_root),
        utxo_root: hex::encode(commitments.utxo_root),
        reputation_root: hex::encode(commitments.reputation_root),
        timetoke_root: hex::encode(commitments.timetoke_root),
        zsi_root: hex::encode(commitments.zsi_root),
        proof_root: hex::encode(commitments.proof_root),
    }
}

fn encode_block_metadata(metadata: &BlockMetadata) -> NetworkBlockMetadata {
    NetworkBlockMetadata {
        height: metadata.height,
        hash: metadata.hash.clone(),
        timestamp: metadata.timestamp,
        previous_state_root: metadata.previous_state_root.clone(),
        new_state_root: metadata.new_state_root.clone(),
        proof_hash: metadata.proof_hash.clone(),
        pruning: metadata.pruning.clone(),
        recursion_anchor: metadata.recursive_anchor.clone(),
    }
}

fn encode_payload_expectations(expectations: &PayloadExpectations) -> NetworkPayloadExpectations {
    NetworkPayloadExpectations {
        transaction_proofs: expectations.transaction_proofs,
        transaction_witnesses: expectations.transaction_witnesses,
        timetoke_witnesses: expectations.timetoke_witnesses,
        reputation_witnesses: expectations.reputation_witnesses,
        zsi_witnesses: expectations.zsi_witnesses,
        consensus_witnesses: expectations.consensus_witnesses,
    }
}

fn encode_reconstruction_request(request: &ReconstructionRequest) -> NetworkReconstructionRequest {
    NetworkReconstructionRequest {
        height: request.height,
        block_hash: request.block_hash.clone(),
        tx_root: request.tx_root.clone(),
        state_root: request.state_root.clone(),
        utxo_root: request.utxo_root.clone(),
        reputation_root: request.reputation_root.clone(),
        timetoke_root: request.timetoke_root.clone(),
        zsi_root: request.zsi_root.clone(),
        proof_root: request.proof_root.clone(),
        pruning_commitment: request.pruning_commitment.clone(),
        aggregated_commitment: request.aggregated_commitment.clone(),
        previous_commitment: request.previous_commitment.clone(),
        pruning_schema_version: request.pruning_schema_version,
        pruning_parameter_version: request.pruning_parameter_version,
        payload_expectations: encode_payload_expectations(&request.payload_expectations),
    }
}

fn encode_chunk(chunk: &StateSyncChunk) -> ChainResult<NetworkStateSyncChunk> {
    let requests = chunk
        .requests
        .iter()
        .map(encode_reconstruction_request)
        .collect();
    let mut proofs = Vec::with_capacity(chunk.requests.len());
    for request in &chunk.requests {
        proofs.push(aggregated_commitment_base64(
            &request.aggregated_commitment,
        )?);
    }
    Ok(NetworkStateSyncChunk {
        start_height: chunk.start_height,
        end_height: chunk.end_height,
        requests,
        proofs,
    })
}

fn aggregated_commitment_base64(value: &str) -> ChainResult<String> {
    let digest = decode_digest(value)?;
    Ok(general_purpose::STANDARD.encode(digest))
}

fn recursive_commitment(proof: &ChainProof) -> ChainResult<String> {
    match proof {
        ChainProof::Stwo(proof) => Ok(proof.commitment.clone()),
        #[cfg(feature = "backend-plonky3")]
        ChainProof::Plonky3(_) => Err(ChainError::Config(
            "plonky3 recursive proofs are not supported for state sync gossip".into(),
        )),
        #[cfg(feature = "backend-rpp-stark")]
        ChainProof::RppStark(_) => Err(ChainError::Config(
            "rpp-stark recursive proofs are not supported for state sync gossip".into(),
        )),
    }
}

fn encode_recursive_proof(proof: &ChainProof) -> ChainResult<String> {
    let bytes = serde_json::to_vec(proof)
        .map_err(|err| ChainError::Config(format!("failed to serialise recursive proof: {err}")))?;
    Ok(general_purpose::STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        evaluate_vrf, BftVote, BftVoteKind, ConsensusCertificate, SignedBftVote, VoteRecord,
    };
    use crate::crypto::{address_from_public_key, generate_vrf_keypair, vrf_public_key_to_hex};
    use crate::rpp::{ConsensusWitness, ModuleWitnessBundle, ProofArtifact};
    use crate::state::merkle::compute_merkle_root;
    use crate::stwo::circuit::ExecutionTrace;
    use crate::stwo::circuit::{
        pruning::PruningWitness, recursive::RecursiveWitness, state::StateWitness,
    };
    use crate::stwo::proof::{
        CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
    };
    use crate::types::{Account, BlockHeader, PruningProof, RecursiveProof, Stake};
    use ed25519_dalek::{Keypair, Signer};
    use rand::rngs::OsRng;
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

    fn persist_validator_account(storage: &Storage, keypair: &Keypair) {
        let address = address_from_public_key(&keypair.public);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account
            .ensure_wallet_binding(&hex::encode(keypair.public.to_bytes()))
            .expect("bind wallet key");
        storage
            .persist_account(&account)
            .expect("persist validator account");
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

    fn make_block(height: u64, previous: Option<&Block>) -> (Block, Keypair) {
        let previous_hash = previous
            .map(|block| block.hash.clone())
            .unwrap_or_else(|| hex::encode([0u8; 32]));
        let seed = previous
            .map(|block| block.block_hash())
            .unwrap_or([0u8; 32]);
        let mut tx_leaves: Vec<[u8; 32]> = Vec::new();
        let tx_root = hex::encode(compute_merkle_root(&mut tx_leaves));
        let state_root = hex::encode([height as u8 + 2; 32]);
        let utxo_root = hex::encode([height as u8 + 3; 32]);
        let reputation_root = hex::encode([height as u8 + 4; 32]);
        let timetoke_root = hex::encode([height as u8 + 5; 32]);
        let zsi_root = hex::encode([height as u8 + 6; 32]);
        let proof_root = hex::encode([height as u8 + 7; 32]);
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let address = address_from_public_key(&keypair.public);
        let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");
        let vrf = evaluate_vrf(&seed, height, &address, height, Some(&vrf_keypair.secret))
            .expect("evaluate vrf");
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
            vrf.randomness.to_string(),
            vrf_public_key_to_hex(&vrf_keypair.public),
            vrf.preoutput.clone(),
            vrf.proof.clone(),
            address.clone(),
            Tier::Tl3.to_string(),
            height,
        );
        let block_hash_hex = hex::encode(header.hash());
        let prevote = BftVote {
            round: height,
            height,
            block_hash: block_hash_hex.clone(),
            voter: address.clone(),
            kind: BftVoteKind::PreVote,
        };
        let prevote_sig = keypair.sign(&prevote.message_bytes());
        let signed_prevote = SignedBftVote {
            vote: prevote.clone(),
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(prevote_sig.to_bytes()),
        };
        let precommit_vote = BftVote {
            kind: BftVoteKind::PreCommit,
            ..prevote
        };
        let precommit_sig = keypair.sign(&precommit_vote.message_bytes());
        let signed_precommit = SignedBftVote {
            vote: precommit_vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(precommit_sig.to_bytes()),
        };
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
        let recursive_chain_proof = crate::types::ChainProof::Stwo(recursive_stark.clone());
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
        let mut module_witnesses = ModuleWitnessBundle::default();
        module_witnesses.record_consensus(ConsensusWitness::new(
            height,
            height,
            vec![address.clone()],
        ));
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
            recursive_chain_proof,
        );
        let signature = keypair.sign(&header.canonical_bytes());
        let mut consensus = ConsensusCertificate::genesis();
        consensus.round = height;
        consensus.total_power = "1".to_string();
        consensus.quorum_threshold = "1".to_string();
        consensus.pre_vote_power = "1".to_string();
        consensus.pre_commit_power = "1".to_string();
        consensus.commit_power = "1".to_string();
        consensus.pre_votes = vec![VoteRecord {
            vote: signed_prevote,
            weight: "1".to_string(),
        }];
        consensus.pre_commits = vec![VoteRecord {
            vote: signed_precommit,
            weight: "1".to_string(),
        }];
        let block = Block::new(
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
        );
        (block, keypair)
    }

    #[test]
    fn reconstruction_plan_detects_pruned_blocks() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let (genesis, genesis_keypair) = make_block(0, None);
        let mut payloads = HashMap::new();
        payloads.insert(0, BlockPayload::from_block(&genesis));
        let genesis_metadata = BlockMetadata::from(&genesis);
        storage
            .store_block(&genesis, &genesis_metadata)
            .expect("store genesis");
        persist_validator_account(&storage, &genesis_keypair);

        let (block_one, block_one_keypair) = make_block(1, Some(&genesis));
        payloads.insert(1, BlockPayload::from_block(&block_one));
        let block_one_metadata = BlockMetadata::from(&block_one);
        storage
            .store_block(&block_one, &block_one_metadata)
            .expect("store block one");
        storage
            .prune_block_payload(1)
            .expect("prune block one payload");
        persist_validator_account(&storage, &block_one_keypair);

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

    #[test]
    fn state_sync_plan_groups_chunks_and_updates_light_clients() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let (genesis, genesis_keypair) = make_block(0, None);
        let genesis_metadata = BlockMetadata::from(&genesis);
        storage
            .store_block(&genesis, &genesis_metadata)
            .expect("store genesis");
        persist_validator_account(&storage, &genesis_keypair);

        let (block_one, block_one_keypair) = make_block(1, Some(&genesis));
        let block_one_metadata = BlockMetadata::from(&block_one);
        storage
            .store_block(&block_one, &block_one_metadata)
            .expect("store block one");
        storage
            .prune_block_payload(1)
            .expect("prune block one payload");
        persist_validator_account(&storage, &block_one_keypair);

        let (block_two, block_two_keypair) = make_block(2, Some(&block_one));
        let block_two_metadata = BlockMetadata::from(&block_two);
        storage
            .store_block(&block_two, &block_two_metadata)
            .expect("store block two");
        storage
            .prune_block_payload(2)
            .expect("prune block two payload");
        persist_validator_account(&storage, &block_two_keypair);

        let engine = ReconstructionEngine::new(storage.clone());
        let plan = engine.state_sync_plan(1).expect("state sync plan");
        assert_eq!(plan.snapshot.height, 0);
        assert_eq!(plan.tip.height, 2);
        assert_eq!(plan.chunks.len(), 2);
        assert_eq!(plan.chunks[0].requests.len(), 1);
        assert_eq!(plan.chunks[1].requests.len(), 1);
        assert_eq!(plan.light_client_updates.len(), 3);
        assert_eq!(plan.light_client_updates[2].height, 2);

        let light_client_feed = engine.light_client_feed(1).expect("feed from height 1");
        assert_eq!(light_client_feed.len(), 2);
        assert!(light_client_feed
            .iter()
            .all(|update| !update.state_root.is_empty()));
    }
}
