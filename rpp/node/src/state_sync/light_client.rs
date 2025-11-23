use std::collections::HashMap;
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;

use crate::telemetry::pipeline::PipelineMetrics;
use base64::engine::general_purpose;
use base64::Engine as _;
use blake2::digest::Digest as _;
use blake2::Blake2s256;
use blake3::Hasher as Blake3Hasher;
use rpp_chain::runtime::sync::{
    ReconstructionEngine, RuntimeRecursiveProofVerifier, StateSyncPlan,
};
use rpp_chain::storage::Storage;
use rpp_p2p::{
    LightClientSync, NetworkLightClientUpdate, NetworkStateSyncChunk, NetworkStateSyncPlan,
    PipelineError,
};
use rpp_pruning::{COMMITMENT_TAG, DIGEST_LENGTH, DOMAIN_TAG_LENGTH};
use storage::snapshots::{known_snapshot_sets, SnapshotSet};
use storage_firewood::pruning::{PersistedPrunerSnapshot, PersistedPrunerState};
use thiserror::Error;

const PRUNER_STATE_KEY: &[u8] = b"pruner_state";
const SNAPSHOT_PREFIX: &[u8] = b"fw-pruning-snapshot";
const PROOF_IO_MARKER: &str = "ProofError::IO";

/// Verifies state sync plans by reusing the existing LightClientSync pipeline.
pub struct LightClientVerifier {
    storage: Storage,
    snapshot_dir: Option<PathBuf>,
}

impl LightClientVerifier {
    /// Constructs a verifier backed by the provided storage handle.
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            snapshot_dir: None,
        }
    }

    /// Constructs a verifier that persists reconstruction plans to `snapshot_dir`.
    pub fn with_snapshot_dir(storage: Storage, snapshot_dir: PathBuf) -> Self {
        Self {
            storage,
            snapshot_dir: Some(snapshot_dir),
        }
    }

    /// Executes the verification pipeline and returns a detailed report of the run.
    pub fn run(&self, chunk_size: usize) -> Result<StateSyncVerificationReport, VerificationError> {
        let mut builder = ReportBuilder::default();
        let engine = match self.snapshot_dir.clone() {
            Some(dir) => ReconstructionEngine::with_snapshot_dir(self.storage.clone(), dir),
            None => ReconstructionEngine::new(self.storage.clone()),
        };

        let plan = engine
            .state_sync_plan(chunk_size)
            .map_err(|err| builder.fail(VerificationErrorKind::Plan(err.to_string())))?;

        builder.set_snapshot_height(plan.snapshot.height);
        builder.record_event(LightClientVerificationEvent::PlanLoaded {
            snapshot_height: plan.snapshot.height,
            chunk_count: plan.chunks.len(),
            update_count: plan.light_client_updates.len(),
        });

        let persisted_state = self
            .load_pruner_state()
            .map_err(|kind| builder.fail(kind))?;

        validate_snapshot_metadata(&plan, &persisted_state, &mut builder)?;

        let verifier = Arc::new(RuntimeRecursiveProofVerifier::default());
        let mut light_client = LightClientSync::new(verifier);

        let network_plan = plan
            .to_network_plan()
            .map_err(|err| builder.fail(VerificationErrorKind::Plan(err.to_string())))?;
        ingest_plan(&network_plan, &mut light_client, &mut builder)?;

        let chunk_messages = plan
            .chunk_messages()
            .map_err(|err| builder.fail(VerificationErrorKind::Plan(err.to_string())))?;
        let mut chunk_roots: Vec<[u8; DIGEST_LENGTH]> = Vec::with_capacity(chunk_messages.len());
        ingest_chunks(
            &chunk_messages,
            &mut light_client,
            &mut builder,
            &mut chunk_roots,
        )?;

        let light_client_messages = plan
            .light_client_messages()
            .map_err(|err| builder.fail(VerificationErrorKind::Plan(err.to_string())))?;
        ingest_light_client_updates(&light_client_messages, &mut light_client, &mut builder)?;

        let verified = light_client
            .verify()
            .map_err(|err| builder.fail(classify_pipeline_error(err)))?;
        if !verified {
            return Err(builder.fail(VerificationErrorKind::Incomplete(
                "light client verification incomplete".to_string(),
            )));
        }

        let mut leaves = chunk_roots.clone();
        let snapshot_root = compute_merkle_root(&mut leaves);
        builder.set_snapshot_root(snapshot_root);
        builder.record_event(LightClientVerificationEvent::VerificationCompleted {
            snapshot_root: hex::encode(snapshot_root),
        });

        Ok(builder.into_success())
    }

    fn load_pruner_state(&self) -> Result<PersistedPrunerState, VerificationErrorKind> {
        let bytes = self
            .storage
            .read_metadata_blob(PRUNER_STATE_KEY)
            .map_err(|err| VerificationErrorKind::PrunerState(err.to_string()))?
            .ok_or_else(|| {
                VerificationErrorKind::PrunerState(
                    "persisted pruning state missing from storage".to_string(),
                )
            })?;
        bincode::deserialize(&bytes)
            .map_err(|err| VerificationErrorKind::PrunerState(err.to_string()))
    }
}

fn ingest_plan(
    plan: &NetworkStateSyncPlan,
    light_client: &mut LightClientSync,
    builder: &mut ReportBuilder,
) -> Result<(), VerificationError> {
    let payload = serde_json::to_vec(plan).map_err(|err| {
        builder.fail(VerificationErrorKind::Encoding(format!(
            "failed to encode plan payload: {err}"
        )))
    })?;
    light_client
        .ingest_plan(&payload)
        .map_err(|err| builder.fail(classify_pipeline_error(err)))?;
    builder.record_event(LightClientVerificationEvent::PlanIngested {
        chunk_count: plan.chunks.len(),
        update_count: plan.light_client_updates.len(),
    });
    Ok(())
}

fn ingest_chunks(
    chunks: &[NetworkStateSyncChunk],
    light_client: &mut LightClientSync,
    builder: &mut ReportBuilder,
    chunk_roots: &mut Vec<[u8; DIGEST_LENGTH]>,
) -> Result<(), VerificationError> {
    for chunk in chunks {
        let payload = serde_json::to_vec(chunk).map_err(|err| {
            builder.fail(VerificationErrorKind::Encoding(format!(
                "failed to encode chunk payload for start {}: {err}",
                chunk.start_height
            )))
        })?;
        light_client
            .ingest_chunk(&payload)
            .map_err(|err| builder.fail(classify_pipeline_error(err)))?;

        let mut leaves = Vec::with_capacity(chunk.proofs.len());
        for proof in &chunk.proofs {
            let digest = decode_commitment_base64(proof).map_err(|kind| builder.fail(kind))?;
            leaves.push(digest);
        }
        let root = compute_merkle_root(&mut leaves);
        chunk_roots.push(root);

        builder.note_chunk(chunk.start_height, chunk.end_height);
        builder.record_event(LightClientVerificationEvent::MerkleRootConfirmed {
            start_height: chunk.start_height,
            end_height: chunk.end_height,
        });
    }
    Ok(())
}

fn ingest_light_client_updates(
    updates: &[NetworkLightClientUpdate],
    light_client: &mut LightClientSync,
    builder: &mut ReportBuilder,
) -> Result<(), VerificationError> {
    for update in updates {
        let payload = serde_json::to_vec(update).map_err(|err| {
            builder.fail(VerificationErrorKind::Encoding(format!(
                "failed to encode light client update for height {}: {err}",
                update.height
            )))
        })?;
        light_client
            .ingest_light_client_update(&payload)
            .map_err(|err| builder.fail(classify_pipeline_error(err)))?;
        builder.note_update(update.height);
        builder.record_event(LightClientVerificationEvent::RecursiveProofVerified {
            height: update.height,
        });
    }
    Ok(())
}

fn validate_snapshot_metadata(
    plan: &StateSyncPlan,
    persisted: &PersistedPrunerState,
    builder: &mut ReportBuilder,
) -> Result<(), VerificationError> {
    let sets = known_snapshot_sets();
    if sets.is_empty() {
        return Err(builder.fail(VerificationErrorKind::Metadata(
            "no known snapshot metadata available".to_string(),
        )));
    }

    let Some(dataset) = find_matching_dataset(sets, persisted) else {
        return Err(builder.fail(VerificationErrorKind::Metadata(
            "persisted pruning state does not match any known snapshot dataset".to_string(),
        )));
    };

    if persisted.layout_version != dataset.layout_version {
        return Err(builder.fail(VerificationErrorKind::Metadata(format!(
            "snapshot layout version mismatch (recorded {}, expected {})",
            persisted.layout_version, dataset.layout_version
        ))));
    }
    if persisted.retain < dataset.snapshots.len() {
        return Err(builder.fail(VerificationErrorKind::Metadata(format!(
            "pruner retention ({}) is insufficient for dataset {}",
            persisted.retain,
            dataset.snapshots.len()
        ))));
    }
    if persisted.snapshots.len() != dataset.snapshots.len() {
        return Err(builder.fail(VerificationErrorKind::Metadata(format!(
            "snapshot count mismatch (recorded {}, metadata {})",
            persisted.snapshots.len(),
            dataset.snapshots.len()
        ))));
    }

    let mut recorded: HashMap<u64, &PersistedPrunerSnapshot> =
        HashMap::with_capacity(persisted.snapshots.len());
    for snapshot in &persisted.snapshots {
        recorded.insert(snapshot.block_height(), snapshot);
    }

    for snapshot in dataset.snapshots {
        let Some(recorded_snapshot) = recorded.remove(&snapshot.block_height) else {
            return Err(builder.fail(VerificationErrorKind::Metadata(format!(
                "missing pruning receipt for block {}",
                snapshot.block_height
            ))));
        };
        if recorded_snapshot.state_commitment() != snapshot.state_commitment {
            return Err(builder.fail(VerificationErrorKind::Metadata(format!(
                "state commitment mismatch for block {}",
                snapshot.block_height
            ))));
        }
        let dataset_root =
            decode_hex_digest(snapshot.state_root).map_err(|kind| builder.fail(kind))?;
        let expected_commitment = compute_state_commitment_digest(
            &persisted.schema_digest,
            &persisted.parameter_digest,
            snapshot.block_height,
            &dataset_root,
        );
        if expected_commitment != snapshot.state_commitment {
            return Err(builder.fail(VerificationErrorKind::Metadata(format!(
                "computed state commitment diverges for block {}",
                snapshot.block_height
            ))));
        }
    }

    if !recorded.is_empty() {
        return Err(builder.fail(VerificationErrorKind::Metadata(
            "unexpected pruning receipts recorded for unknown heights".to_string(),
        )));
    }

    let plan_state_root_hex = hex::encode(plan.snapshot.commitments.global_state_root);
    let plan_entry = dataset
        .snapshots
        .iter()
        .find(|entry| entry.block_height == plan.snapshot.height)
        .ok_or_else(|| {
            builder.fail(VerificationErrorKind::Metadata(format!(
                "snapshot height {} missing from metadata set {}",
                plan.snapshot.height, dataset.label
            )))
        })?;
    if !plan_entry
        .state_root
        .eq_ignore_ascii_case(&plan_state_root_hex)
    {
        return Err(builder.fail(VerificationErrorKind::Metadata(format!(
            "state root mismatch for height {}",
            plan.snapshot.height
        ))));
    }
    let expected_plan_commitment = compute_state_commitment_digest(
        &persisted.schema_digest,
        &persisted.parameter_digest,
        plan.snapshot.height,
        &plan.snapshot.commitments.global_state_root,
    );
    if expected_plan_commitment != plan_entry.state_commitment {
        return Err(builder.fail(VerificationErrorKind::Metadata(format!(
            "plan snapshot commitment mismatch for height {}",
            plan.snapshot.height
        ))));
    }

    builder.record_event(LightClientVerificationEvent::SnapshotMetadataValidated {
        dataset_label: dataset.label.to_string(),
        state_root: plan_state_root_hex,
        state_commitment: hex::encode(expected_plan_commitment),
    });
    builder.record_event(LightClientVerificationEvent::ReceiptsMatched {
        dataset_label: dataset.label.to_string(),
        snapshot_count: dataset.snapshots.len(),
    });

    Ok(())
}

fn find_matching_dataset<'a>(
    sets: &'a [SnapshotSet],
    persisted: &PersistedPrunerState,
) -> Option<&'a SnapshotSet> {
    sets.iter().find(|set| {
        set.schema_digest == persisted.schema_digest
            && set.parameter_digest == persisted.parameter_digest
    })
}

fn decode_hex_digest(value: &str) -> Result<[u8; DIGEST_LENGTH], VerificationErrorKind> {
    let bytes = hex::decode(value).map_err(|err| {
        VerificationErrorKind::Metadata(format!("invalid hex digest {value}: {err}"))
    })?;
    if bytes.len() != DIGEST_LENGTH {
        return Err(VerificationErrorKind::Metadata(format!(
            "expected 32-byte digest, received {} bytes",
            bytes.len()
        )));
    }
    let mut digest = [0u8; DIGEST_LENGTH];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

fn decode_commitment_base64(value: &str) -> Result<[u8; DIGEST_LENGTH], VerificationErrorKind> {
    let bytes = general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|err| {
            VerificationErrorKind::Encoding(format!("invalid pruning commitment encoding: {err}"))
        })?;
    if bytes.len() != DOMAIN_TAG_LENGTH + DIGEST_LENGTH {
        return Err(VerificationErrorKind::Encoding(format!(
            "expected {}-byte tagged commitment, received {} bytes",
            DOMAIN_TAG_LENGTH + DIGEST_LENGTH,
            bytes.len()
        )));
    }
    if bytes[..DOMAIN_TAG_LENGTH] != COMMITMENT_TAG.as_bytes() {
        return Err(VerificationErrorKind::Encoding(
            "unexpected commitment domain tag".to_string(),
        ));
    }
    let mut digest = [0u8; DIGEST_LENGTH];
    digest.copy_from_slice(&bytes[DOMAIN_TAG_LENGTH..]);
    Ok(digest)
}

fn classify_pipeline_error(err: PipelineError) -> VerificationErrorKind {
    match err {
        PipelineError::SnapshotVerification(message) if message.contains(PROOF_IO_MARKER) => {
            PipelineMetrics::global().record_root_io_error();
            VerificationErrorKind::Io(message)
        }
        PipelineError::SnapshotVerification(message) => {
            PipelineMetrics::global().record_state_sync_tamper("snapshot_verification");
            VerificationErrorKind::Pipeline(message)
        }
        PipelineError::Validation(message) if message.contains(PROOF_IO_MARKER) => {
            PipelineMetrics::global().record_root_io_error();
            VerificationErrorKind::Io(message)
        }
        PipelineError::Persistence(message) if message.contains(PROOF_IO_MARKER) => {
            PipelineMetrics::global().record_root_io_error();
            VerificationErrorKind::Io(message)
        }
        other => VerificationErrorKind::Pipeline(other.to_string()),
    }
}

fn compute_merkle_root(leaves: &mut Vec<[u8; DIGEST_LENGTH]>) -> [u8; DIGEST_LENGTH] {
    if leaves.is_empty() {
        let mut hasher = Blake2s256::new();
        hasher.update(b"rpp-empty");
        let output = hasher.finalize();
        let mut digest = [0u8; DIGEST_LENGTH];
        digest.copy_from_slice(&output);
        return digest;
    }
    leaves.sort();
    let mut current = leaves.clone();
    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut data = Vec::with_capacity(DIGEST_LENGTH * 2);
            data.extend_from_slice(&left);
            data.extend_from_slice(&right);
            let mut hasher = Blake2s256::new();
            hasher.update(&data);
            let output = hasher.finalize();
            let mut digest = [0u8; DIGEST_LENGTH];
            digest.copy_from_slice(&output);
            next.push(digest);
        }
        current = next;
    }
    current[0]
}

fn compute_state_commitment_digest(
    schema_digest: &[u8; DIGEST_LENGTH],
    parameter_digest: &[u8; DIGEST_LENGTH],
    block_height: u64,
    state_root: &[u8; DIGEST_LENGTH],
) -> [u8; DIGEST_LENGTH] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(SNAPSHOT_PREFIX);
    hasher.update(schema_digest);
    hasher.update(parameter_digest);
    hasher.update(&block_height.to_be_bytes());
    hasher.update(state_root);
    let output = hasher.finalize();
    let mut digest = [0u8; DIGEST_LENGTH];
    digest.copy_from_slice(output.as_bytes());
    digest
}

#[derive(Debug, Default)]
struct ReportBuilder {
    events: Vec<LightClientVerificationEvent>,
    chunk_ranges: Vec<VerifiedChunkRange>,
    update_heights: Vec<u64>,
    snapshot_height: Option<u64>,
    snapshot_root: Option<[u8; DIGEST_LENGTH]>,
}

impl ReportBuilder {
    fn record_event(&mut self, event: LightClientVerificationEvent) {
        self.events.push(event);
    }

    fn note_chunk(&mut self, start: u64, end: u64) {
        self.chunk_ranges.push(VerifiedChunkRange {
            start_height: start,
            end_height: end,
        });
    }

    fn note_update(&mut self, height: u64) {
        self.update_heights.push(height);
    }

    fn set_snapshot_height(&mut self, height: u64) {
        self.snapshot_height = Some(height);
    }

    fn set_snapshot_root(&mut self, root: [u8; DIGEST_LENGTH]) {
        self.snapshot_root = Some(root);
    }

    fn fail(&mut self, kind: VerificationErrorKind) -> VerificationError {
        let builder = mem::replace(self, ReportBuilder::default());
        let report = builder.finish(Some(kind.to_string()));
        VerificationError { kind, report }
    }

    fn into_success(self) -> StateSyncVerificationReport {
        self.finish(None)
    }

    fn finish(mut self, failure: Option<String>) -> StateSyncVerificationReport {
        let snapshot_root = self.snapshot_root.map(hex::encode);
        let summary = StateSyncVerificationSummary {
            snapshot_height: self.snapshot_height,
            snapshot_root,
            verified_chunk_ranges: self.chunk_ranges,
            verified_light_client_heights: self.update_heights,
            failure,
        };
        StateSyncVerificationReport {
            events: self.events,
            summary,
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum VerificationErrorKind {
    #[error("plan generation failed: {0}")]
    Plan(String),
    #[error("payload encoding error: {0}")]
    Encoding(String),
    #[error("light client pipeline error: {0}")]
    Pipeline(String),
    #[error("{0}")]
    Io(String),
    #[error("persisted pruning state error: {0}")]
    PrunerState(String),
    #[error("snapshot metadata mismatch: {0}")]
    Metadata(String),
    #[error("verification incomplete: {0}")]
    Incomplete(String),
}

#[derive(Debug, Error)]
#[error("{kind}")]
pub struct VerificationError {
    kind: VerificationErrorKind,
    report: StateSyncVerificationReport,
}

impl VerificationError {
    pub fn kind(&self) -> &VerificationErrorKind {
        &self.kind
    }

    pub fn report(&self) -> &StateSyncVerificationReport {
        &self.report
    }
}

#[derive(Clone, Debug)]
pub enum LightClientVerificationEvent {
    PlanLoaded {
        snapshot_height: u64,
        chunk_count: usize,
        update_count: usize,
    },
    PlanIngested {
        chunk_count: usize,
        update_count: usize,
    },
    SnapshotMetadataValidated {
        dataset_label: String,
        state_root: String,
        state_commitment: String,
    },
    ReceiptsMatched {
        dataset_label: String,
        snapshot_count: usize,
    },
    MerkleRootConfirmed {
        start_height: u64,
        end_height: u64,
    },
    RecursiveProofVerified {
        height: u64,
    },
    VerificationCompleted {
        snapshot_root: String,
    },
}

#[derive(Clone, Debug)]
pub struct VerifiedChunkRange {
    pub start_height: u64,
    pub end_height: u64,
}

#[derive(Clone, Debug)]
pub struct StateSyncVerificationSummary {
    pub snapshot_height: Option<u64>,
    pub snapshot_root: Option<String>,
    pub verified_chunk_ranges: Vec<VerifiedChunkRange>,
    pub verified_light_client_heights: Vec<u64>,
    pub failure: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StateSyncVerificationReport {
    pub events: Vec<LightClientVerificationEvent>,
    pub summary: StateSyncVerificationSummary,
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::{global, Context};
    use opentelemetry_sdk::metrics::data::ResourceMetrics;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, MeterProvider, PeriodicReader};
    use rpp_chain::runtime::sync::{ReconstructionEngine, RuntimeRecursiveProofVerifier};
    use rpp_chain::storage::Storage;
    use rpp_p2p::LightClientSync;
    use std::sync::Arc;
    use tempfile::TempDir;

    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/support/mod.rs"
        ));
    }

    #[test]
    fn mid_stream_tamper_aborts_and_records_metric() {
        let (exporter, provider) = setup_metrics();
        global::set_meter_provider(provider.clone());

        let tempdir = TempDir::new().expect("temp dir");
        let storage = Storage::open(tempdir.path()).expect("open storage");

        let mut blocks = Vec::new();
        let mut previous = None;
        for height in 1..=4 {
            let block = support::make_dummy_block(height, previous.as_ref());
            previous = Some(block.clone());
            blocks.push(block);
        }

        support::install_pruned_chain(&storage, &blocks).expect("install pruned chain");
        let engine = ReconstructionEngine::new(storage.clone());
        let artifacts = support::collect_state_sync_artifacts(&engine, 2)
            .expect("collect state sync artifacts");
        assert!(
            artifacts.chunk_messages.len() >= 2,
            "fixture should produce at least two chunks",
        );

        let mut light_client =
            LightClientSync::new(Arc::new(RuntimeRecursiveProofVerifier::default()));
        let plan_bytes = serde_json::to_vec(&artifacts.network_plan).expect("encode plan");
        light_client
            .ingest_plan(&plan_bytes)
            .expect("plan ingestion succeeds");

        let first_chunk = artifacts
            .chunk_messages
            .first()
            .expect("first chunk present");
        let first_bytes = serde_json::to_vec(first_chunk).expect("encode first chunk");
        light_client
            .ingest_chunk(&first_bytes)
            .expect("first chunk ingests");

        let tampered = support::corrupt_chunk_commitment(
            artifacts
                .chunk_messages
                .get(1)
                .expect("second chunk present"),
        );
        let tampered_bytes = serde_json::to_vec(&tampered).expect("encode tampered chunk");
        let err = light_client
            .ingest_chunk(&tampered_bytes)
            .expect_err("tampered chunk should fail");

        let message = err.to_string();
        assert!(
            message.contains("commitment mismatch") || message.contains("root mismatch"),
            "unexpected tamper error: {message}",
        );

        let _ = super::classify_pipeline_error(err);

        provider
            .force_flush(&Context::current())
            .expect("flush metrics");
        let exported: Vec<ResourceMetrics> = exporter.get_finished_metrics().unwrap();
        assert!(metric_observed(
            &exported,
            "rpp_node_pipeline_state_sync_tamper_total"
        ));
    }

    fn setup_metrics() -> (InMemoryMetricExporter, MeterProvider) {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = MeterProvider::builder().with_reader(reader).build();
        (exporter, provider)
    }

    fn metric_observed(exported: &[ResourceMetrics], name: &str) -> bool {
        exported
            .iter()
            .flat_map(|resource| resource.scope_metrics())
            .flat_map(|scope| scope.metrics())
            .any(|metric| metric.name() == name)
    }
}
