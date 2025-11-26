use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::{
    column_family::ColumnFamily,
    kv::{FirewoodKv, Hash, KvError},
    pruning::{FirewoodPruner, PersistedPrunerState, SnapshotManifest},
    tree::{FirewoodTree, MerkleProof},
};

pub type StateRoot = Hash;

pub const STORAGE_LAYOUT_VERSION: u32 = 1;
const CF_PRUNING_SNAPSHOTS: &str = "cf_pruning_snapshots";
const CF_PRUNING_PROOFS: &str = "cf_pruning_proofs";
const CF_META: &str = "cf_meta";
const META_LAYOUT_KEY: &str = "layout_version.json";
const META_PRUNER_KEY: &str = "pruner_state.json";
const META_TELEMETRY_KEY: &str = "telemetry.json";

#[derive(Debug, Error)]
pub enum StateError {
    #[error("kv error: {0}")]
    Kv(#[from] KvError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("storage layout requires migration from {from} to {to}")]
    MigrationRequired { from: u32, to: u32 },
    #[error("storage layout {stored} is newer than supported {current}")]
    UnsupportedLayout { stored: u32, current: u32 },
}

pub struct FirewoodState {
    kv: Mutex<FirewoodKv>,
    tree: RwLock<FirewoodTree>,
    pruner: Mutex<FirewoodPruner>,
    snapshots_cf: ColumnFamily,
    proofs_cf: ColumnFamily,
    meta_cf: ColumnFamily,
    options: StorageOptions,
}

impl FirewoodState {
    pub fn open(path: &str) -> Result<Arc<Self>, StateError> {
        Self::open_with_options(path, StorageOptions::default())
    }

    pub fn open_with_options<P: AsRef<Path>>(
        path: P,
        options: StorageOptions,
    ) -> Result<Arc<Self>, StateError> {
        let kv = FirewoodKv::open(path)?;
        let mut tree = FirewoodTree::new();
        for (key, value) in kv.scan_prefix(b"") {
            tree.update(&key, value);
        }
        let base_dir = kv.base_dir().to_path_buf();
        let snapshots_cf = if let Some(dir) = options.snapshot_dir.clone() {
            ColumnFamily::open_at(dir)?
        } else {
            ColumnFamily::open(&base_dir, CF_PRUNING_SNAPSHOTS)?
        };
        let proofs_cf = if let Some(dir) = options.proof_dir.clone() {
            ColumnFamily::open_at(dir)?
        } else {
            ColumnFamily::open(&base_dir, CF_PRUNING_PROOFS)?
        };
        let meta_cf = ColumnFamily::open(&base_dir, CF_META)?;

        let stored_layout = read_layout_version(&meta_cf)?;
        if stored_layout > STORAGE_LAYOUT_VERSION {
            return Err(StateError::UnsupportedLayout {
                stored: stored_layout,
                current: STORAGE_LAYOUT_VERSION,
            });
        }

        if stored_layout < STORAGE_LAYOUT_VERSION {
            if env::var_os("FIREWOOD_MIGRATION_DRY_RUN").is_some() {
                return Err(StateError::MigrationRequired {
                    from: stored_layout,
                    to: STORAGE_LAYOUT_VERSION,
                });
            }
            run_migrations(
                &meta_cf,
                stored_layout,
                STORAGE_LAYOUT_VERSION,
                options.sync_policy,
            )?;
        }

        let mut pruner = if let Some(mut persisted) =
            meta_cf.get_json::<PersistedPrunerState>(META_PRUNER_KEY)?
        {
            if persisted.retain == 0 {
                persisted.retain = options.retain_snapshots.max(1);
            }
            FirewoodPruner::from_persisted(persisted)
        } else {
            FirewoodPruner::new(options.retain_snapshots)
        };

        // Ensure we persist the current layout marker for fresh deployments.
        persist_pruner_state(
            &meta_cf,
            &mut pruner,
            STORAGE_LAYOUT_VERSION,
            options.sync_policy,
        )?;

        Ok(Arc::new(FirewoodState {
            kv: Mutex::new(kv),
            tree: RwLock::new(tree),
            pruner: Mutex::new(pruner),
            snapshots_cf,
            proofs_cf,
            meta_cf,
            options,
        }))
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.kv.lock().get(key)
    }

    pub fn put(&self, key: Vec<u8>, value: Vec<u8>) {
        self.kv.lock().put(key.clone(), value.clone());
        let mut tree = self.tree.write();
        tree.update(&key, value);
    }

    pub fn delete(&self, key: &[u8]) {
        self.kv.lock().delete(key);
        let mut tree = self.tree.write();
        tree.delete(key);
    }

    pub fn commit_block(
        &self,
        block_id: u64,
    ) -> Result<(StateRoot, Arc<rpp_pruning::Envelope>), StateError> {
        let mut kv = self.kv.lock();
        let root = kv.commit()?;
        drop(kv);
        let mut pruner = self.pruner.lock();
        let proof = Arc::new(pruner.prune_block(block_id, root));
        let proof_bytes = bincode::serialize(proof.as_ref())?;
        let proof_name = format!("{block_id:020}.bin");
        self.proofs_cf.put_bytes(
            &proof_name,
            &proof_bytes,
            self.options.sync_policy == SyncPolicy::Always,
        )?;

        let manifest = pruner.manifest(
            STORAGE_LAYOUT_VERSION,
            block_id,
            root,
            proof_name.clone(),
            &proof_bytes,
        );
        let manifest_name = format!("{block_id:020}.json");
        self.snapshots_cf.put_json(
            &manifest_name,
            &manifest,
            self.options.sync_policy == SyncPolicy::Always,
        )?;

        let exported = pruner.export_state();
        let persisted = persist_state_snapshot(
            &self.meta_cf,
            exported,
            STORAGE_LAYOUT_VERSION,
            self.options.sync_policy,
        )?;
        prune_old_artifacts(&self.snapshots_cf, &self.proofs_cf, &persisted)?;

        metrics::counter!(
            "firewood.storage.bytes_written",
            "cf" => CF_PRUNING_PROOFS
        )
        .increment(proof_bytes.len() as u64);

        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|err| StateError::Serialization(err.to_string()))?;
        metrics::counter!(
            "firewood.storage.bytes_written",
            "cf" => CF_PRUNING_SNAPSHOTS
        )
        .increment(manifest_bytes.len() as u64);

        metrics::gauge!(
            "firewood.storage.io_budget",
            "stage" => "commit"
        )
        .set(self.options.commit_io_budget_bytes as f64);
        metrics::gauge!(
            "firewood.storage.io_budget",
            "stage" => "compaction"
        )
        .set(self.options.compaction_io_budget_bytes as f64);

        let telemetry = CommitTelemetry {
            snapshot_bytes: manifest_bytes.len() as u64,
            proof_bytes: proof_bytes.len() as u64,
            commit_budget_bytes: self.options.commit_io_budget_bytes,
            compaction_budget_bytes: self.options.compaction_io_budget_bytes,
        };
        self.meta_cf.put_json(
            META_TELEMETRY_KEY,
            &telemetry,
            self.options.sync_policy == SyncPolicy::Always,
        )?;

        {
            let mut kv = self.kv.lock();
            kv.gc_wal()?;
        }

        Ok((root, proof))
    }

    pub fn prove(&self, key: &[u8]) -> MerkleProof {
        let tree = self.tree.read();
        tree.get_proof(key)
    }

    pub(crate) fn load_meta<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StateError> {
        Ok(self.meta_cf.get_json(key)?)
    }

    pub(crate) fn store_meta<T: Serialize>(&self, key: &str, value: &T) -> Result<(), StateError> {
        self.meta_cf
            .put_json(key, value, self.options.sync_policy == SyncPolicy::Always)?;
        Ok(())
    }

    pub(crate) fn import_snapshot_artifacts(
        &self,
        manifest_name: &str,
        manifest: &SnapshotManifest,
        proof_bytes: &[u8],
    ) -> Result<(), StateError> {
        self.snapshots_cf.put_json(
            manifest_name,
            manifest,
            self.options.sync_policy == SyncPolicy::Always,
        )?;
        self.proofs_cf.put_bytes(
            &manifest.proof_file,
            proof_bytes,
            self.options.sync_policy == SyncPolicy::Always,
        )?;
        Ok(())
    }

    pub(crate) fn remove_snapshots_newer_than(&self, height: u64) -> Result<(), StateError> {
        let keys = self.snapshots_cf.list_keys()?;
        for key in keys {
            if let Some(id) = snapshot_id_from_name(&key) {
                if id > height {
                    if let Some(manifest) = self.snapshots_cf.get_json::<SnapshotManifest>(&key)? {
                        self.snapshots_cf.remove(&key)?;
                        self.proofs_cf.remove(&manifest.proof_file)?;
                    } else {
                        self.snapshots_cf.remove(&key)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl From<bincode::Error> for StateError {
    fn from(err: bincode::Error) -> Self {
        StateError::Serialization(err.to_string())
    }
}

fn read_layout_version(meta_cf: &ColumnFamily) -> Result<u32, StateError> {
    Ok(meta_cf.get_json::<u32>(META_LAYOUT_KEY)?.unwrap_or(0))
}

fn write_layout_version(
    meta_cf: &ColumnFamily,
    version: u32,
    policy: SyncPolicy,
) -> Result<(), StateError> {
    meta_cf.put_json(META_LAYOUT_KEY, &version, policy == SyncPolicy::Always)?;
    Ok(())
}

#[derive(Serialize)]
struct CommitTelemetry {
    snapshot_bytes: u64,
    proof_bytes: u64,
    commit_budget_bytes: u64,
    compaction_budget_bytes: u64,
}

fn run_migrations(
    meta_cf: &ColumnFamily,
    from: u32,
    to: u32,
    policy: SyncPolicy,
) -> Result<(), StateError> {
    let mut version = from;
    while version < to {
        match version {
            0 => {
                write_layout_version(meta_cf, 1, policy)?;
            }
            other => {
                return Err(StateError::UnsupportedLayout {
                    stored: other,
                    current: to,
                });
            }
        }
        version += 1;
    }
    Ok(())
}

fn persist_pruner_state(
    meta_cf: &ColumnFamily,
    pruner: &mut FirewoodPruner,
    layout_version: u32,
    policy: SyncPolicy,
) -> Result<(), StateError> {
    let exported = pruner.export_state();
    let _ = persist_state_snapshot(meta_cf, exported, layout_version, policy)?;
    Ok(())
}

fn persist_state_snapshot(
    meta_cf: &ColumnFamily,
    mut state: PersistedPrunerState,
    layout_version: u32,
    policy: SyncPolicy,
) -> Result<PersistedPrunerState, StateError> {
    state.layout_version = layout_version;
    meta_cf.put_json(META_PRUNER_KEY, &state, policy == SyncPolicy::Always)?;
    Ok(state)
}

fn prune_old_artifacts(
    snapshots_cf: &ColumnFamily,
    proofs_cf: &ColumnFamily,
    state: &PersistedPrunerState,
) -> Result<(), StateError> {
    let retain: HashSet<String> = state
        .snapshots
        .iter()
        .map(|snapshot| format!("{:020}", snapshot.block_height()))
        .collect();

    for entry in snapshots_cf.list_keys()? {
        if let Some(id) = entry.strip_suffix(".json") {
            if !retain.contains(id) {
                snapshots_cf.remove(&entry)?;
            }
        }
    }

    for entry in proofs_cf.list_keys()? {
        if let Some(id) = entry.strip_suffix(".bin") {
            if !retain.contains(id) {
                proofs_cf.remove(&entry)?;
            }
        }
    }

    Ok(())
}

fn snapshot_id_from_name(name: &str) -> Option<u64> {
    let id = name.strip_suffix(".json")?;
    id.parse().ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPolicy {
    Always,
    Deferred,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        SyncPolicy::Always
    }
}

#[derive(Clone, Debug)]
pub struct StorageOptions {
    pub snapshot_dir: Option<PathBuf>,
    pub proof_dir: Option<PathBuf>,
    pub sync_policy: SyncPolicy,
    pub commit_io_budget_bytes: u64,
    pub compaction_io_budget_bytes: u64,
    pub retain_snapshots: usize,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            snapshot_dir: None,
            proof_dir: None,
            sync_policy: SyncPolicy::Always,
            commit_io_budget_bytes: 64 * 1024 * 1024,
            compaction_io_budget_bytes: 128 * 1024 * 1024,
            retain_snapshots: 3,
        }
    }
}
