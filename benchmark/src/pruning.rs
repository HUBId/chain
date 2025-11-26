use std::error::Error;
use std::fs;
use std::time::{Duration, Instant};

use log::info;
use serde::Serialize;
use sha2::{Digest, Sha256};
use storage_firewood::{pruning::FirewoodPruner, Storage, StorageOptions, SyncPolicy};
use tempfile::tempdir;

use crate::{pruning_baseline, Args, TestRunner};

const DEFAULT_BLOCKS: u64 = 3;
const OPS_PER_BLOCK: u64 = 32;
const OUTPUT_ENV: &str = "FIREWOOD_PRUNING_OUTPUT";
const DEFAULT_OUTPUT_FILE: &str = "pruning-metrics.json";

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PruningRunMetrics {
    pub(crate) backend: &'static str,
    pub(crate) branch_factor: u16,
    pub(crate) blocks: u64,
    pub(crate) ops_per_block: u64,
    pub(crate) total_operations: u64,
    pub(crate) total_duration_ms: f64,
    pub(crate) throughput_ops_per_sec: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) per_block_ms: Vec<f64>,
}

pub struct Pruning;

impl Pruning {
    const fn backend() -> &'static str {
        if cfg!(feature = "io-uring") {
            "io-uring"
        } else {
            "standard"
        }
    }

    const fn branch_factor() -> u16 {
        if cfg!(feature = "branch_factor_256") {
            256
        } else {
            16
        }
    }

    fn output_path() -> std::path::PathBuf {
        std::env::var(OUTPUT_ENV)
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_OUTPUT_FILE))
    }

    fn dataset() -> Vec<(Vec<u8>, Vec<u8>)> {
        (0..(DEFAULT_BLOCKS * OPS_PER_BLOCK))
            .map(|index| {
                let digest: [u8; 32] = Sha256::digest(index.to_be_bytes())
                    .as_slice()
                    .try_into()
                    .expect("sha2 output is 32 bytes");
                let value: [u8; 32] = Sha256::digest((index + 1).to_be_bytes())
                    .as_slice()
                    .try_into()
                    .expect("sha2 output is 32 bytes");
                (digest.to_vec(), value.to_vec())
            })
            .collect()
    }

    fn throughput(total_ops: u64, elapsed: Duration) -> f64 {
        if total_ops == 0 {
            return 0.0;
        }
        let seconds = elapsed.as_secs_f64();
        if seconds == 0.0 {
            return total_ops as f64;
        }
        total_ops as f64 / seconds
    }
}

impl TestRunner for Pruning {
    fn run(&self, _db: &firewood::db::Db, _args: &Args) -> Result<(), Box<dyn Error>> {
        let dataset = Self::dataset();
        let storage_root = tempdir()?;
        let mut options = StorageOptions::default();
        options.retain_snapshots = DEFAULT_BLOCKS as usize;
        options.sync_policy = SyncPolicy::Deferred;
        let state = Storage::open_with_options(storage_root.path().to_str().unwrap(), options)?;

        let mut per_block_ms = Vec::with_capacity(DEFAULT_BLOCKS as usize);
        let mut total_ops = 0;
        let bench_start = Instant::now();

        for block in 0..DEFAULT_BLOCKS {
            let block_start = Instant::now();
            let start = block * OPS_PER_BLOCK;
            let end = start + OPS_PER_BLOCK;
            for (key, value) in &dataset[start as usize..end as usize] {
                state.put(key.clone(), value.clone());
                total_ops += 1;
            }
            let (root, proof) = state.commit_block(block + 1)?;
            assert!(FirewoodPruner::verify_pruned_state(root, proof.as_ref()));
            per_block_ms.push(block_start.elapsed().as_secs_f64() * 1_000.0);
        }

        let total_duration = bench_start.elapsed();
        let throughput = Self::throughput(total_ops, total_duration);

        info!(
            "Pruning benchmark wrote {total_ops} ops across {DEFAULT_BLOCKS} blocks (backend: {}, branch factor: {}, throughput: {:.2} ops/s)",
            Self::backend(),
            Self::branch_factor(),
            throughput
        );
        println!(
            "PRUNING_BENCHMARK backend={} branch_factor={} throughput_ops_per_sec={throughput:.2} blocks={DEFAULT_BLOCKS} ops_per_block={OPS_PER_BLOCK}",
            Self::backend(),
            Self::branch_factor(),
        );

        let metrics = PruningRunMetrics {
            backend: Self::backend(),
            branch_factor: Self::branch_factor(),
            blocks: DEFAULT_BLOCKS,
            ops_per_block: OPS_PER_BLOCK,
            total_operations: total_ops,
            total_duration_ms: total_duration.as_secs_f64() * 1_000.0,
            throughput_ops_per_sec: throughput,
            per_block_ms,
        };

        let baseline_report = pruning_baseline::evaluate(&metrics)?;
        if !baseline_report.within_thresholds() {
            return Err("pruning benchmark fell outside baseline thresholds".into());
        }

        let payload = serde_json::json!({
            "backend": metrics.backend,
            "branch_factor": metrics.branch_factor,
            "blocks": metrics.blocks,
            "ops_per_block": metrics.ops_per_block,
            "total_operations": metrics.total_operations,
            "total_duration_ms": metrics.total_duration_ms,
            "per_block_ms": metrics.per_block_ms,
            "throughput_ops_per_sec": metrics.throughput_ops_per_sec,
            "baseline": baseline_report,
        });

        let output_path = Self::output_path();
        fs::write(&output_path, serde_json::to_string_pretty(&payload)?)?;
        info!(
            "Pruning benchmark metrics written to {}",
            output_path.display()
        );

        Ok(())
    }
}
