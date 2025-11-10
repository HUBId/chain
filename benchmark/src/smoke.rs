// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use firewood::db::Db;
use firewood::v2::api::{Db as _, Proposal as _};
use log::info;
use serde::Serialize;

use crate::{baseline, Args, TestRunner};

const MAX_BATCHES: u64 = 5;
const MAX_BATCH_SIZE: u64 = 100;
const OUTPUT_ENV: &str = "FIREWOOD_SMOKE_OUTPUT";
const DEFAULT_OUTPUT_FILE: &str = "smoke-metrics.json";

pub struct Smoke;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SmokeRunMetrics {
    pub(crate) batches: u64,
    pub(crate) batch_size: u64,
    pub(crate) total_operations: u64,
    pub(crate) total_duration_ms: f64,
    pub(crate) throughput_ops_per_sec: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) per_batch_ms: Vec<f64>,
}

impl Smoke {
    fn workload(args: &Args) -> (u64, u64) {
        let batches = args.global_opts.number_of_batches.min(MAX_BATCHES).max(1);
        let batch_size = args.global_opts.batch_size.min(MAX_BATCH_SIZE).max(1);
        (batches, batch_size)
    }

    fn output_path() -> PathBuf {
        std::env::var(OUTPUT_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_OUTPUT_FILE))
    }

    fn throughput(total_ops: u64, total_duration: Duration) -> f64 {
        if total_ops == 0 {
            return 0.0;
        }
        let seconds = total_duration.as_secs_f64();
        if seconds == 0.0 {
            return total_ops as f64;
        }
        total_ops as f64 / seconds
    }
}

impl TestRunner for Smoke {
    fn run(&self, db: &Db, args: &Args) -> Result<(), Box<dyn Error>> {
        let (batches, batch_size) = Self::workload(args);
        let mut total_duration = Duration::default();
        let mut per_batch_ms = Vec::with_capacity(batches as usize);

        for batch_index in 0..batches {
            let start = Instant::now();
            let inserts = Self::generate_inserts(batch_index * batch_size, batch_size);
            let proposal = db.propose(inserts).expect("proposal should succeed");
            proposal.commit()?;
            let elapsed = start.elapsed();
            per_batch_ms.push(elapsed.as_secs_f64() * 1_000.0);
            total_duration += elapsed;
        }

        let total_ops = batches * batch_size;
        let throughput = Self::throughput(total_ops, total_duration);

        info!(
            "Smoke benchmark committed {batches} batches (size {batch_size}) in {:?} (throughput: {:.2} ops/s)",
            total_duration,
            throughput
        );
        println!(
            "SMOKE_BENCHMARK throughput_ops_per_sec={throughput:.2} total_batches={batches} batch_size={batch_size}"
        );

        let run_metrics = SmokeRunMetrics {
            batches,
            batch_size,
            total_operations: total_ops,
            total_duration_ms: total_duration.as_secs_f64() * 1_000.0,
            throughput_ops_per_sec: throughput,
            per_batch_ms,
        };

        let baseline_report = baseline::evaluate(&run_metrics)?;

        let metrics = serde_json::json!({
            "batches": run_metrics.batches,
            "batch_size": run_metrics.batch_size,
            "total_operations": run_metrics.total_operations,
            "total_duration_ms": run_metrics.total_duration_ms,
            "per_batch_ms": run_metrics.per_batch_ms,
            "throughput_ops_per_sec": run_metrics.throughput_ops_per_sec,
            "baseline": baseline_report,
        });

        let output_path = Self::output_path();
        fs::write(&output_path, serde_json::to_string_pretty(&metrics)?)?;
        info!(
            "Smoke benchmark metrics written to {}",
            output_path.display()
        );

        Ok(())
    }
}
