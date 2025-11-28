#![cfg(all(feature = "prover-stwo", feature = "backend-rpp-stark"))]

use std::fs;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

mod zk_load_common;
use zk_load_common::{emit_vector_checksums, run_rpp_batch, run_stwo_batch};

const MAX_RSS_GROWTH_BYTES: u64 = 50 * 1024 * 1024;
const LOAD_ROUNDS: usize = 4;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zk_backends_hold_rss_under_drift_threshold() -> Result<()> {
    fs::create_dir_all("logs/zk-heap").context("create heap profile directory")?;
    let _profiler = dhat::Profiler::builder()
        .file_name("logs/zk-heap/zk-load-heap.json")
        .build();

    emit_vector_checksums()?;

    let mut peak_rss = current_rss_bytes()?;
    let baseline_rss = peak_rss;

    for _ in 0..LOAD_ROUNDS {
        let stwo_metrics = run_stwo_batch().await.context("stwo batch generation")?;
        assert!(
            stwo_metrics.throughput_per_second > 0.1,
            "stwo throughput should stay above minimal floor"
        );

        let rpp_metrics = run_rpp_batch().await.context("rpp-stark verifier batch")?;
        assert!(
            rpp_metrics.oversize_failure_recorded,
            "oversized proofs must fail"
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        peak_rss = peak_rss.max(current_rss_bytes()?);
    }

    let rss_growth = peak_rss.saturating_sub(baseline_rss);
    ensure_within_growth(rss_growth, MAX_RSS_GROWTH_BYTES)?;

    Ok(())
}

fn current_rss_bytes() -> Result<u64> {
    let statm = fs::read_to_string("/proc/self/statm").context("read statm")?;
    let rss_pages = statm
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("statm missing rss entry"))?
        .parse::<u64>()
        .context("parse statm rss")?;

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(anyhow!("sysconf returned invalid page size"));
    }

    Ok(rss_pages * page_size as u64)
}

fn ensure_within_growth(observed: u64, budget: u64) -> Result<()> {
    if observed <= budget {
        return Ok(());
    }

    Err(anyhow!(
        "rss growth {} bytes exceeded budget {} bytes",
        observed,
        budget
    ))
}
