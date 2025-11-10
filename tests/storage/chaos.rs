use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use metrics_exporter_prometheus::PrometheusBuilder;
use rand::RngCore;
use storage_firewood::kv::FirewoodKv;
use tempfile::TempDir;

#[path = "../support/mod.rs"]
mod support;

use support::seeded_rng;

const CHAOS_HELPER_ENV: &str = "FIREWOOD_WAL_CHAOS_HELPER";
const CHAOS_DIR_ENV: &str = "FIREWOOD_WAL_CHAOS_DIR";
const CHAOS_READY_MSG: &str = "wal_chaos_ready";
const COMMIT_PAUSE_ENV: &str = "FIREWOOD_KV_COMMIT_PAUSE_PATH";
const ARTIFACT_DIR_ENV: &str = "FIREWOOD_WAL_CHAOS_ARTIFACT_DIR";
const WAL_FILE: &str = "firewood.wal";
const CHAOS_VALUE_SIZE: usize = 64 * 1024;
const CHAOS_MUTATION_COUNT: usize = 128;
const READY_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const ARTIFACT_NAMESPACE: &str = "target/compliance/chaos/firewood-wal";
const CHAOS_KEY_PREFIX: &str = "chaos-00000000-0000";

#[test]
#[ignore = "nightly chaos scenario"]
fn wal_crash_recovery_handles_abrupt_termination() -> Result<()> {
    if env::var(CHAOS_HELPER_ENV).as_deref() == Ok("1") {
        run_helper();
    }

    env::remove_var(CHAOS_HELPER_ENV);
    env::remove_var(CHAOS_DIR_ENV);
    env::remove_var(COMMIT_PAUSE_ENV);
    env::remove_var(ARTIFACT_DIR_ENV);

    let temp_dir = TempDir::new().context("create chaos temp dir")?;
    let data_dir = temp_dir.path().join("kv");
    fs::create_dir_all(&data_dir).context("create kv directory")?;

    let mut baseline = FirewoodKv::open(&data_dir).context("open baseline kv")?;
    baseline.put(b"baseline".to_vec(), b"committed".to_vec());
    let baseline_root = baseline.commit().context("commit baseline state")?;
    assert_eq!(baseline.get(b"baseline"), Some(b"committed".to_vec()));
    drop(baseline);

    let pause_path = temp_dir.path().join("commit.pause");
    let artifact_dir = artifact_directory();
    fs::create_dir_all(&artifact_dir).context("create chaos artifact directory")?;

    let wal_path = data_dir.join(WAL_FILE);
    let initial_len = wal_size(&wal_path).context("fetch baseline wal length")?;

    let mut child = Command::new(env::current_exe().context("locate current test binary")?)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(CHAOS_HELPER_ENV, "1")
        .env(CHAOS_DIR_ENV, &data_dir)
        .env(COMMIT_PAUSE_ENV, &pause_path)
        .spawn()
        .context("spawn chaos helper")?;

    let ready_deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < ready_deadline {
        if pause_path.exists() {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    assert!(
        pause_path.exists(),
        "chaos helper never reached commit pause sentinel"
    );

    let post_len = wal_size(&wal_path).context("fetch wal length after helper start")?;
    assert!(
        post_len > initial_len,
        "wal did not grow before simulated crash"
    );

    let output = terminate_helper(&mut child).context("terminate chaos helper")?;

    let stdout_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout_text.contains(CHAOS_READY_MSG),
        "helper never signaled heavy wal activity: {stdout_text}"
    );

    if pause_path.exists() {
        fs::remove_file(&pause_path).context("remove commit pause sentinel")?;
    }

    let crash_wal = artifact_dir.join("firewood.wal.after_crash");
    fs::copy(&wal_path, &crash_wal).context("persist crashed wal artifact")?;

    if !output.stdout.is_empty() {
        fs::write(artifact_dir.join("helper.stdout.log"), &output.stdout)
            .context("write helper stdout artifact")?;
    }
    if !output.stderr.is_empty() {
        fs::write(artifact_dir.join("helper.stderr.log"), &output.stderr)
            .context("write helper stderr artifact")?;
    }

    let prometheus = PrometheusBuilder::new()
        .install_recorder()
        .context("install prometheus metrics recorder")?;

    let recovered = FirewoodKv::open(&data_dir).context("reopen kv after crash")?;
    assert_eq!(
        recovered.get(b"baseline"),
        Some(b"committed".to_vec()),
        "baseline key lost across crash recovery"
    );
    assert_eq!(
        recovered.root_hash(),
        baseline_root,
        "recovered root hash diverged after crash"
    );
    assert!(
        recovered.get(CHAOS_KEY_PREFIX.as_bytes()).is_none(),
        "inflight transaction committed despite crash"
    );
    let last_key = format!("chaos-00000000-{CHAOS_MUTATION_COUNT - 1:04}");
    assert!(
        recovered.get(last_key.as_bytes()).is_none(),
        "last staged mutation unexpectedly visible after crash"
    );
    drop(recovered);

    let metrics = prometheus.render();
    assert!(
        metrics.contains("firewood_wal_transactions_total{result=\"rolled_back\"} 1"),
        "rolled_back metric missing from export: {metrics}"
    );

    let recovered_wal = artifact_dir.join("firewood.wal.after_recovery");
    fs::copy(&wal_path, &recovered_wal).context("persist recovered wal artifact")?;
    fs::write(artifact_dir.join("metrics.prom"), metrics.as_bytes())
        .context("write metrics artifact")?;

    let summary = format!(
        "baseline_root={baseline_root:?}\ncrash_wal={}\nrecovered_wal={}\n",
        crash_wal.display(),
        recovered_wal.display()
    );
    fs::write(artifact_dir.join("recovery.summary"), summary)
        .context("write recovery summary artifact")?;

    Ok(())
}

fn run_helper() -> ! {
    let data_dir = PathBuf::from(env::var(CHAOS_DIR_ENV).expect("chaos dir env not set"));
    let pause_path = PathBuf::from(env::var(COMMIT_PAUSE_ENV).expect("commit pause env not set"));

    let mut rng = seeded_rng("storage_chaos_helper");
    let mut kv = FirewoodKv::open(&data_dir).expect("open kv for chaos writes");

    for chunk in 0..CHAOS_MUTATION_COUNT {
        let mut value = vec![0u8; CHAOS_VALUE_SIZE];
        rng.fill_bytes(&mut value);
        let key = format!("chaos-00000000-{chunk:04}").into_bytes();
        kv.put(key, value);
    }

    println!("{CHAOS_READY_MSG}");
    std::io::stdout()
        .flush()
        .expect("flush chaos helper readiness signal");

    let _ = kv.commit();
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn wal_size(path: &Path) -> Result<u64> {
    Ok(fs::metadata(path).context("wal metadata")?.len())
}

fn terminate_helper(child: &mut std::process::Child) -> Result<std::process::Output> {
    let _ = child.kill();
    child.wait_with_output().context("wait for helper exit")
}

fn artifact_directory() -> PathBuf {
    match env::var(ARTIFACT_DIR_ENV) {
        Ok(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(ARTIFACT_NAMESPACE),
    }
}
