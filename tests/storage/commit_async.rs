use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use firewood::manager::{clear_commit_flush_delay, set_commit_flush_delay};
use firewood::{BatchOp, Db, DbConfig};
use firewood_storage::noop_storage_metrics;
use metrics_exporter_prometheus::PrometheusBuilder;
use tempfile::TempDir;

const QUEUE_METRIC: &str = "firewood_commit_wal_flush_queue_depth";
const WAIT_METRIC: &str = "firewood_commit_wal_flush_wait_seconds";

fn gauge_value(metrics: &str, name: &str) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.starts_with(name) {
            return None;
        }

        line.split_whitespace()
            .last()
            .and_then(|value| value.parse::<f64>().ok())
    })
}

fn histogram_sum(metrics: &str, name: &str) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.starts_with(&format!("{name}_sum")) {
            return None;
        }

        line.split_whitespace()
            .last()
            .and_then(|value| value.parse::<f64>().ok())
    })
}

struct FlushDelayGuard;

impl FlushDelayGuard {
    fn install(delay: Duration) -> Self {
        set_commit_flush_delay(delay);
        Self
    }
}

impl Drop for FlushDelayGuard {
    fn drop(&mut self) {
        clear_commit_flush_delay();
    }
}

#[test]
fn wal_flush_executor_reports_queue_depth_and_latency() -> Result<()> {
    let delay = Duration::from_millis(200);
    let _guard = FlushDelayGuard::install(delay);

    let prometheus = PrometheusBuilder::new().install_recorder()?;
    let temp_dir = TempDir::new()?;
    let db = Db::new(
        temp_dir.path(),
        DbConfig::builder().build(),
        noop_storage_metrics(),
    )?;

    let first = db.propose(vec![BatchOp::Put {
        key: b"key".to_vec(),
        value: b"value".to_vec(),
    }])?;

    let commit_start = Instant::now();

    thread::scope(|scope| -> Result<()> {
        let handle = scope.spawn(|| first.commit());

        let mut observed_queue = false;
        for _ in 0..50 {
            if handle.is_finished() {
                break;
            }

            let snapshot = prometheus.render();
            if gauge_value(&snapshot, QUEUE_METRIC).unwrap_or_default() > 0.0 {
                observed_queue = true;
                break;
            }

            thread::sleep(Duration::from_millis(10));
        }

        assert!(
            observed_queue,
            "expected WAL flush queue depth to grow while commit pending"
        );
        assert!(
            !handle.is_finished(),
            "commit finished before telemetry captured queue depth"
        );

        let second = db.propose(vec![BatchOp::Put {
            key: b"side".to_vec(),
            value: b"value".to_vec(),
        }])?;
        assert!(
            second.root_hash()?.is_some(),
            "second proposal should compute root hash"
        );

        handle
            .join()
            .map_err(|_| anyhow!("commit thread panicked"))??;

        assert!(
            commit_start.elapsed() >= delay,
            "commit must incur configured WAL flush delay"
        );

        let snapshot = prometheus.render();
        let depth = gauge_value(&snapshot, QUEUE_METRIC).unwrap_or_default();
        assert!(
            depth.abs() <= f64::EPSILON,
            "queue depth should drain after commit: {snapshot}"
        );

        let wait_sum = histogram_sum(&snapshot, WAIT_METRIC).unwrap_or_default();
        assert!(
            wait_sum > 0.0,
            "flush wait histogram should record latency: {snapshot}"
        );

        second.commit()?;

        Ok(())
    })?;

    Ok(())
}
