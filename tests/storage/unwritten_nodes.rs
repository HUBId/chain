use anyhow::Result;
use firewood::{BatchOp, Db, DbConfig};
use firewood_storage::noop_storage_metrics;
use metrics_exporter_prometheus::PrometheusBuilder;
use tempfile::TempDir;

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

#[test]
fn unwritten_nodes_metric_tracks_commit_cycles() -> Result<()> {
    let prometheus = PrometheusBuilder::new().install_recorder()?;
    let temp_dir = TempDir::new()?;

    let db = Db::new(
        temp_dir.path(),
        DbConfig::builder().build(),
        noop_storage_metrics(),
    )?;

    let metric_name = "firewood_nodestore_unwritten_nodes";
    let initial = prometheus.render();
    let baseline = gauge_value(&initial, metric_name).unwrap_or_default();
    assert!(
        baseline.abs() <= f64::EPSILON,
        "baseline gauge must start at 0: {baseline}"
    );

    let proposal = db.propose(vec![BatchOp::Put {
        key: b"key".to_vec(),
        value: b"value".to_vec(),
    }])?;
    let after_propose = prometheus.render();
    let queued = gauge_value(&after_propose, metric_name)
        .expect("gauge should be exported after staging nodes");
    assert!(
        queued > 0.0,
        "expected queued nodes after staging: {after_propose}"
    );

    proposal.commit()?;
    let after_commit = prometheus.render();
    let drained =
        gauge_value(&after_commit, metric_name).expect("gauge should remain exported after commit");
    assert!(
        drained.abs() <= f64::EPSILON,
        "gauge must drain to zero after commit: {after_commit}"
    );

    let proposal = db.propose(vec![BatchOp::Put {
        key: b"key".to_vec(),
        value: b"next".to_vec(),
    }])?;
    let after_second_propose = prometheus.render();
    let second_queue = gauge_value(&after_second_propose, metric_name).unwrap();
    assert!(
        second_queue > 0.0,
        "queue should grow for second commit: {after_second_propose}"
    );

    proposal.commit()?;
    let after_second_commit = prometheus.render();
    let final_value = gauge_value(&after_second_commit, metric_name).unwrap();
    assert!(
        final_value.abs() <= f64::EPSILON,
        "gauge must reset after second commit: {after_second_commit}"
    );

    Ok(())
}
