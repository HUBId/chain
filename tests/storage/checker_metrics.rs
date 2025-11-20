use anyhow::Result;
use firewood_storage::nodestore::alloc::test_utils::test_write_header;
use firewood_storage::nodestore::{FreeLists, NodeStoreHeader};
use firewood_storage::{noop_storage_metrics, CheckOpt, NodeStore};
use metrics_exporter_prometheus::PrometheusBuilder;
use tempfile::TempDir;

fn metric_value(metrics: &str, name: &str) -> Option<f64> {
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
fn checker_emits_leak_fix_metrics() -> Result<()> {
    let prometheus = PrometheusBuilder::new().install_recorder()?;
    let temp_dir = TempDir::new()?;

    let memstore = firewood_storage::linear::memory::MemStore::new(vec![]);
    let mut nodestore =
        NodeStore::new_empty_committed(memstore.into(), noop_storage_metrics())?;

    // Write a header that declares additional space without mapping it to free lists or trie
    // roots so the checker will detect and repair the leaked span.
    test_write_header(
        &mut nodestore,
        NodeStoreHeader::SIZE + 4096,
        None,
        FreeLists::default(),
    );

    let (result, _report) = nodestore.check_and_fix(CheckOpt {
        hash_check: false,
        progress_bar: None,
    });
    result.expect("leaked area should be re-queued successfully");

    let exported = prometheus.render();

    let leaked_ranges = metric_value(&exported, "firewood_checker_leaked_ranges")
        .expect("checker should export leaked range gauge");
    assert_eq!(leaked_ranges, 1.0);

    let detected_areas = metric_value(&exported, "firewood_checker_leaked_areas_detected")
        .expect("checker should export leaked area gauge");
    assert_eq!(detected_areas, 1.0);

    let fixed = metric_value(&exported, "firewood_checker_leaked_areas_fixed")
        .expect("fixed counter should be exported");
    assert!(fixed >= 1.0, "expected at least one leak fix recorded");

    let failed = metric_value(&exported, "firewood_checker_leaked_areas_failed_to_fix")
        .unwrap_or_default();
    assert!(failed.abs() <= f64::EPSILON, "no failures expected: {exported}");

    // Persist the nodestore to disk to keep parity with other storage integration tests.
    drop(nodestore);
    drop(temp_dir);

    Ok(())
}
