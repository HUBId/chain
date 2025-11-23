use anyhow::Result;
use firewood_storage::nodestore::alloc::test_utils::test_write_header;
use firewood_storage::nodestore::{FreeLists, NodeStoreHeader};
use firewood_storage::{noop_storage_metrics, CheckOpt, NodeStore};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use tempfile::TempDir;

fn prometheus_handle() -> &'static PrometheusHandle {
    static PROMETHEUS: OnceLock<PrometheusHandle> = OnceLock::new();
    PROMETHEUS.get_or_init(|| PrometheusBuilder::new().install_recorder().unwrap())
}

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

fn metric_delta(before: &str, after: &str, name: &str) -> f64 {
    let before_value = metric_value(before, name).unwrap_or_default();
    let after_value = metric_value(after, name).unwrap_or_default();
    after_value - before_value
}

#[derive(Debug, Default)]
struct FailingMemStore {
    inner: firewood_storage::linear::memory::MemStore,
    fail_on: Mutex<HashSet<u64>>,
}

impl firewood_storage::ReadableStorage for FailingMemStore {
    fn stream_from(&self, addr: u64) -> Result<impl firewood_storage::OffsetReader, firewood_storage::FileIoError> {
        self.inner.stream_from(addr)
    }

    fn size(&self) -> Result<u64, firewood_storage::FileIoError> {
        self.inner.size()
    }
}

impl firewood_storage::WritableStorage for FailingMemStore {
    fn write(&self, offset: u64, object: &[u8]) -> Result<usize, firewood_storage::FileIoError> {
        if self.fail_on.lock().unwrap().contains(&offset) {
            return Err(firewood_storage::FileIoError::from_generic_no_file(
                std::io::Error::new(std::io::ErrorKind::Other, "forced failure"),
                "failing memstore write",
                offset,
            ));
        }

        self.inner.write(offset, object)
    }
}

#[test]
fn checker_emits_leak_fix_metrics() -> Result<()> {
    let prometheus = prometheus_handle();
    let before_metrics = prometheus.render();
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

    let fixed = metric_delta(
        &before_metrics,
        &exported,
        "firewood_checker_leaked_areas_fixed",
    );
    assert!(fixed >= 1.0, "expected at least one leak fix recorded");

    let failed = metric_delta(
        &before_metrics,
        &exported,
        "firewood_checker_leaked_areas_failed_to_fix",
    );
    assert!(failed.abs() <= f64::EPSILON, "no failures expected: {exported}");

    // Persist the nodestore to disk to keep parity with other storage integration tests.
    drop(nodestore);
    drop(temp_dir);

    Ok(())
}

#[test]
fn checker_metrics_capture_io_failures_and_partial_progress() -> Result<()> {
    let prometheus = prometheus_handle();
    let before_metrics = prometheus.render();

    let mut nodestore = NodeStore::new_empty_committed(
        std::sync::Arc::new(FailingMemStore::default()),
        noop_storage_metrics(),
    )?;

    // Write a zeroed span that will be split into multiple leaked areas.
    // The first leaked block write will be forced to fail to simulate IO errors during repair.
    let leaked_range_size = 1024 + 768 + 128 + 64 + 16;
    firewood_storage::nodestore::alloc::test_utils::test_write_zeroed_area(
        &nodestore,
        leaked_range_size,
        NodeStoreHeader::SIZE,
    );

    let leaked_range = &nonzero!(NodeStoreHeader::SIZE).into()..&LinearAddress::new(
        NodeStoreHeader::SIZE + leaked_range_size,
    )
    .unwrap();
    let leaked_areas: Vec<_> = nodestore
        .split_range_into_leaked_areas(leaked_range, None)
        .into_iter()
        .collect();
    assert!(leaked_areas.len() > 1, "expected multiple leaked areas for partial repair checks");

    // Force the first leaked block to fail during enqueue while allowing others to succeed.
    nodestore
        .storage()
        .fail_on
        .lock()
        .unwrap()
        .insert(leaked_areas[0].0.get());

    let mut proposal = NodeStore::<MutableProposal, _>::new(&nodestore)?;
    let fix_report = proposal.fix(CheckerReport {
        errors: vec![CheckerError::AreaLeaks(vec![
            *leaked_range.start..*leaked_range.end,
        ])],
        db_stats: DBStats {
            high_watermark: leaked_range.end.get(),
            trie_stats: TrieStats::default(),
            free_list_stats: FreeListsStats::default(),
        },
    });

    let expected_failures = 1_u64;
    let expected_successes = leaked_areas.len() as u64 - expected_failures;
    assert_eq!(fix_report.unfixable.len() as u64, expected_failures);
    assert!(fix_report.unfixable.iter().all(|(_, err)| err.is_some()));
    assert_eq!(fix_report.fixed.len(), 0, "partial repairs remain flagged for operator review");

    let after_metrics = prometheus.render();

    let detected_delta = metric_delta(
        &before_metrics,
        &after_metrics,
        "firewood_checker_leaked_areas_detected",
    );
    assert_eq!(detected_delta, leaked_areas.len() as f64);

    let fixed_delta = metric_delta(
        &before_metrics,
        &after_metrics,
        "firewood_checker_leaked_areas_fixed",
    );
    assert_eq!(fixed_delta, expected_successes as f64);

    let failed_delta = metric_delta(
        &before_metrics,
        &after_metrics,
        "firewood_checker_leaked_areas_failed_to_fix",
    );
    assert_eq!(failed_delta, expected_failures as f64);

    Ok(())
}
