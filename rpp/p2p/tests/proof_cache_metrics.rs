use std::sync::Arc;

use rpp_p2p::{
    GossipTopic, PeerId, PipelineError, ProofCacheMetrics, ProofMempool, ProofRecord, ProofStorage,
    ProofValidator,
};

#[derive(Debug, Default, Clone)]
struct AcceptAllValidator;

impl ProofValidator for AcceptAllValidator {
    fn validate(&self, _peer: &PeerId, _payload: &[u8]) -> Result<(), PipelineError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct BoundedProofStorage {
    capacity: usize,
    records: parking_lot::Mutex<Vec<ProofRecord>>,
}

impl BoundedProofStorage {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            ..Default::default()
        }
    }
}

impl ProofStorage for BoundedProofStorage {
    fn persist(&self, record: &ProofRecord) -> Result<usize, PipelineError> {
        let mut guard = self.records.lock();
        guard.push(record.clone());
        if guard.len() > self.capacity {
            let evicted = guard.len() - self.capacity;
            guard.drain(0..evicted);
            Ok(evicted)
        } else {
            Ok(0)
        }
    }

    fn load(&self) -> Result<Vec<ProofRecord>, PipelineError> {
        Ok(self.records.lock().clone())
    }
}

fn make_payload(tag: &str) -> Vec<u8> {
    format!("{{\"payload\":\"{tag}\"}}").into_bytes()
}

#[test]
fn cache_miss_recorded_for_unique_payload() {
    let metrics = ProofCacheMetrics::default();
    let validator = Arc::new(AcceptAllValidator::default());
    let storage = Arc::new(BoundedProofStorage::with_capacity(4));
    let mut mempool =
        ProofMempool::new_with_metrics(validator, storage, metrics.clone()).expect("mempool");

    let peer = PeerId::random();
    mempool
        .ingest(peer, GossipTopic::Proofs, make_payload("one"))
        .expect("first payload accepted");

    assert_eq!(
        metrics.snapshot().misses,
        1,
        "first unique payload should be a miss"
    );
    assert_eq!(metrics.snapshot().hits, 0, "no cache hits expected");
    assert_eq!(metrics.snapshot().evictions, 0, "no evictions expected");
}

#[test]
fn cache_hit_recorded_for_duplicate_payload() {
    let metrics = ProofCacheMetrics::default();
    let validator = Arc::new(AcceptAllValidator::default());
    let storage = Arc::new(BoundedProofStorage::with_capacity(4));
    let mut mempool =
        ProofMempool::new_with_metrics(validator, storage, metrics.clone()).expect("mempool");

    let peer = PeerId::random();
    let payload = make_payload("duplicate");

    mempool
        .ingest(peer, GossipTopic::WitnessProofs, payload.clone())
        .expect("first payload accepted");
    let err = mempool
        .ingest(peer, GossipTopic::WitnessProofs, payload)
        .expect_err("second payload must be treated as duplicate");

    assert!(matches!(err, PipelineError::Duplicate));
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.misses, 1, "first insert counts as miss");
    assert_eq!(snapshot.hits, 1, "duplicate insert increments hits");
    assert_eq!(snapshot.evictions, 0, "duplicate should not evict");
}

#[test]
fn eviction_counter_tracks_persistence_evictions() {
    let metrics = ProofCacheMetrics::default();
    let validator = Arc::new(AcceptAllValidator::default());
    let storage = Arc::new(BoundedProofStorage::with_capacity(1));
    let mut mempool =
        ProofMempool::new_with_metrics(validator, storage, metrics.clone()).expect("mempool");

    let peer = PeerId::random();
    mempool
        .ingest(peer, GossipTopic::Proofs, make_payload("first"))
        .expect("first payload accepted");
    mempool
        .ingest(peer, GossipTopic::Proofs, make_payload("second"))
        .expect("second payload accepted");

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.misses, 2, "each unique payload counts as miss");
    assert_eq!(snapshot.hits, 0, "no duplicates were processed");
    assert_eq!(
        snapshot.evictions, 1,
        "storage evictions should be recorded"
    );
}

#[test]
fn cache_metrics_snapshot_preserves_export_format() {
    let metrics = ProofCacheMetrics::default();
    let expected = serde_json::json!({
        "hits": 0,
        "misses": 0,
        "evictions": 0,
    });
    assert_eq!(
        serde_json::to_value(metrics.snapshot()).expect("serializable"),
        expected,
        "telemetry payload for cache metrics should remain stable",
    );
}
