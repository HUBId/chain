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

fn ingest_many(
    mempool: &mut ProofMempool,
    peer: PeerId,
    topic: GossipTopic,
    tags: impl IntoIterator<Item = String>,
) {
    for tag in tags.into_iter() {
        mempool
            .ingest(peer, topic, make_payload(&tag))
            .unwrap_or_else(|err| panic!("failed to ingest {tag}: {err:?}"));
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

    fn capacity(&self) -> Option<usize> {
        Some(self.capacity)
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
        "capacity": 0,
    });
    assert_eq!(
        serde_json::to_value(metrics.snapshot()).expect("serializable"),
        expected,
        "telemetry payload for cache metrics should remain stable",
    );
}

#[test]
fn cache_snapshot_captures_backend_capacity() {
    let metrics = ProofCacheMetrics::default();
    metrics.configure("rpp-stark", 6);
    let validator = Arc::new(AcceptAllValidator::default());
    let storage = Arc::new(BoundedProofStorage::with_capacity(6));

    let _mempool =
        ProofMempool::new_with_metrics(validator, storage, metrics.clone()).expect("mempool");

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.capacity, 6,
        "configured capacity should be recorded"
    );
    assert_eq!(
        snapshot.backend.as_deref(),
        Some("rpp-stark"),
        "backend label should be preserved for telemetry",
    );
}

#[test]
fn eviction_policy_is_fifo_and_hits_survive_eviction() {
    let metrics = ProofCacheMetrics::default();
    let validator = Arc::new(AcceptAllValidator::default());
    let storage = Arc::new(BoundedProofStorage::with_capacity(4));
    let mut mempool = ProofMempool::new_with_metrics(validator, storage.clone(), metrics.clone())
        .expect("mempool");

    let peer = PeerId::random();
    let initial_payloads: Vec<String> = (0..6).map(|idx| format!("payload-{idx}")).collect();
    ingest_many(
        &mut mempool,
        peer,
        GossipTopic::Proofs,
        initial_payloads.clone(),
    );

    let stored_tags: Vec<String> = storage
        .records()
        .into_iter()
        .map(|record| String::from_utf8(record.payload).expect("payload UTF-8"))
        .collect();

    assert_eq!(
        stored_tags,
        vec![
            make_payload("payload-2"),
            make_payload("payload-3"),
            make_payload("payload-4"),
            make_payload("payload-5"),
        ]
        .into_iter()
        .map(String::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .expect("utf8 payloads"),
        "proof cache should evict the oldest entries first",
    );

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.misses, 6, "all unique payloads are misses");
    assert_eq!(snapshot.hits, 0, "no duplicates ingested yet");
    assert_eq!(snapshot.evictions, 2, "overflow should evict two records");

    // Re-ingest an evicted payload to ensure duplicate detection continues to work.
    let duplicate = make_payload("payload-0");
    let err = mempool
        .ingest(peer, GossipTopic::Proofs, duplicate.clone())
        .expect_err("duplicate payload should be rejected even after eviction");
    assert!(matches!(err, PipelineError::Duplicate));

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.misses, 6, "no new misses should be counted");
    assert_eq!(snapshot.hits, 1, "evicted entries still count as hits");
    assert_eq!(snapshot.evictions, 2, "no extra evictions were triggered");
}

#[test]
fn eviction_hit_rate_stays_stable_under_pressure() {
    let metrics = ProofCacheMetrics::default();
    let validator = Arc::new(AcceptAllValidator::default());
    let storage = Arc::new(BoundedProofStorage::with_capacity(8));
    let mut mempool =
        ProofMempool::new_with_metrics(validator, storage, metrics.clone()).expect("mempool");

    let peer = PeerId::random();
    let unique: Vec<String> = (0..20).map(|idx| format!("burst-{idx}")).collect();
    ingest_many(
        &mut mempool,
        peer,
        GossipTopic::WitnessProofs,
        unique.clone(),
    );

    // Re-ingest a sliding window of past payloads after heavy eviction to exercise hit rate.
    for tag in unique.iter().step_by(3).cloned().collect::<Vec<_>>() {
        let payload = make_payload(&tag);
        let _ = mempool.ingest(peer, GossipTopic::WitnessProofs, payload);
    }

    let snapshot = metrics.snapshot();
    assert!(
        snapshot.hits >= 6,
        "duplicates across eviction cycles should still increment hits",
    );
    assert_eq!(
        snapshot.misses, 20,
        "only the first wave of unique payloads should count as misses",
    );
    assert!(
        snapshot.evictions >= 12,
        "stress burst should evict earlier records"
    );
}
