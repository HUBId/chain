# Firewood storage monitoring

Firewood exposes dedicated metrics through the runtime and storage crates so operators can
track write-ahead-log (WAL) health, snapshot ingestion, and recovery workflows. The
following signals map the emitted telemetry to recommended alert thresholds. When a
threshold references Prometheus syntax the metric name reflects the exported form (dots
converted to underscores).

| Metric | Source | Recommended alerting thresholds | Notes |
| --- | --- | --- | --- |
| `firewood_nodestore_unwritten_nodes` (gauge) | Tracks nodes queued for persistence and decrements as commits flush, mirroring the WAL queue depth.【F:storage/src/nodestore/mod.rs†L468-L498】【F:storage/src/nodestore/persist.rs†L348-L470】 | • **Warning:** queue depth > 1 000 for 10 m<br>• **Critical:** queue depth > 5 000 for 5 m (mirrors the Grafana panel thresholds used by benchmarking rigs).【F:benchmark/Grafana-dashboard.json†L930-L948】 | Spikes indicate back-pressure between Firewood commits and disk. Verify disk latency and the IO budget gauges before throttling intake. |
| `firewood_db_requests_total{operation="commit",result="failure"}` (counter) | Emitted whenever the database rejects a commit because the proposal is stale or persistence fails.【F:firewood/src/db.rs†L120-L149】【F:firewood/src/db.rs†L370-L405】 | Page on any non-zero increase over 5 m—commit failures leave validators with divergent state. | Correlate with `firewood_db_requests_total{operation="commit",result="success"}` to confirm recoveries and inspect WAL metrics for root-cause analysis. |
| `firewood_db_request_latency{operation="commit",result="success"}` (histogram) | Measures latency for Firewood proposal commits; emitted alongside counts for propose/commit/revision success and failure paths.【F:firewood/src/db.rs†L69-L107】【F:firewood/src/db.rs†L205-L249】【F:firewood/src/db.rs†L370-L405】 | Alert if the p95 latency exceeds 1 s for 10 m—sustained slow commits stall block production. | Pair with `firewood_db_request_latency{operation="propose",result="success"}` to see whether slowdowns originate in proposal construction or disk flushes. |
| `rpp_runtime_storage_wal_flush_total{outcome="failed"}` (counter) | Runtime telemetry tracks WAL flush attempts per outcome.【F:rpp/runtime/telemetry/metrics.rs†L74-L114】 | Page immediately when `increase(...[5m]) > 0`. Treat any failure as a critical write-path fault and inspect logs for matching errors. | Correlate with `...{outcome="retried"}` to distinguish transient retries from permanent failures; repeated retries for 15 m should raise a warning. |
| `firewood_wal_transactions_total{result="rolled_back"}` (counter) | WAL replay increments the counter when incomplete transactions are discarded during recovery.【F:storage-firewood/src/kv.rs†L120-L165】 | Alert if `increase(...[15m]) > 0`. Rolled back transactions point to WAL corruption or abrupt shutdowns. | A sustained increase warrants invoking `firewood_recovery` to rebuild the log before resuming peers. |
| `firewood_snapshot_ingest_failures_total{reason}` (counter) | Snapshot ingestion records failures for missing proofs, checksum mismatches, or rejected manifests.【F:storage-firewood/src/lifecycle.rs†L14-L248】 | Page on any non-zero increase over 15 m. Investigate by reviewing the recorded reason and snapshot manifest referenced in logs. | Combine with `firewood_nodestore_root_read_errors_total` to confirm persistent storage corruption. |
| `firewood_nodestore_root_read_errors_total{state}` (counter) | Logged when Firewood fails to read committed or immutable roots from storage.【F:storage/src/nodestore/mod.rs†L687-L719】 | Warn when `sum by (state)(increase(...[5m])) > 0` and escalate if the trend persists for 30 m. | Signals read-path corruption; pause ingestion and audit the underlying block device. |
| `firewood_checker_leaked_ranges` (gauge) | Checker reports the number of leaked storage ranges encountered during validation.【F:storage/src/checker/mod.rs†L221-L237】 | Page when the gauge is non-zero after a maintenance run; leaked ranges should drop to zero immediately after repair. | Run `check_and_fix` and monitor the paired fix/failure counters to confirm reclamation progress. |
| `firewood_checker_leaked_areas_fixed` / `firewood_checker_leaked_areas_failed_to_fix` (counters) | Count leaked areas successfully re-enqueued into free lists and failures encountered during repair, respectively.【F:storage/src/checker/mod.rs†L641-L681】 | • **Warning:** `increase(..._failed_to_fix[5m]) > 0`<br>• **Critical:** `increase(..._failed_to_fix[15m]) >= 3` or `rate(..._fixed[5m]) == 0` while leaks persist. | Use alongside `firewood_checker_leaked_ranges` to validate that checker runs drain leaks; sustained failures require manual free-list reconstruction. |
| `firewood_recovery_active` (gauge) & `firewood_recovery_runs_total{phase}` (counter) | The recovery drill marks workflows active and increments start/complete phases around WAL rebuilds.【F:storage-firewood/src/bin/firewood_recovery.rs†L62-L171】 | • Warn when `firewood_recovery_active > 0` for 15 m.<br>• Page if starts minus completes within 30 m is > 0, indicating a stalled recovery. | Should return to zero once recovery completes; investigate logs and rerun the drill if it remains stuck. |
| `snapshot_stream_lag_seconds` (gauge) | Snapshot behaviour exports stream lag via libp2p metrics registration.【F:rpp/p2p/src/behaviour/snapshots.rs†L462-L499】 | • **Warning:** lag > 30 s for 5 m.<br>• **Critical:** lag > 120 s for 2 m, matching the documented pipeline SLOs.【F:docs/observability/pipeline.md†L32-L44】 | When triggered, follow the network snapshot failover runbook to re-route consumers. |

Pair these thresholds with the sample Alertmanager rules under `ops/alerts/storage/` and the
observability runbook sections referenced below. Alert annotations should link to the relevant
runbook anchors (`docs/runbooks/observability.md`).

## Updating the telemetry schema

The storage metrics surfaced here are validated in CI against `telemetry/schema.yaml`. When adding a
new counter, histogram, or gauge:

1. Append the metric name and any labels it emits to `telemetry/schema.yaml`.
2. Run `cargo test --test observability_metrics telemetry_metrics_match_allowlist -- --nocapture`
   to confirm the allowlist covers the updated label set.
3. Commit the schema change alongside the instrumentation patch so downstream pipelines can ingest
   the new timeseries without breaking the schema gate.
