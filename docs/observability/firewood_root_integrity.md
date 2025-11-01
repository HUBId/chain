# Firewood root integrity dashboards

Firewood nodes now emit dedicated metrics whenever the committed trie root or a
snapshot artifact fails validation. Use these panels to surface latent storage
corruption before it propagates to downstream consumers.

## Metrics

- **`firewood.nodestore.root.read_errors`** – counter labelled by `state`
  (`committed` or `immutable`) that increments when the nodestore fails to load
  the root from disk.【F:storage/src/nodestore/mod.rs†L661-L701】 Treat any
  increase as a blocking condition; the trie is no longer trustworthy.
- **`firewood.snapshot.ingest.failures`** – counter labelled by `reason`
  (`missing_proof`, `checksum_mismatch`, `proof_rejected`) that records why a
  snapshot bundle was rejected during ingestion.【F:storage-firewood/src/lifecycle.rs†L18-L37】【F:storage-firewood/src/lifecycle.rs†L238-L276】
- **`firewood.recovery.runs`** – counter labelled by `phase` that tracks the
  recovery drill lifecycle (`start` and `complete`).【F:storage-firewood/src/bin/firewood_recovery.rs†L62-L110】 Pair this with
  **`firewood.recovery.active`**, a gauge that indicates whether a recovery
  workflow is currently running.【F:storage-firewood/src/bin/firewood_recovery.rs†L48-L73】 A non-zero reading outside a drill means
  manual intervention failed to cleanly exit.

## Suggested panels

1. **Root read error timeline** – plot
   `sum by (state)(increase(firewood_nodestore_root_read_errors_total[5m]))` to
   highlight which revision type is failing. Combine with log panels filtered
   for `root read failed` to triage the backing storage quickly.
2. **Snapshot ingest failure heatmap** – use
   `increase(firewood_snapshot_ingest_failures_total[reason][30m])` to contrast
   missing proof files against checksum mismatches. Persistent `proof_rejected`
   spikes usually signal tampered manifests.
3. **Recovery workflow tracker** – overlay
   `increase(firewood_recovery_runs_total{phase="start"}[1h])` and
   `increase(...{phase="complete"}[1h])` alongside the instantaneous gauge
   `firewood_recovery_active`. Divergence between starts and completes or a
   gauge value stuck at `1` indicates a stalled recovery.

## Alert rules

- **Root read failure streak:** fire when
  `increase(firewood_nodestore_root_read_errors_total[10m]) > 0`. Immediate
  paging is recommended because the trie cannot be trusted without successful
  root reads.
- **Snapshot ingestion failing fast:** trigger if
  `increase(firewood_snapshot_ingest_failures_total[reason="checksum_mismatch"][15m]) >= 1`
  or `increase(...{reason="missing_proof"}[15m]) >= 1`. Pair the alert with the
  manifest path logged in the error payload for rapid remediation.【F:storage-firewood/src/lifecycle.rs†L259-L276】
- **Recovery stuck:** alert when `firewood_recovery_active > 0` for more than
  five minutes or when the difference between `start` and `complete` phases of
  `firewood.recovery.runs` grows monotonically. This indicates an operator
  kicked off a drill but the cleanup never completed.
