# Observability Incident Runbook

This runbook captures the common telemetry-driven investigations that operators
encounter during chain operations. Each scenario links symptoms to the
telemetry signals emitted by the runtime and prescribes the checks and
mitigations that restore healthy pipelines.

## Telemetry exporter drops

**Symptoms.** Dashboards and traces stall, and the node logs warnings from the
`telemetry` target indicating that the OTLP exporter is disabled or dropping
items.【F:rpp/runtime/telemetry/metrics.rs†L41-L48】

**Checks.**

1. Inspect the rollout status snapshot (RPC `/status/rollout`) to confirm that
   `rollout.telemetry.enabled` and the configured endpoint match expectations;
   the node tracks the effective telemetry flag and endpoint in its runtime
   status.【F:rpp/runtime/node.rs†L3932-L3943】
2. Verify the deployment configuration—`rollout.telemetry.endpoint`,
   `http_endpoint`, authentication token, and TLS files—in `node.toml` or the
   runtime profile. Empty or scheme-less URLs are rejected during validation and
   will prevent the exporter from initialising.【F:config/node.toml†L43-L54】【F:rpp/runtime/config.rs†L1740-L1787】
3. Audit overrides applied at launch: the CLI flags `--telemetry-endpoint`,
   `--telemetry-auth-token`, and `--telemetry-sample-interval` replace the file
   configuration when present, and the `RPP_NODE_OTLP_*` environment variables
   override both at runtime.【F:rpp/node/src/lib.rs†L163-L207】【F:rpp/node/src/lib.rs†L1567-L1588】
4. If the exporter initialised but is throttled, check whether the bounded
   queue is undersized (`trace_max_queue_size`/`trace_max_export_batch_size`) or
   the timeout/retry knobs are too small for the collector; these values govern
   the OpenTelemetry batcher and will emit drop warnings when saturation
   occurs.【F:rpp/runtime/config.rs†L1736-L1775】【F:rpp/runtime/telemetry/exporter.rs†L90-L98】

**Mitigations.**

- Provide both OTLP HTTP and gRPC endpoints when enabling metrics and tracing;
  a missing HTTP endpoint forces the runtime into log-only mode and must be
  corrected before metrics resume flowing.【F:rpp/runtime/telemetry/metrics.rs†L41-L48】
- Increase `trace_max_queue_size` (and optionally the batch size) to absorb
  bursts from block production. Retain `warn_on_drop = true` so further
  saturation is surfaced promptly.【F:rpp/runtime/config.rs†L1736-L1775】【F:rpp/runtime/telemetry/metrics.rs†L41-L48】
- Use `scripts/smoke_otlp_export.sh --mode <profile>` to validate the corrected
  configuration against a local collector before redeploying the node.【F:scripts/smoke_otlp_export.sh†L1-L190】

## Stalled block production

**Symptoms.** Consensus dashboards show elongated round durations, elevated
quorum latency, or repeated leader changes, and `rpp.runtime.consensus.*`
metrics plateau at a fixed height/round.【F:rpp/runtime/telemetry/metrics.rs†L104-L161】【F:rpp/runtime/node.rs†L4000-L4017】

**Checks.**

1. Confirm whether the runtime is still assembling blocks by watching
   `rpp.runtime.consensus.round.duration` and
   `rpp.runtime.consensus.round.quorum_latency`; sudden spikes signal quorum
   formation issues. Pair the histogram deltas with the per-round attributes to
   identify the affected height/round tuple.【F:rpp/runtime/telemetry/metrics.rs†L140-L158】【F:rpp/runtime/telemetry/metrics.rs†L288-L319】
2. Inspect `rpp.runtime.consensus.round.leader_changes` and
   `rpp.runtime.consensus.failed_votes` for the stalled round to determine
   whether repeated reproposals or invalid votes are blocking progress. The
   telemetry snapshot surfaced by `/status/consensus` mirrors these counters for
   ad-hoc debugging.【F:rpp/runtime/telemetry/metrics.rs†L159-L192】【F:rpp/runtime/node.rs†L3996-L4017】
3. Compare the current `chain.block_height` histogram samples with the tip
   reported over RPC; divergences indicate the node has fallen behind peers and
   is no longer importing remote blocks.【F:rpp/runtime/telemetry/metrics.rs†L193-L200】
4. Check mempool health via `/status/mempool` to ensure queues are draining;
   saturation can delay proposal assembly even when consensus signals are still
   firing.【F:rpp/runtime/node.rs†L2140-L2230】

**Mitigations.**

- Restart the validator in hybrid/validator mode if the consensus worker has
  crashed; the runtime exposes combined node+wallet telemetry in these profiles
  so stalled rounds remain observable after restart.【F:rpp/runtime/mod.rs†L8-L56】
- For quorum instability, widen gossip rate limits or peer counts so votes and
  proofs propagate faster; adjustments are applied via `p2p.gossip_rate_limit_per_sec`
  and the peer store configuration.【F:config/node.toml†L25-L35】【F:rpp/runtime/node.rs†L4723-L4785】
- If the node is simply behind, trigger a resync or snapshot restore to catch up
  before rejoining consensus.

## WAL slowdowns or backpressure

**Symptoms.** Storage dashboards record rising
`rpp.runtime.storage.wal_flush.duration` latencies, increasing flush batch sizes,
or a surge in `wal_flush.total{outcome="retried"|"failed"}` samples. Header flush
metrics often trail with similar spikes.【F:rpp/runtime/telemetry/metrics.rs†L118-L157】

**Checks.**

1. Break down the WAL counters by `outcome` to determine whether retries or
   permanent failures dominate; the runtime maps storage-layer results into the
   OTLP labels `success`, `retried`, and `failed`.【F:rpp/runtime/telemetry/metrics.rs†L720-L749】
2. Correlate WAL duration and bytes histograms to see whether large batches or
   slow disks are responsible. Compare with `header_flush.duration/bytes/total`
   to isolate header writer contention.【F:rpp/runtime/telemetry/metrics.rs†L118-L147】
3. Inspect proof generation metrics—large proofs can hold the WAL open—by
   watching `rpp.runtime.proof.generation.duration` and
   `rpp.runtime.proof.generation.size` for concurrent spikes.【F:rpp/runtime/telemetry/metrics.rs†L362-L389】
4. Verify that the storage subsystem still reports healthy status via
   `/status/storage` (if enabled) and that disk quotas were not exceeded at the
   platform layer.

**Mitigations.**

- Increase I/O headroom or retune the WAL sync cadence; persistent `failed`
  outcomes require operator intervention before data loss occurs.
- If retries dominate, raise the collector-side write throughput or reduce
  block size so flush batches shrink; monitoring proof metrics in parallel helps
  confirm whether heavy proving workloads are contributing to WAL pressure.【F:rpp/runtime/telemetry/metrics.rs†L362-L389】
- After mitigation, continue to watch the WAL histograms to ensure the latency
  and outcome distributions return to their normal baseline.

