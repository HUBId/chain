# Telemetry Dashboard Blueprints

The runtime exports OpenTelemetry metrics for nodes, wallets, storage, and proof
pipelines. This document outlines vendor-neutral panels that operators can map
onto Grafana, Chronosphere, Datadog, or similar tools. Metric names are given in
their OTLP form; apply your collector's naming transforms as needed.

## Node and consensus

- **Consensus stage duration heatmap.** Use
  `rpp.runtime.consensus.block_duration{stage=*}` to visualise per-stage latency
  across rounds; bucket by `stage` to highlight where time is spent inside the
  proposer pipeline.【F:rpp/runtime/telemetry/metrics.rs†L104-L132】
- **Round lifecycle timeline.** Pair `rpp.runtime.consensus.round.duration` and
  `rpp.runtime.consensus.round.quorum_latency`, slicing by the `height`/`round`
  attributes to expose slow quorums versus slow block assembly.【F:rpp/runtime/telemetry/metrics.rs†L140-L158】【F:rpp/runtime/telemetry/metrics.rs†L288-L319】
- **Leadership and failure counters.** Plot
  `rpp.runtime.consensus.round.leader_changes` alongside
  `rpp.runtime.consensus.failed_votes{reason=*}` to track instability and vote
  rejection trends.【F:rpp/runtime/telemetry/metrics.rs†L159-L192】
- **Network connectivity.** Trend `rpp.runtime.network.peer_count` as a gauge to
  detect isolation, and layer alerts when the histogram collapses below the
  expected validator quorum.【F:rpp/runtime/telemetry/metrics.rs†L193-L200】
- **Block height parity.** Display the latest samples from
  `rpp.runtime.chain.block_height` versus the canonical height from your indexer
  to catch lagging nodes.【F:rpp/runtime/telemetry/metrics.rs†L193-L200】

## Wallet

- **Wallet RPC latency.** Graph `rpp.runtime.wallet.rpc_latency{method=*}` to see
  which endpoints drive user-facing latency and determine whether spikes are
  method-specific or systemic.【F:rpp/runtime/telemetry/metrics.rs†L115-L123】
- **Wallet RPC throughput.** Overlay `rpp.runtime.rpc.request.total` with the
  matching latency histogram so operators can tie load to response times; use the
  `method` and `result` labels to identify failure hot spots.【F:rpp/runtime/telemetry/metrics.rs†L124-L139】
- **RPC rate limiting.** Plot `sum by (method, status)(rate(rpp.runtime.rpc.rate_limit.total[5m]))`
  to separate throttled requests from healthy traffic per method when tuning
  budgets or investigating abuse spikes.【F:rpp/runtime/telemetry/metrics.rs†L124-L150】
- **Pipeline health.** Complement runtime metrics with the orchestrator
  counters—`pipeline_stage_latency_ms`, `pipeline_errors_total`,
  `pipeline_gossip_events_total`, `pipeline_leader_rotations_total`—to ensure the
  wallet pipeline mirrors node health.【F:rpp/runtime/orchestration.rs†L359-L706】【F:rpp/runtime/orchestration.rs†L747-L940】

## Pipeline orchestrator

Dashboard blueprints for the orchestrator live alongside this guide:

- [`pipeline_overview.json`](./pipeline_overview.json)
- [`pipeline_wallet_intake.json`](./pipeline_wallet_intake.json)
- [`pipeline_proof_validation.json`](./pipeline_proof_validation.json)
- [`pipeline_consensus_finality.json`](./pipeline_consensus_finality.json)
- [`pipeline_storage_commit.json`](./pipeline_storage_commit.json)
- [`compliance_overview.json`](./compliance_overview.json)
- [`snapshot_resilience.json`](./snapshot_resilience.json)

Import them into Grafana via **Dashboards → New → Import**, then upload the JSON
file or paste the contents into the dialog. Assign each dashboard to your
preferred folder and Prometheus datasource (the definitions reference the
default `prometheus` UID, which can be remapped during import).

## VRF selection

Validator operators can import the VRF dashboards described in
[`docs/observability/vrf.md`](../observability/vrf.md):

- [`vrf_overview.json`](./vrf_overview.json)
- [`vrf_thresholds.json`](./vrf_thresholds.json)

Use the same Grafana import flow as above, mapping the dashboards to your
Prometheus datasource or adjusting the datasource UID during import.

## Storage

- **WAL latency and throughput.** Pair
  `rpp.runtime.storage.wal_flush.duration` and
  `rpp.runtime.storage.wal_flush.bytes`, grouped by `outcome`, to spot retries or
  large batches.【F:rpp/runtime/telemetry/metrics.rs†L118-L138】
- **WAL outcome counters.** Alert on sustained growth in
  `rpp.runtime.storage.wal_flush.total{outcome="failed"}` to capture hardware or
  filesystem failures early.【F:rpp/runtime/telemetry/metrics.rs†L138-L147】
- **Header writer tracking.** Track
  `rpp.runtime.storage.header_flush.duration`, `.bytes`, and `.total` together to
  correlate header flush pressure with WAL spikes.【F:rpp/runtime/telemetry/metrics.rs†L147-L157】
- **Reputation penalties.** Display `rpp.runtime.reputation.penalties` to connect
  storage-induced slowness (e.g., missing proofs) with validator scoring.
  Sustained penalties should trigger follow-up investigations.【F:rpp/runtime/telemetry/metrics.rs†L200-L205】

## Proofs

- **Proof generation SLOs.** Chart `rpp.runtime.proof.generation.duration{proof_kind=*}`
  with percentile overlays and correlate with `rpp.runtime.proof.generation.size`
  to understand workload cost per backend.【F:rpp/runtime/telemetry/metrics.rs†L362-L382】
- **Proof issuance volume.** Monitor
  `rpp.runtime.proof.generation.count{proof_kind=*}` to ensure expected proving
  throughput; sudden drops can precede consensus stalls.【F:rpp/runtime/telemetry/metrics.rs†L382-L389】
- **Verification footprint.** Visualise the STARK verification histograms—
  `rpp_stark_verify_duration_seconds`, `rpp_stark_proof_total_bytes`,
  `rpp_stark_params_bytes`, `rpp_stark_public_inputs_bytes`, and
  `rpp_stark_payload_bytes`—to catch regressions in verifier cost.
  Use `proof_backend` to compare STWO byte growth against RPP-STARK artifacts side-by-side.【F:rpp/runtime/telemetry/metrics.rs†L389-L409】【F:rpp/runtime/node.rs†L5513-L5534】
- **Verification stage quality.** Count
  `rpp_stark_stage_checks_total{proof_stage,proof_outcome}` to expose which phases
  fail during verification and whether failures cluster around a specific proof
  kind.【F:rpp/runtime/telemetry/metrics.rs†L389-L413】【F:rpp/runtime/telemetry/metrics.rs†L438-L457】

