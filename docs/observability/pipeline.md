# Pipeline Telemetry Dashboards & Alerts

## Overview
The pipeline orchestrator exports OpenTelemetry metrics whenever wallet
submissions progress through the workflow. Each stage—wallet ingress, proof
validation, BFT finality, and Firewood storage—is tagged so dashboards can
separate delays and failure modes per subsystem. The instruments listed below
are emitted as soon as `PipelineStageEvent`s are published by the node hooks
and flow through the OTLP exporter.

## Metric Inventory
| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `rpp.node.pipeline.stage_latency_ms` | Histogram (f64) | `phase` (`wallet`, `proof`, `consensus`, `storage`) | End-to-end latency in milliseconds from bundle ingestion until the stage was first observed. |
| `rpp.node.pipeline.stage_total` | Counter (u64) | `phase` (`wallet`, `proof`, `consensus`, `storage`) | Total number of stage observations. Useful for rate panels and alert ratios. |
| `rpp.node.pipeline.commit_height` | Histogram (u64) | `phase="storage"` | Firewood commit height reported once the storage stage completes. Confirms persistence progress. |

The latency and count instruments apply to every stage; the commit height bucket
is only populated when Firewood commits the block. Metrics share the
`rpp-node.pipeline` meter scope so they can be grouped in Grafana by resource or
scope.

## Dashboard Blueprint
1. **Wallet Intake Heatmap** – plot `stage_latency_ms{phase="wallet"}` as a
   heatmap to highlight bursts of delayed gossip ingestion alongside a rate
   panel for `stage_total{phase="wallet"}`.
2. **Proof Validation Trend** – combine `stage_latency_ms{phase="proof"}` with
   acceptance counters to monitor verifier throughput. Use percentile panels to
   surface sustained latency regressions.
3. **Consensus Finality SLO** – rate panel for
   `stage_total{phase="consensus"}` compared to BFT block production combined
   with a table of recent latency quantiles.
4. **Storage Commit Tracker** – dual-axis panel pairing
   `stage_latency_ms{phase="storage"}` with
   `stage_total{phase="storage"}` and overlaying the latest value from
   `commit_height` to confirm Firewood persistence is keeping up.

Export rendered dashboards to the checked-in Grafana definitions under
`docs/dashboards/`. The repository already contains:

- `pipeline_overview.json`
- `pipeline_wallet_intake.json`
- `pipeline_proof_validation.json`
- `pipeline_consensus_finality.json`
- `pipeline_storage_commit.json`

Each dashboard file can be imported into Grafana via **Dashboards → New → Import**
by uploading the JSON file or pasting its contents. Use the
`docs/observability/pipeline_grafana.json` layout as a reference when creating
bespoke variants or extending panel coverage.

## Alerting Guidance
- **Wallet Intake Stall** – fire when the 5-minute rate of
  `stage_total{phase="wallet"}` drops below the expected submission baseline
  while RPC clients remain connected.
- **Proof Latency Regression** – trigger if the 95th percentile of
  `stage_latency_ms{phase="proof"}` stays above the agreed SLA (e.g. 8 seconds)
  for 15 minutes.
- **Consensus Catch-up Failure** – alert when
  `stage_total{phase="consensus"}` lags block finalisation for more than two
  epochs, indicating VRF leadership or BFT participation issues.
- **Storage Backlog** – raise severity when the derivative of
  `commit_height` flattens while new `stage_total{phase="storage"}` events
  continue to arrive, suggesting Firewood persistence is stuck.

### Runbook Links
Attach this document to observability and startup runbooks so operators can
navigate directly to the recommended dashboards when diagnosing pipeline gaps.
