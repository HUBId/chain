# Pipeline Telemetry Dashboards & Alerts

## Overview
The pipeline orchestrator exports OpenTelemetry metrics whenever wallet
submissions progress through the workflow. Each stage—wallet ingress, proof
validation, BFT finality, and Firewood storage—is tagged so dashboards can
separate delays and failure modes per subsystem. The instruments listed below
are emitted as soon as `PipelineStageEvent`s are published by the node hooks
and flow through the OTLP exporter. Die gleichen Messreihen stehen – sofern der
Prometheus-Scrape-Endpunkt (`rollout.telemetry.metrics`) aktiviert ist – auch
unter `/metrics` bereit und tragen die Präfixe `pipeline_*` beziehungsweise
`pipeline_gossip_*`.

## Metric Inventory
| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `rpp.node.pipeline.stage_latency_ms` | Histogram (f64) | `phase` (`wallet`, `proof`, `consensus`, `storage`) | End-to-end latency in milliseconds from bundle ingestion until the stage was first observed. |
| `rpp.node.pipeline.stage_total` | Counter (u64) | `phase` (`wallet`, `proof`, `consensus`, `storage`) | Total number of stage observations. Useful for rate panels and alert ratios. |
| `rpp.node.pipeline.commit_height` | Histogram (u64) | `phase="storage"` | Firewood commit height reported once the storage stage completes. Confirms persistence progress. |
| `rpp_node_pipeline_root_io_errors_total` | Counter (u64) | _none_ | Total Firewood root IO errors surfaced by the state-sync verifier. Alerts operators to snapshot corruption or storage outages. |

The latency and count instruments apply to every stage; the commit height bucket
is only populated when Firewood commits the block. Metrics share the
`rpp-node.pipeline` meter scope so they can be grouped in Grafana by resource or
scope.

### Snapshot & Light Client Sync Metrics
Snapshot distribution now exposes dedicated counters and gauges to extend the
pipeline view beyond Firewood. These metrics live alongside the pipeline scope
when Prometheus scraping is enabled:

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `snapshot_bytes_sent_total` | Counter (u64) | `direction` (`outbound`, `inbound`), `kind` (`plan`, `chunk`, `light_client_update`, `resume`, `ack`, `error`) | Captures throughput for producers (outbound) and consumers (inbound). Chunk throughput should rise steadily during light-client syncs. |
| `snapshot_stream_lag_seconds` | Gauge (f64) | _none_ | Maximum observed delay since the last successful chunk/update/ack across active sessions. Healthy streams remain below 30 seconds. |
| `light_client_chunk_failures_total` | Counter (u64) | `direction`, `kind` (`chunk`, `light_client_update`) | Counts failed fetches or decode errors. Any sustained increase indicates unhealthy peers or corrupt artefacts. |

See `docs/observability/network_snapshots.md` for detailed queries, alert
thresholds, and dashboard examples that tie these metrics back into the pipeline
view.

### Sample Grafana Panel

```json
{
  "type": "stat",
  "title": "Firewood Root IO Errors (5m)",
  "targets": [
    {
      "expr": "sum(increase(rpp_node_pipeline_root_io_errors_total[5m]))",
      "legendFormat": "IO errors"
    }
  ],
  "options": {
    "colorMode": "value",
    "graphMode": "none",
    "justifyMode": "auto"
  },
  "thresholds": {
    "mode": "absolute",
    "steps": [
      { "color": "green", "value": null },
      { "color": "red", "value": 1 }
    ]
  }
}
```

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
5. **Snapshot Stream Health** – Panel **#6 _Snapshot Chunk Throughput_** plots
   `rate(snapshot_bytes_sent_total{kind="chunk",direction="outbound"}[5m])`
   alongside the matching inbound rate to compare producer versus consumer
   throughput. Panel **#7 _Snapshot Stream Lag_** surfaces
   `snapshot_stream_lag_seconds` so operators can immediately see when replay
   stalls. Panel **#8 _Light Client Chunk Failures_** highlights
   `increase(light_client_chunk_failures_total{kind="chunk"}[15m])` for both
   directions to call out peers that repeatedly fail chunk delivery.

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
- **Firewood Root IO Errors** – alert when `sum(increase(rpp_node_pipeline_root_io_errors_total[5m]))`
  is greater than zero for more than one scrape interval, signalling a recurring
  snapshot read failure along the state-sync path.
- **Snapshot Stream Lag** – warn when
  `snapshot_stream_lag_seconds > 30` for five minutes and escalate at 120
  seconds. Pair with a throughput check on
  `rate(snapshot_bytes_sent_total{kind="chunk"}[5m])` to reduce noise when no
  sessions are active.
- **Snapshot Failure Spike** – trigger when
  `increase(light_client_chunk_failures_total{kind="chunk",direction="outbound"}[10m])`
  exceeds three or inbound failures rise above one per 10 minutes, indicating
  sustained delivery issues.

### Runbook Links
Attach this document to observability and startup runbooks so operators can
navigate directly to the recommended dashboards when diagnosing pipeline gaps.
Link snapshot operators to
[`docs/observability/network_snapshots.md`](network_snapshots.md) and the
[network snapshot failover runbook](../runbooks/network_snapshot_failover.md)
for stream-specific remediation steps.
