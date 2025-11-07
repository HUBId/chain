# Snapshot Stream Observability

Phase 3 introduces dedicated telemetry for snapshot producers and
light-client consumers so operators can reason about sync progress without
parsing debug logs. The metrics are emitted through both OTLP and the optional
Prometheus scrape endpoint (`rollout.telemetry.metrics.listen`). They share the
`snapshot` prefix and are available on every validator once the snapshot
feature gate is enabled.

## Metric Inventory
| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `snapshot_bytes_sent_total` | Counter (u64) | `direction` (`outbound`, `inbound`), `kind` (`plan`, `chunk`, `light_client_update`, `resume`, `ack`, `error`) | Total bytes transferred per snapshot artefact and direction. Outbound values represent producer traffic, inbound values track consumer throughput. |
| `snapshot_stream_lag_seconds` | Gauge (f64) | _none_ | Maximum wall-clock delay since the last successful chunk, update, or acknowledgement across all active sessions. Values close to zero indicate the stream is progressing. |
| `light_client_chunk_failures_total` | Counter (u64) | `direction`, `kind` (`chunk`, `light_client_update`) | Count of failed fetches, serialisation, or decode operations for chunks and light-client updates. A sustained increase requires investigation. |

All metrics reset when a node restarts. The counter cardinality is limited to a
small number of enumerated labels, making them safe to record at 10s scrape
intervals.

## Recommended Dashboards
1. **Snapshot Throughput (Bytes/min)** – PromQL:
   ```promql
   sum by(kind, direction)(rate(snapshot_bytes_sent_total[5m]))
   ```
   Plot as a stacked area chart. Expect sustained outbound chunk throughput on
   providers and inbound throughput on syncing validators.
2. **Stream Lag Gauge** – Use a single-stat panel on
   `snapshot_stream_lag_seconds`. Configure thresholds at 30s (warning) and
   120s (critical). Values above the warning threshold indicate stalled
   consumers or saturated producers.
3. **Failure Rate Table** – PromQL:
   ```promql
   sum by(direction, kind)(increase(light_client_chunk_failures_total[15m]))
   ```
   Display as a table sorted by the largest increase to highlight peers that
   repeatedly fail chunk delivery.
4. **Correlation with Pipeline** – Overlay
   `rate(snapshot_bytes_sent_total{kind="chunk",direction="outbound"}[5m])`
   against pipeline stage latency (`rpp.node.pipeline.stage_latency_ms`) to
   quickly spot whether pipeline stalls coincide with snapshot slowdowns.

## Alerting Suggestions
- **Snapshot Lag Warning** – Alert when
  `snapshot_stream_lag_seconds > 30` for longer than 5 minutes. Escalate to
  critical at 120 seconds.
- **Chunk Failure Surge** – Fire when
  `increase(light_client_chunk_failures_total{direction="outbound",kind="chunk"}[10m])`
  exceeds 3. On consumers, alert when inbound failures exceed 1 in 10 minutes,
  signalling persistent decode problems.
- **Zero Throughput** – Trigger a warning if both outbound and inbound rates of
  `snapshot_bytes_sent_total{kind="chunk"}` fall to zero while a session
  remains active (check `/p2p/snapshots` RPC). Combine with stream lag alerts to
  reduce noise during idle periods.

## Operational Checklist
- Confirm metrics availability with the integration test
  `tests/network/snapshots.rs`, which establishes a producer/consumer pair,
  scrapes `/metrics`, and asserts non-zero throughput.
- Tie alerts back to the runbook steps in the
  [network snapshot failover runbook](../runbooks/network_snapshot_failover.md)
  so on-call engineers can restart stalled streams and replay missing chunks.
- Surface the gauges on the pipeline overview dashboard (see
  `docs/observability/pipeline.md`) to provide an end-to-end picture from wallet
  intake through snapshot distribution.
