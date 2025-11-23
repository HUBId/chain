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
| `snapshot_negotiated_chunk_size_bytes` | Gauge (u64) | `role` (`provider`, `consumer`) | Last chunk size selected after negotiating capabilities and explicit bounds. Providers emit the size they apply to responses; consumers emit the size advertised by the peer. |
| `snapshot_negotiated_chunk_size_bytes_histogram` | Histogram (u64) | _none_ | Distribution of negotiated chunk sizes in bytes to spot skew across peers or sessions. |
| `snapshot_adaptive_chunk_size_bytes` | Gauge (u64) | _none_ | Most recent adaptive chunk size calculated by the requester based on observed throughput and RTT. |
| `snapshot_adaptive_chunk_size_bytes_histogram` | Histogram (u64) | _none_ | Distribution of adaptive chunk sizes selected over time, useful for catching oscillation or stagnation. |
| `snapshot_stream_lag_seconds` | Gauge (f64) | _none_ | Maximum wall-clock delay since the last successful chunk, update, or acknowledgement across all active sessions. Values close to zero indicate the stream is progressing. |
| `snapshot_chunk_send_queue_depth` | Gauge (u64) | _none_ | Current number of chunk responses buffered by the provider because the consumer cannot accept them yet. Rising depth signals backpressure or stalled consumers. |
| `snapshot_chunk_send_latency_seconds` | Histogram (f64) | _none_ | Time to flush a chunk response to the consumer. Captures transport- and consumer-side backpressure; sustained elevation indicates slow receivers. |
| `light_client_chunk_failures_total` | Counter (u64) | `direction`, `kind` (`chunk`, `light_client_update`) | Count of failed fetches, serialisation, or decode operations for chunks and light-client updates. A sustained increase requires investigation. |
| `snapshot_provider_circuit_open` | Gauge (u64) | _none_ | `1` when the snapshot provider circuit breaker is open after repeated errors (for example, manifest mismatch or authentication failures), `0` otherwise. |
| `snapshot_provider_consecutive_failures` | Gauge (u64) | _none_ | Number of consecutive snapshot serving failures tracked by the circuit breaker. Resets to zero after a successful response or manual reset. |

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
3. **Chunk Backpressure Panel** – Plot
   `max_over_time(snapshot_chunk_send_queue_depth[5m])` as a gauge with warning
   at 10 buffered chunks and critical at 25. Pair with
   `rate(snapshot_chunk_send_latency_seconds_sum[5m]) / rate(snapshot_chunk_send_latency_seconds_count[5m])`
   to visualise average flush latency; keep it below ~2s during healthy syncs.
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
The Prometheus rules in
[`docs/observability/alerts/snapshot_stream.yaml`](alerts/snapshot_stream.yaml)
codify the following defaults, routing warnings to the telemetry channel and
critical pages to the snapshot on-call rotation:

- **Snapshot Lag Warning** – Alert when
  `snapshot_stream_lag_seconds > 30` for longer than 5 minutes. Escalate to
  critical at 120 seconds (2 minute hold time).
- **Chunk Send Backpressure** – Warn when
  `max_over_time(snapshot_chunk_send_queue_depth[5m])` exceeds 10, signalling
  that the consumer is not draining chunk responses quickly. Page once the
  5-minute max crosses 25 to avoid exhausting buffers.
- **Chunk Send Latency** – Warn when the 5-minute average
  `snapshot_chunk_send_latency_seconds` tops 2 seconds. Page at 8 seconds to
  catch receivers that are persistently throttling or misbehaving.
- **Chunk Failure Surge** – Fire when
  `increase(light_client_chunk_failures_total{direction="outbound",kind="chunk"}[10m])`
  exceeds 3. On consumers, alert when inbound failures exceed 1 in 10 minutes,
  signalling persistent decode problems. Critical pages trigger once outbound
  failures pass 6 or inbound failures pass 3 within the same 10 minute window.
- **Zero Throughput** – Trigger a warning if both outbound and inbound rates of
  `snapshot_bytes_sent_total{kind="chunk"}` fall to zero while a session
  remains active (check `/p2p/snapshots` RPC). Combine with stream lag alerts to
  reduce noise during idle periods. Page when the stall persists for 20 minutes
  despite recent activity.

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
- Watch the circuit breaker gauges when inbound requests fail repeatedly.
  `snapshot_provider_circuit_open` flips to `1` once three consecutive failures
  occur; the companion health endpoint (`/health` and `/health/ready`) surfaces
  the same status under the `snapshot_breaker` field. When the circuit is open
  all inbound snapshot requests receive an error until it is manually reset via
  `POST /p2p/snapshots/breaker/reset`.
