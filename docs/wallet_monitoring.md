# Wallet monitoring guide

This reference maps the wallet runtime’s emitted telemetry to the dashboards and
alerts operators rely on during deployment rollouts. Use it as the canonical
hand-off from engineering to on-call teams so Phase 4 features (backup flows,
RBAC, GUI workflows, hardware signing, etc.) remain observable.

## Metric-to-dashboard mapping

| Signal | Metric(s) | Recommended dashboards | Alerting guidance |
| --- | --- | --- | --- |
| **Sync progress & driver health** | `rpp.runtime.wallet.sync.active`, `rpp.runtime.wallet.runtime.active` | Pipeline Wallet Intake / Overview dashboards capture sync/resume stages alongside runtime liveness.【F:rpp/runtime/telemetry/metrics.rs†L69-L176】【F:docs/performance_dashboards.json†L1-L26】 | Alert when the sync histogram remains `0` while runtime activity stays `1` for >10 m (stalled resume) or when both drop simultaneously (process crash). |
| **Chain height, lag, and last sync success** | `rpp.runtime.wallet.sync.height`, `rpp.runtime.wallet.sync.lag_blocks`, `rpp.runtime.wallet.sync.last_success_timestamp_seconds` | Wallet Intake dashboards surface the live height (`wallet_synced_height`), chain tip (`wallet_chain_tip`), and calculated lag (`wallet_sync_lag`) from readiness probes next to the Prometheus metrics so responders can compare probes vs. scrapes in one view.【F:docs/performance_dashboards.json†L1-L26】 | Fire a **lag alert** when average lag stays above 20 blocks for >5 m or when `time() - last_success` exceeds 10 m. When triggered, verify whether the probe height matches Prometheus and inspect gossip reachability before restarting—treat probe-metric divergence as a telemetry issue, not a crash. |
| **Fee estimator latency & congestion** | `rpp.runtime.wallet.fee.estimate.latency_ms`, `rpp.runtime.wallet.action.total{action="wallet.fee"…}` | Pipeline Proof Validation dashboard overlays fee quote timing with mempool load so reviewers can compare estimators with chain data.【F:rpp/runtime/telemetry/metrics.rs†L69-L176】【F:docs/performance_dashboards.json†L9-L19】 | Threshold when p95 latency exceeds 3 s for 5 m or when error-labelled fee actions spike over baseline. |
| **Prover runtimes** | `rpp.runtime.wallet.prover.job.duration_ms`, `rpp.runtime.wallet.broadcast.rejected{reason="prover"}` | Proof Validation dashboard highlights job durations per backend and correlates with rejection reasons to spot ZK bottlenecks.【F:rpp/runtime/telemetry/metrics.rs†L69-L164】【F:docs/performance_dashboards.json†L12-L22】 | Alert when p99 job duration doubles past the documented timeout (default 300 s from `wallet.prover.timeout_secs`) twice within 30 m or when broadcast denials with `reason="witness"` increase consecutively.【F:config/wallet.toml†L142-L152】 |
| **Signer latency & failures** | `rpp.runtime.wallet.sign.latency_ms{mode,account_type,backend,result}`, `rpp.runtime.wallet.sign.failures{mode,account_type,backend,code}` | Pipeline Wallet Intake panels “Signer latency (p95)” and “Signer failure rate” break down online vs. offline signing paths.【F:docs/dashboards/pipeline_wallet_intake.json†L1-L120】 | Warn when p95 online signing latency stays above 3 s for 5 m and page when signing failures exceed 3 in 5 m; alert rules live in `docs/observability/alerts/wallet_signer.yaml`. |
| **Backup / watch-only / hardware action counters** | `rpp.runtime.wallet.action.total` (OpenTelemetry) and CLI/UI counters (`cli.action.events`, `ui.send.steps`, `ui.rescan.triggered`, etc.).【F:rpp/runtime/telemetry/metrics.rs†L69-L164】【F:rpp/wallet/src/telemetry/mod.rs†L1-L62】【F:rpp/wallet/src/ui/telemetry.rs†L52-L173】 | Wallet Intake dashboard adds panels for backup/export attempts so ops can see backup cadence next to sync states.【F:docs/performance_dashboards.json†L9-L15】 | Alert when error-labelled counters (e.g., `backup.export.err`, `watch_only.enable.err`) increase more than twice within 30 m or when CLI counters expose repeated hardware fallbacks (`operation="hw.sign", outcome="err"`). |
| **RBAC & audit denials** | `rpp.runtime.wallet.action.total` with `result="error"`, RPC latency spikes, plus rotating audit logs under `wallet/audit`.【F:rpp/runtime/telemetry/metrics.rs†L69-L164】【F:rpp/runtime/wallet/rpc/audit.rs†L1-L82】 | Observability + security dashboards overlay audit volume, RBAC denials, and latency so on-call staff can pair errors with log segments.【F:docs/performance_dashboards.json†L1-L26】 | Alert when RBAC-denied actions exceed 5/min or when audit append warnings appear without matching telemetry (indicates disk or retention failure). |

## Sample alert rules

These expressions work in Prometheus-compatible systems. Adjust labels or OTLP
selectors to match your scrape pipeline.

## Finality awareness via wallet APIs

- The wallet account response now embeds `finality.last_finalized_height` and
  `finality.finality_lag_blocks` so operators can see how far each account lags
  behind the latest committed block when finality slows down.【F:rpp/wallet/ui/wallet.rs†L491-L514】
- The node tab contract (`/wallet/ui/node`) mirrors the aggregated pipeline
  finality snapshot under `metrics.pipeline_finality`, giving UI clients the
  same view that Grafana panels use to correlate API-reported lag with
  Prometheus series on the Pipeline Consensus Finality dashboard.【F:rpp/wallet/ui/tabs/node.rs†L8-L25】【F:docs/dashboards/pipeline_consensus_finality.json†L72-L112】

```promql
# Stalled sync driver
(avg_over_time(rpp_runtime_wallet_sync_active[5m]) < 0.5)
  and (max_over_time(rpp_runtime_wallet_runtime_active[5m]) > 0.5)
```

```promql
# Wallet height lags chain tip by N blocks for M minutes
avg_over_time(rpp_runtime_wallet_sync_lag_blocks[5m]) > 20
```

```promql
# Last successful sync older than threshold (in seconds)
(time() - max_over_time(rpp_runtime_wallet_sync_last_success_timestamp_seconds[5m])) > 600
```

```promql
# Broadcast rejections after policy/prover checks
increase(rpp_runtime_wallet_broadcast_rejected{reason!="ok"}[10m]) > 3
```

```promql
# Prover timeout / saturation
histogram_quantile(0.99,
  rate(rpp_runtime_wallet_prover_job_duration_ms_bucket[15m])) > 280000
```

```promql
# RBAC denials or client auth drift
increase(rpp_runtime_wallet_action_total{result="error", action=~"security.*|wallet.rpc"}[5m]) > 5
```

Combine alert definitions with existing dashboard annotations so incidents link
back to the correct panels in Grafana (`pipeline-wallet-intake`,
`pipeline-proof-validation`, etc.).【F:docs/performance_dashboards.json†L1-L26】

## Regional RPC failover metrics

- **Nightly coverage** – The `simnet-wallet-rpc-failover` workflow exercises
  regional partitions, backend restarts, and wallet RPC bursts so dashboards
  capture latency and uptime regressions before production. The run publishes
  summaries and alert probe artifacts under
  `artifacts/simnet/wallet-rpc-failover-<feature-matrix>/` for review.【F:.github/workflows/nightly.yml†L121-L176】
- **Latency and uptime panels** – Track `rpp.runtime.wallet.rpc.latency_ms` by
  method and the `rpp.runtime.wallet.uptime_*` counters from the scheduler and
  proof submission pipelines to confirm failover does not stall proofs or RPC
  responsiveness.【F:rpp/runtime/telemetry/metrics.rs†L69-L188】【F:rpp/runtime/telemetry/metrics.rs†L524-L530】
- **Alert validation** – Use `python3 tools/alerts/validate_alerts.py --artifacts
  <dir>` against the simnet artifacts to confirm wallet latency and uptime alerts
  fire/clear with the same thresholds wired in production dashboards before
  promoting the change.【F:tools/alerts/validate_alerts.py†L1-L77】

## Signer latency and failures

The `wallet_signer` alert manifest covers spikes in signing latency and failures
for both online and offline paths. The Pipeline Wallet Intake dashboard now
includes signer panels that surface the `mode`, `account_type`, and `backend`
labels so responders can quickly see whether a hot account or hardware signer
is slowing down.【F:docs/observability/alerts/wallet_signer.yaml†L1-L40】【F:docs/dashboards/pipeline_wallet_intake.json†L1-L120】

When alerts fire:

1. Check the signer latency panel for the affected mode and backend.
2. Inspect the failure panel to grab the error code (e.g., `HW_REJECTED` vs.
   `PROVER_TIMEOUT`) and backend identity.
3. For hardware accounts, confirm the device is reachable and unlocked; for hot
   accounts, review prover saturation and node connectivity before retrying.

## Log correlation and incident triage

1. **Runtime logs** – `scripts/run_wallet_mode.sh` wraps `rpp-node wallet` and
   streams readiness probes (`/health/live` and `/health/ready`) plus log level
   overrides via `RPP_WALLET_LOG_LEVEL`. Use it to confirm whether a stalled
   metric corresponds to an actual process restart or probe failure.【F:scripts/run_wallet_mode.sh†L1-L57】
2. **Audit logs** – Enabling `[wallet.audit]` provisions rotating JSONL files in
   `wallet/audit/`, recording timestamp, RPC method, identity, role set, and
   result code for every call. Segments rotate after either
   `wallet.audit.rotation_seconds` (default 24h) or
   `wallet.audit.max_segment_bytes` (default 16MiB); retention prunes segments
   past `wallet.audit.retention_days` and trims oldest files when
   `wallet.audit.retention_bytes` (default 512MiB) is exceeded, writing a
   `wallet-audit.anchor` checkpoint so the SHA-256 hash chain remains
   verifiable across rotations.【F:rpp/runtime/wallet/rpc/audit.rs†L17-L365】
   Correlate RBAC alert spikes with these records to distinguish legitimate
   denials from misconfigurations.【F:rpp/runtime/wallet/rpc/audit.rs†L17-L365】
3. **Action telemetry** – CLI and GUI flows expose opt-in counters (e.g.,
   `cli.action.events`, `ui.send.steps`, `ui.rpc.latency_ms`). When alerting on
   wallet action anomalies, include the counter snapshot from the GUI/CLI so the
   audit trail ties to a specific user action and RPC ID.【F:rpp/wallet/src/cli/telemetry.rs†L32-L109】【F:rpp/wallet/src/ui/telemetry.rs†L52-L173】

During incidents, start with the metric-based alert, pull the matching Grafana
panel, then pivot into runtime/audit logs. Recording that correlation in the
runbook ticket ensures future deployments reuse the same investigation trail.
