# Wallet monitoring guide

This reference maps the wallet runtime’s emitted telemetry to the dashboards and
alerts operators rely on during deployment rollouts. Use it as the canonical
hand-off from engineering to on-call teams so Phase 4 features (backup flows,
RBAC, GUI workflows, hardware signing, etc.) remain observable.

## Metric-to-dashboard mapping

| Signal | Metric(s) | Recommended dashboards | Alerting guidance |
| --- | --- | --- | --- |
| **Sync progress & driver health** | `rpp.runtime.wallet.sync.active`, `rpp.runtime.wallet.runtime.active` | Pipeline Wallet Intake / Overview dashboards capture sync/resume stages alongside runtime liveness.【F:rpp/runtime/telemetry/metrics.rs†L69-L176】【F:docs/performance_dashboards.json†L1-L26】 | Alert when the sync histogram remains `0` while runtime activity stays `1` for >10 m (stalled resume) or when both drop simultaneously (process crash). |
| **Fee estimator latency & congestion** | `rpp.runtime.wallet.fee.estimate.latency_ms`, `rpp.runtime.wallet.action.total{action="wallet.fee"…}` | Pipeline Proof Validation dashboard overlays fee quote timing with mempool load so reviewers can compare estimators with chain data.【F:rpp/runtime/telemetry/metrics.rs†L69-L176】【F:docs/performance_dashboards.json†L9-L19】 | Threshold when p95 latency exceeds 3 s for 5 m or when error-labelled fee actions spike over baseline. |
| **Prover runtimes** | `rpp.runtime.wallet.prover.job.duration_ms`, `rpp.runtime.wallet.broadcast.rejected{reason="prover"}` | Proof Validation dashboard highlights job durations per backend and correlates with rejection reasons to spot ZK bottlenecks.【F:rpp/runtime/telemetry/metrics.rs†L69-L164】【F:docs/performance_dashboards.json†L12-L22】 | Alert when p99 job duration doubles past the documented timeout (default 300 s) twice within 30 m or when broadcast denials with `reason="witness"` increase consecutively. |
| **Backup / watch-only / hardware action counters** | `rpp.runtime.wallet.action.total` (OpenTelemetry) and CLI/UI counters (`cli.action.events`, `ui.send.steps`, `ui.rescan.triggered`, etc.).【F:rpp/runtime/telemetry/metrics.rs†L69-L164】【F:rpp/wallet/src/telemetry/mod.rs†L1-L62】【F:rpp/wallet/src/ui/telemetry.rs†L52-L173】 | Wallet Intake dashboard adds panels for backup/export attempts so ops can see backup cadence next to sync states.【F:docs/performance_dashboards.json†L9-L15】 | Alert when error-labelled counters (e.g., `backup.export.err`, `watch_only.enable.err`) increase more than twice within 30 m or when CLI counters expose repeated hardware fallbacks (`operation="hw.sign", outcome="err"`). |
| **RBAC & audit denials** | `rpp.runtime.wallet.action.total` with `result="error"`, RPC latency spikes, plus rotating audit logs under `wallet/audit`.【F:rpp/runtime/telemetry/metrics.rs†L69-L164】【F:rpp/runtime/wallet/rpc/audit.rs†L1-L82】 | Observability + security dashboards overlay audit volume, RBAC denials, and latency so on-call staff can pair errors with log segments.【F:docs/performance_dashboards.json†L1-L26】 | Alert when RBAC-denied actions exceed 5/min or when audit append warnings appear without matching telemetry (indicates disk or retention failure). |

## Sample alert rules

These expressions work in Prometheus-compatible systems. Adjust labels or OTLP
selectors to match your scrape pipeline.

```promql
# Stalled sync driver
(avg_over_time(rpp_runtime_wallet_sync_active[5m]) < 0.5)
  and (max_over_time(rpp_runtime_wallet_runtime_active[5m]) > 0.5)
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

## Log correlation and incident triage

1. **Runtime logs** – `scripts/run_wallet_mode.sh` wraps `rpp-node wallet` and
   streams readiness probes (`/health/live` and `/health/ready`) plus log level
   overrides via `RPP_WALLET_LOG_LEVEL`. Use it to confirm whether a stalled
   metric corresponds to an actual process restart or probe failure.【F:scripts/run_wallet_mode.sh†L1-L57】
2. **Audit logs** – Enabling `[wallet.audit]` provisions rotating JSONL files in
   `wallet/audit/`, recording timestamp, RPC method, identity, role set, and
   result code for every call. Correlate RBAC alert spikes with these records to
   distinguish legitimate denials from misconfigurations.【F:rpp/runtime/wallet/rpc/audit.rs†L15-L80】
3. **Action telemetry** – CLI and GUI flows expose opt-in counters (e.g.,
   `cli.action.events`, `ui.send.steps`, `ui.rpc.latency_ms`). When alerting on
   wallet action anomalies, include the counter snapshot from the GUI/CLI so the
   audit trail ties to a specific user action and RPC ID.【F:rpp/wallet/src/cli/telemetry.rs†L32-L109】【F:rpp/wallet/src/ui/telemetry.rs†L52-L173】

During incidents, start with the metric-based alert, pull the matching Grafana
panel, then pivot into runtime/audit logs. Recording that correlation in the
runbook ticket ensures future deployments reuse the same investigation trail.
