# RPP-STARK Verifier Alert Operations

> **Scope:** This runbook supplements the [general backend procedures](../zk_backends.md) with
> Prometheus, Alertmanager, and Grafana guidance for the `backend-rpp-stark`
> verifier.

## Telemetry signals

The runtime exposes per-stage counters and latency histograms every time the
RPP-STARK verifier processes a proof. Successful checks emit `result="ok"`,
while any failure records `result="fail"` together with the stage label, making
persistent errors easy to isolate in queries such as
`rpp_stark_stage_checks_total{stage="fri",result="fail"}`.【F:rpp/runtime/node.rs†L3770-L3850】【F:rpp/runtime/telemetry/metrics.rs†L473-L492】

All zk-related runtime and wallet metrics now carry an explicit `backend`
label so dashboards and alerts can slice data per prover/verifier. The stable
values are `backend="stwo"` for proof generation and wallet prover surfaces
and `proof_backend="rpp-stark"` for verifier signals; alerts in this guide are
scoped to those labels to keep mixed-backend deployments separate.【F:rpp/runtime/telemetry/metrics.rs†L380-L459】【F:ops/alerts/zk/rpp_stark.yaml†L6-L35】


### Proof-cache sizing & observability

- Cache retention is configurable per backend via the `[proof_cache]` block in
  the node configuration. `default_retain` (default: 1 024) applies to all
  backends, while `[proof_cache.per_backend_retain]` accepts backend
  fingerprints from `ProofVerifierRegistry::backend_fingerprint()` (for
  example `rpp-stark` in this guide). Zero or negative values are rejected
  during config validation. Startup logs with target `p2p.proof.cache` report
  the active backend, path, and retain size, and `/status/node` mirrors the
  applied values under `verifier_metrics.cache.{backend,capacity}`.【F:rpp/runtime/config.rs†L203-L235】【F:rpp/runtime/node_runtime/node.rs†L320-L356】【F:rpp/p2p/src/pipeline.rs†L262-L304】
- Proof-cache counters `rpp.runtime.proof.cache.{hits,misses,evictions}` now
  include a `backend` label in addition to `cache=gossip-proof-cache`, enabling
  per-backend dashboards and alerts; the same backend/capacity values surface
  in `/status/node` for incident audits.【F:rpp/runtime/telemetry/metrics.rs†L939-L976】【F:telemetry/schema.yaml†L23-L32】【F:rpp/p2p/src/pipeline.rs†L266-L304】
### Backend-specific alerts

- **STWO prover failures** – `increase(rpp_runtime_wallet_prover_failures{backend="stwo"}[10m])`
  pages when wallet proof generation repeatedly fails and always carries the
  `backend="stwo"` label so stwo regressions cannot be conflated with other
  prover incidents.【F:ops/alerts/zk/stwo.yaml†L1-L35】
- **RPP-STARK verifier regressions** – Stage-failure and latency alerts remain
  scoped to `proof_backend="rpp-stark"`, ensuring verifier incidents do not
  page wallets or other proving systems.【F:ops/alerts/zk/rpp_stark.yaml†L1-L35】
- **Validation coverage** – The alert probe under `tests/zk_alert_probe.rs`
  exercises both backends and asserts the fired payloads include the backend
  identifier, preventing cross-backend pollution in Alertmanager payloads.【F:tests/zk_alert_probe.rs†L1-L101】

### Startup validation and supported flag combinations

The node now validates compiled ZK backend flags during bootstrap so operators
get actionable errors instead of tripping runtime panics later on. The checks
reject binaries that:

- Enable both `backend-plonky3` and `backend-plonky3-gpu` at the same time.
- Omit every recognised backend feature (`prover-stwo`, `prover-stwo-simd`,
  `backend-plonky3`, `backend-plonky3-gpu`, `backend-rpp-stark`,
  `prover-mock`).

Startups that hit these guardrails exit with descriptive `ChainError::Config`
messages pointing at the offending flags, making misbuilt release artifacts
easy to diagnose before rollout.【F:rpp/runtime/node.rs†L2068-L2101】

Additional context for paging decisions is available through the
`VerifierMetricsSnapshot` that powers `/status/node`:
`backend_health.rpp-stark.verifier.rejected` increments on every rejected proof,
mirroring the per-stage counters and helping SREs confirm that the runtime is
actively discarding payloads.【F:rpp/proofs/proof_system/mod.rs†L343-L405】【F:docs/zk_backends.md†L92-L101】

Latency thresholds re-use the performance SLO established for the consensus
verifier: the p95 must stay at or below 3.2 seconds to keep block finality inside
the 12 second envelope.【F:docs/performance/consensus_proofs.md†L21-L38】

## Recommended alert thresholds

| Signal | Suggested query | Threshold | Purpose |
| --- | --- | --- | --- |
| Stage failures | `increase(rpp_stark_stage_checks_total{proof_backend="rpp-stark",result="fail"}[10m])` | Warning: > 0 for 10 m<br>Critical: > 3 for 10 m | Escalate once any stage starts failing persistently and prioritise incidents that reject multiple proofs within one rotation.【F:rpp/runtime/node.rs†L3770-L3850】【F:docs/zk_backends.md†L69-L107】 |
| Consensus verifier latency | `histogram_quantile(0.95, sum(rate(rpp_stark_verify_duration_seconds_bucket{proof_backend="rpp-stark",proof_kind="consensus"}[5m])) by (le))` | Critical: > 3.2 s for 15 m | Protect the consensus finality envelope by paging when the verifier exceeds the accepted p95 latency budget.【F:rpp/runtime/telemetry/metrics.rs†L509-L518】【F:docs/performance/consensus_proofs.md†L21-L38】 |
| Rejection counter confirmation | `increase(backend_health_rpp_stark_verifier_rejected[10m])` (via scraper or `/status/node`) | Investigate whenever > 0 while alerts fire | Validate that failed stage checks translate to runtime rejections before authorising a rollback or enforcement bypass.【F:rpp/proofs/proof_system/mod.rs†L343-L405】【F:docs/zk_backends.md†L92-L101】 |

Sample Alertmanager groups and Grafana drilldowns that encode these thresholds
are provided under `ops/alerts/zk/` and can be imported as a starting point for
PagerDuty and dashboard configuration.【F:ops/alerts/zk/rpp_stark.yaml†L1-L36】【F:ops/alerts/zk/rpp_stark_grafana.json†L1-L48】

## Alert triage and response

1. **Identify the failing stage.** Inspect the `stage` label on
   `rpp_stark_stage_checks_total{result="fail"}` to map the alert back to the
   countermeasures table in the primary playbook. Stage-specific remediation
   steps—including replay commands and configuration toggles—are maintained in
   the `Verifier-Stage-Flags & Gegenmaßnahmen` section of the backend
   guide.【F:docs/zk_backends.md†L69-L107】
2. **Confirm runtime enforcement.** Query `/status/node` for
   `backend_health.rpp-stark.verifier` and ensure `rejected` is increasing. The
   same snapshot should show whether `accepted` recovers after mitigation. Use
   the mempool status endpoint to capture the offending proofs before they are
   reaped.【F:rpp/runtime/node.rs†L5416-L5460】【F:docs/zk_backends.md†L96-L101】
3. **Escalate according to the playbook.** If mitigation fails, apply the
   fallback paths documented for backend swaps or enforcement bypasses and loop
   in release engineering. Defer sustained outages or mixed fork/verifier
   incidents to the central [incident response runbook](./incidents.md) so the
   pruning, fork-handling, and verifier failover timelines remain aligned.
   Every alert acknowledgement must be accompanied by an incident log entry
   summarising the proof IDs inspected, configuration overrides applied, and
   whether Stage flags returned to `true`.【F:docs/zk_backends.md†L102-L107】

Following these steps keeps the on-call workflow aligned with the incident
runbook while giving responders explicit telemetry cues to confirm that alerts
represent real verifier regressions.
