# Node Lifecycle Expectations

> **Breadcrumbs:** [Operator documentation index](./README.md) › [Checklists](./README.md#checklists) › Node lifecycle expectations
>
> **Related references:** [Security policy & reporting](../SECURITY.md),
> [Observability overview](./observability.md) & [runbook](./runbooks/observability.md),
> [Zero-knowledge backend procedures](./zk_backends.md),
> [RPP-STARK verifier alert operations](./operations/zk_backends.md),
> [Incident response runbook](./operations/incidents.md),
> [Snapshot restore and wallet recovery](./runbooks/snapshot_restore_and_wallet_recovery.md)

The validator process exposes `/health/live` and `/health/ready` probes on the
configured RPC listener as soon as startup completes. Integration coverage in
`tests/node_lifecycle.rs::node_process_handles_health_probes_and_ctrl_c` asserts that
both endpoints return HTTP 200 while the node is serving traffic, then flip to
`503 Service Unavailable` once a CTRL+C signal is delivered and the process
shuts down cleanly. The payloads now include the active proof backend, the last
verification outcome (including bypass signalling), and proof-cache counters;
flag deployments where `last_verification.outcome` reports `Rejected` or
`cache.evictions` spikes despite a 200/OK status. The test also verifies that
the TCP listener is released so orchestrators can bind the port again
immediately after shutdown.

Operators can now query those probes alongside consensus finality, pruning
progress, wallet readiness, uptime proof backlog, and timetoke snapshot counts
with `rpp-chain-cli validator health --rpc-url http://host:port`. The command
exits with `0` when all checks succeed, `20` when a degraded subsystem is
detected (e.g., missing quorum or wallet signer not ready), and `21` if any
probe cannot be reached. Use `--json` for automation workflows that need to
ingest the summarized payloads directly.

Configuration changes are exercised by
`tests/node_lifecycle.rs::node_restart_applies_feature_gate_changes`. The workflow
persists updated feature gates and storage backend policies, respawns the
process with the same configuration file, and waits for the ready probe before
querying `/status/node`. The backend health map must include at least one entry
before and after the restart, demonstrating that proof/verifier backends remain
available even when feature flags toggle between runs.

Operators can rely on these behaviours during orchestration rollouts: issuing a
single CTRL+C (or SIGTERM on Unix) initiates an orderly shutdown, health probes
switch to failing responses during teardown, and the subsequent start can reuse
all previously reserved sockets and configuration directories. Any config change
that updates feature flags or backend policies should be applied by writing the
new values to the node configuration file and restarting the service, matching
exactly what the automated lifecycle tests cover.

API credential updates follow the same pattern: publish the new bearer token to
clients, then roll validators with the replacement value so each node reloads the
secret and clears any token-bucket cache. Use the
[RPC API key rotation checklist](./interfaces/rpc/README.md#live-api-key-rotation)
for step-by-step timing guidance.

> **Warning:** The runtime only loads configuration files during startup. Signals such as
> `SIGHUP` are ignored for reload purposes, and editing `node.toml`, `malachite.toml`, or admission
> policies while the process is running does not take effect. Plan for a full shutdown and restart
> after configuration changes, just as the lifecycle tests demonstrate.

## Startup validation failures

Startup validation now has dedicated coverage in
`tests/node_lifecycle/startup_errors.rs`. The suite exercises the three most
common operator mistakes and asserts that the CLI exits with code 2, the
configuration error bucket exposed by `BootstrapErrorKind` in the runtime.

| Failure mode | Likely causes | Fix | Deeper docs |
| --- | --- | --- | --- |
| Configuration parsing fails or the config file is missing | Truncated or malformed TOML, or `RPP_CONFIG` points to a path that does not exist.【F:tests/node_lifecycle/startup_errors.rs†L11-L68】 | Re-copy the template, reapply changes, and re-run `rpp-node … --dry-run` to surface loader errors before restarting automation.【F:tests/node_lifecycle/startup_errors.rs†L11-L68】【F:rpp/node/src/lib.rs†L258-L359】 | [Configuration reference](./configuration.md) and [startup runbook](./runbooks/startup.md) checklist entries for config loading. |
| Backend validation rejects the build | Validator or hybrid modes compiled without a proof backend (`prover-stwo`), or feature flags enable unsupported backend combinations (e.g., Plonky3 with mock prover).【F:rpp/node/src/lib.rs†L90-L120】【F:docs/runbooks/startup.md†L15-L28】 | Rebuild with the required backend feature set (see `prover-stwo`/`backend-plonky3`), then rerun the startup checklist to confirm guards and readiness markers pass.【F:rpp/node/src/lib.rs†L90-L120】【F:docs/runbooks/startup.md†L15-L38】 | [ZK backend procedures](./zk_backends.md) and [startup runbook guard verification](./runbooks/startup.md#phase-1-guard-verification). |
| Missing snapshots or corrupted state during boot | Baseline Firewood snapshots absent from `storage.firewood.snapshots`, or root-integrity guard detects corrupted manifests while state sync hydrates storage.【F:docs/storage/firewood.md†L1-L48】【F:docs/runbooks/startup.md†L19-L38】 | Restore snapshots from the export pipeline or rebuild via `/snapshots/rebuild`, then retry boot once the root-integrity guard reports healthy readiness.【F:docs/storage/firewood.md†L1-L48】【F:docs/runbooks/pruning.md†L1-L120】【F:docs/runbooks/startup.md†L19-L38】 | [Firewood lifecycle guide](./storage/firewood.md) and [pruning operations runbook](./runbooks/pruning_operations.md). |

Before shipping new pruning checkpoints, hash-compare the state captured before
and after pruning with `fwdctl compare` as outlined in the
[pruning operations runbook](./runbooks/pruning_operations.md#4-verify-pruning-checkpoints)
so operators can block distribution if the roots diverge.

Enable `--strict-config-validation` (or set `RPP_STRICT_CONFIG_VALIDATION=1`) during rollout dry runs to surface typos and unexpected keys before production restarts. Strict mode rejects unrecognized fields across node and wallet profiles, keeping misaligned templates from silently loading in relaxed mode.【F:rpp/node-runtime-api/src/lib.rs†L119-L152】【F:rpp/node/src/lib.rs†L1257-L1321】【F:rpp/node/src/lib.rs†L2868-L2926】

In all three cases, the exit code remains `2`, matching the configuration error
mapping in the runtime. Orchestrators that supervise the process should treat
this exit code as a hard-stop requiring human intervention rather than a simple
retry.【F:rpp/node/src/lib.rs†L152-L233】 Keep this table in sync with the
documentation review checklist so on-call handoffs always reflect the latest
failure modes.

Storage-sensitive rollouts should also review the [Firewood WAL sizing and sync
guidance](./storage/firewood.md#wal-sizing-and-sync-policy-guidance) before
deploying new budgets or durability settings.

## Telemetry alert handoff

When the telemetry pipeline fires an alert, follow the
[telemetry alert response procedures](./observability.md#telemetry-alert-response-procedures)
to acknowledge it in PagerDuty within **five minutes**, scope any Alertmanager
silence, and escalate after **15 minutes** if mitigation remains unclear. Keep
the PagerDuty incident timeline updated with hypotheses, silences, and the
current owner so incoming responders and security liaisons can pick up the
investigation without repeating earlier steps. Link the incident postmortem to
the shared operations log once the alert clears. Major forks, verifier outages,
or pruning stalls should be handled with the [incident response runbook](./operations/incidents.md),
which sets the same acknowledgement and stabilisation timelines and captures
the commands/metrics to apply during on-call mitigation.

## Mempool incident response

High-volume spam or DoS incidents should follow the
[mempool cleanup runbook](./mempool_cleanup.md). The playbook mirrors the
integration coverage that validates limiter behaviour, gossip drains, and the
RPC controls for adjusting queue limits and fee weights, giving on-call
engineers a single reference when the mempool saturates.

## High-availability restart drills

The uptime HA suite (`tests/uptime_ha/mod.rs`) exercises both orderly restarts
and crash-restarts to prove that consensus epochs, timetoke accounting, and
wallet-derived nonces survive process cycles. The graceful flow finalises a
transaction, restarts the validator, and asserts that epochs and block heights
never regress while wallet balances remain stable after the restart. The crash
path injects multiple transactions, flips the node to the recursive/Plonky3
backend on restart, and waits for the mempool to drain with nonces advanced to
cover every submission.【F:tests/uptime_ha/mod.rs†L15-L197】

Operationally, mirror the same guardrails:

- Query `/status/node` before and after a restart to verify that
  `backend_health` contains at least one active prover entry and that epochs and
  block heights never decrease. Any decrease indicates stale snapshots or a
  failed consensus recovery. The same payload now embeds backend SLA snapshots
  (latency and error-rate) under `backend_health.<name>.verifier_sla` and
  `backend_health.<name>.prover_sla`, mirroring the `/health` response used by
  orchestrators.【F:rpp/runtime/node.rs†L289-L310】【F:rpp/rpc/api.rs†L1088-L1110】
- Check the timetoke counters for validators in `/status/node` and `/ledger`
  outputs; hours should be monotonic across restarts, matching the test
  assertions. A drop requires manual replay of uptime proofs.
- When toggling zero-knowledge backends (e.g., switching to the recursive
  pipeline), perform the change during a restart so the new backend is reflected
  in `backend_health`, and watch the proof verification latency metrics for
  regressions.
- Monitor `pending_transactions` immediately after the service returns; counts
  should rapidly drain to zero as the mempool rehydrates and workflows
  re-execute. Stuck queues suggest mempool persistence corruption and should
  trigger a crash dump and rollback.

## CI artefacts for consensus/proving/timetoke failures

Nightly simnet runs now upload artefacts keyed by the backend/feature matrix,
e.g. `simnet-prod-prover-stwo-backend-plonky3` or
`simnet-regression-prod-plonky3`, and attach a sibling failure bundle whenever a
job fails. To retrieve them during incidents:

1. Download the labelled bundle from the workflow run (replace `<run-id>` and
   `<label>` with the GitHub run and artefact names):

   ```
   gh run download <run-id> --name simnet-<label> --dir artifacts
   ```

2. Expand the archive to expose the target layout:

   ```
   tar -xzf artifacts/simnet/<label>/simnet-<label>.tar.gz -C artifacts/simnet/<label>
   ```

3. Inspect consensus/prover/verifier logs under `artifacts/simnet/<label>/logs`
   and timetoke telemetry under `artifacts/simnet/<label>/telemetry/timetoke*.jsonl`
   to determine whether the failure came from proving, verification, or replay
   lag. Summaries remain under `summaries/` for `python3 scripts/analyze_simnet.py`
   so the same checks CI performs can be replicated offline.

## Health integration for orchestrators and Kubernetes

- `/health` keeps returning HTTP 200 for monitoring stacks but now flips the
  `status` field to `degraded` whenever any prover or verifier backend breaches
  its SLA (latency above 8s on average or error rates above 2% for verifiers;
  prover failures above 5%). Kubernetes liveness probes should continue to
  treat the endpoint as available while alerting systems and orchestrators can
  key off the `status` string to surface warnings without hard-restarting pods.
  The per-backend SLA map is exposed under `backend.sla` for automation to
  pinpoint which backend is failing.【F:rpp/proofs/proof_system/mod.rs†L332-L360】【F:rpp/rpc/api.rs†L2706-L2720】
- `/health/ready` remains tied to readiness (e.g., pruning availability,
  snapshot services, and wallet connectivity) and does not treat SLA breaches as
  fatal. Pods should continue using the ready endpoint for traffic gating while
  relying on `/health` for SLA visibility.【F:rpp/rpc/api.rs†L2769-L2799】
- Orchestrators that flip backends during deployments can poll `/status/node`
  and `/health` before and after the change, ensuring the active backend shows
  a healthy SLA entry and that the prover error-rate budget is not exceeded.
  Automate rollback when `backend.sla[active].healthy` is `false` for more than
  a few consecutive checks.

## Responding to SLA degradations

When `/health` reports `status: degraded`, operators should:

1. Inspect `backend_health` for the affected backend and whether latency or
   error budget triggered the breach. Verifier SLA failures often surface as
   rising rejection counts, while prover SLA regressions show increased
   `failed_proofs` against the 5% budget.【F:rpp/runtime/node.rs†L7113-L7146】
2. Cross-check backend logs for circuit-level errors and correlate with the
   metrics driving the SLA breach. For verifier latency spikes, verify that
   proof cache hit ratios remain healthy in the accompanying `cache` snapshot
   and consider raising cache capacity before restarting nodes.【F:rpp/rpc/api.rs†L1097-L1110】
3. If the degraded backend is optional (e.g., a secondary prover), mark it as
   drained in the orchestrator and trigger a backend flip or restart so traffic
   flows to the healthy backend. Capture `/health` and `/status/node` payloads
   before and after the change for incident records.
4. After mitigation, keep polling `/health` until the `status` field returns to
   `ok` and the affected backend’s SLA entry reports `healthy: true`. Escalate to
   the cryptography team if error rates remain above budget after retries or
   cache tuning.

## Networking safeguards for on-call rotations

Before returning a node to service, on-call engineers should verify that gossip
and connection limits match the active playbook. Follow the [gossip tuning
checklist](./networking.md#gossip-tuning-checklist) to validate bandwidth caps,
RPC token buckets, and replay protection thresholds after each configuration
change or rollback, and keep the [network partition response runbook](./operations/network_partition.md)
handy for rapid mitigation when connectivity degrades. The same checklist also
documents the alerts and dashboards expected to fire when a limit is exceeded,
making it the first stop during gossip-related incidents.【F:docs/networking.md†L1-L178】
