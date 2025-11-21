# Node Lifecycle Expectations

> **Breadcrumbs:** [Operator documentation index](./README.md) › [Checklists](./README.md#checklists) › Node lifecycle expectations
>
> **Related references:** [Security policy & reporting](../SECURITY.md),
> [Observability overview](./observability.md) & [runbook](./runbooks/observability.md),
> [Zero-knowledge backend procedures](./zk_backends.md),
> [RPP-STARK verifier alert operations](./operations/zk_backends.md)

The validator process exposes `/health/live` and `/health/ready` probes on the
configured RPC listener as soon as startup completes. Integration coverage in
`tests/node_lifecycle.rs::node_process_handles_health_probes_and_ctrl_c` asserts that
both endpoints return HTTP 200 while the node is serving traffic, then flip to
`503 Service Unavailable` once a CTRL+C signal is delivered and the process
shuts down cleanly. The test also verifies that the TCP listener is released so
orchestrators can bind the port again immediately after shutdown.

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
the shared operations log once the alert clears.

## Mempool incident response

High-volume spam or DoS incidents should follow the
[mempool cleanup runbook](./mempool_cleanup.md). The playbook mirrors the
integration coverage that validates limiter behaviour, gossip drains, and the
RPC controls for adjusting queue limits and fee weights, giving on-call
engineers a single reference when the mempool saturates.

## Networking safeguards for on-call rotations

Before returning a node to service, on-call engineers should verify that gossip
and connection limits match the active playbook. Follow the [gossip tuning
checklist](./networking.md#gossip-tuning-checklist) to validate bandwidth caps,
RPC token buckets, and replay protection thresholds after each configuration
change or rollback, and keep the [network partition response runbook](./operations/network_partition.md)
handy for rapid mitigation when connectivity degrades. The same checklist also
documents the alerts and dashboards expected to fire when a limit is exceeded,
making it the first stop during gossip-related incidents.【F:docs/networking.md†L1-L178】
