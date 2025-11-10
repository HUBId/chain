# Node Lifecycle Expectations

> **Breadcrumbs:** [Operator documentation index](./README.md) › [Checklists](./README.md#checklists) › Node lifecycle expectations
>
> **Related references:** [Security policy & reporting](../SECURITY.md),
> [Observability overview](./observability.md) & [runbook](./runbooks/observability.md),
> [Zero-knowledge backend procedures](./zk_backends.md)

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

- **Malformed configuration files.** If TOML parsing fails, the process exits
  with `configuration error: failed to load configuration …`. Re-copy the
  template and reapply changes rather than editing the broken file in place.
  This scenario catches stray brackets, truncated content, and merge conflicts
  left inside the config.【F:tests/node_lifecycle/startup_errors.rs†L11-L39】
- **Missing configuration paths.** When `RPP_CONFIG` points to a file that does
  not exist, the CLI prints `node configuration not found … (resolved from
  environment)` before exiting. Clear the environment variable or fix the path
  before restarting automation; otherwise every rollout loops on the same
  failure.【F:tests/node_lifecycle/startup_errors.rs†L41-L68】
- **Invalid telemetry overrides.** Setting `RPP_NODE_OTLP_ENDPOINT` to a URI
  that is not HTTP(S) is rejected with `telemetry.endpoint must use http or
  https scheme`. Confirm the scheme and host in secrets management before
  retrying; the runtime will not fall back to the configured endpoint when the
  override is invalid.【F:tests/node_lifecycle/startup_errors.rs†L70-L101】

In all three cases, the exit code remains `2`, matching the configuration error
mapping in the runtime. Orchestrators that supervise the process should treat
this exit code as a hard-stop requiring human intervention rather than a simple
retry.【F:rpp/node/src/lib.rs†L152-L233】

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
change or rollback. The same checklist also documents the alerts and dashboards
expected to fire when a limit is exceeded, making it the first stop during
gossip-related incidents.【F:docs/networking.md†L1-L178】
