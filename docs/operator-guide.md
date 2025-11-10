# Node Lifecycle Expectations

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

## Networking safeguards for on-call rotations

Before returning a node to service, on-call engineers should verify that gossip
and connection limits match the active playbook. Follow the [gossip tuning
checklist](./networking.md#gossip-tuning-checklist) to validate bandwidth caps,
RPC token buckets, and replay protection thresholds after each configuration
change or rollback. The same checklist also documents the alerts and dashboards
expected to fire when a limit is exceeded, making it the first stop during
gossip-related incidents.【F:docs/networking.md†L1-L178】
