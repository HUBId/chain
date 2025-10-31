# Operator checklist

Use this checklist alongside the [modes overview](../modes.md), [configuration guide](../configuration.md),
and the [runbooks](../runbooks/startup.md). Update it after each deployment.

## First-run

- [ ] Execute `rpp-node <mode> --dry-run` to ensure configuration files resolve and port conflicts are
      reported before launch.【F:rpp/node/src/lib.rs†L258-L359】
- [ ] When bootstrapping with the stock templates, prefer `scripts/run_node_mode.sh`, `scripts/run_wallet_mode.sh`, or `scripts/run_hybrid_mode.sh`; they wait for `/health/live` and `/health/ready` to return 200 and surface exit codes 0/2/3/4 for automation.【F:scripts/run_node_mode.sh†L19-L74】【F:scripts/run_wallet_mode.sh†L19-L70】【F:scripts/run_hybrid_mode.sh†L21-L77】【F:rpp/node/src/main.rs†L18-L24】
- [ ] Verify configuration versions and schema validations succeed (no `config_version` or limit
      errors in the output).【F:rpp/runtime/config.rs†L979-L1054】【F:rpp/runtime/config.rs†L185-L210】
- [ ] Start the runtime and confirm the startup markers (`node runtime started`, `pipeline orchestrator
      started`, `wallet runtime initialised`) appear in the logs.【F:rpp/node/src/lib.rs†L442-L553】
- [ ] Check RPC readiness with `/health` and `/health/ready` before exposing the service to peers or
      tooling.【F:rpp/rpc/api.rs†L974-L1145】
- [ ] If telemetry is required, confirm the launch emitted `telemetry endpoints configured` (or similar)
      and that counters begin flowing to the backend.【F:rpp/node/src/lib.rs†L442-L481】【F:rpp/runtime/orchestration.rs†L611-L704】

## Routine operations

- [ ] Monitor pipeline metrics (`pipeline_submissions_total`, stage error counters) and investigate new
      rejection reasons via the [observability runbook](../runbooks/observability.md).【F:rpp/runtime/orchestration.rs†L611-L704】
- [ ] Review `/health/ready` periodically (or via alerting) to ensure node, wallet, and orchestrator
      remain enabled for the active mode.【F:rpp/rpc/api.rs†L1102-L1145】
- [ ] Rotate or inspect VRF key material after secrets backend changes or during scheduled security
      reviews using the validator CLI (`validator vrf rotate` / `validator vrf inspect`).【F:rpp/node/src/main.rs†L57-L178】【F:rpp/runtime/config.rs†L34-L120】
- [ ] Reconcile local configurations with the upstream templates after upgrades, noting telemetry or
      heartbeat default changes highlighted in the [upgrade runbook](../runbooks/upgrade.md).【F:config/hybrid.toml†L1-L47】【F:config/validator.toml†L1-L46】

