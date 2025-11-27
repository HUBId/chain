# Operator checklist

Use this checklist alongside the [modes overview](../modes.md), [configuration guide](../configuration.md),
and the [runbooks](../runbooks/startup.md). Update it after each deployment.

## First-run

- [ ] Execute `cargo run -p rpp-chain -- <mode> --dry-run` to ensure configuration files resolve and port conflicts are
      reported before launch.【F:rpp/node/src/lib.rs†L258-L359】
- [ ] Start from `config/examples/production/validator-stwo-tls.toml` or
      `validator-plonky3-tls.toml` plus the co-located `malachite.toml` so TLS,
      pruning pacing, gossip limits, and zk-backend cache sizes match the
      production defaults before you layer environment-specific overrides.【F:config/examples/production/validator-stwo-tls.toml†L1-L178】【F:config/examples/production/validator-plonky3-tls.toml†L1-L172】【F:config/examples/production/malachite.toml†L1-L76】
- [ ] When bootstrapping with the stock templates, prefer `scripts/run_node_mode.sh`, `scripts/run_wallet_mode.sh`, or `scripts/run_hybrid_mode.sh`; they wait for `/health/live` and `/health/ready` to return 200 and surface exit codes 0/2/3/4 for automation. Configure readiness headers with `RPP_NODE_RPC_AUTH_TOKEN` / `RPP_NODE_HEALTH_HEADERS`, or the wallet-specific `RPP_WALLET_RPC_AUTH_TOKEN` / `RPP_WALLET_HEALTH_HEADERS`, when the RPC gateway enforces authentication.【F:scripts/run_node_mode.sh†L10-L64】【F:scripts/run_wallet_mode.sh†L10-L70】【F:scripts/run_hybrid_mode.sh†L21-L77】【F:rpp/node/src/main.rs†L18-L24】
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
- [ ] During documentation reviews, confirm the [startup validation failures table](../operator-guide.md#startup-validation-failures)
      captures any new configuration, backend, or snapshot boot issues observed since the last deployment.
      Update the table and linked runbooks as needed so on-call handoffs stay accurate.【F:docs/operator-guide.md†L25-L49】
- [ ] Keep the [incident response runbook](../operations/incidents.md) aligned with fork-handling, verifier
      failover, and pruning changes shipped in new releases so future incidents reuse the current commands
      and escalation timelines.

## Phase 2 Acceptance

- [ ] `cargo xtask test-consensus-manipulation` mit den Feature-Sets `backend-plonky3` und
      `prover-stwo` ausführen; Logs/Screenshots im Abnahmeordner ablegen.【F:xtask/src/main.rs†L1-L120】
- [ ] Simnet-Szenario `consensus_quorum_stress` laufen lassen und die erwarteten Fehler (`invalid VRF proof`,
      `duplicate precommit detected`, …) im Operator-Logbook dokumentieren.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:rpp/runtime/types/block.rs†L2002-L2245】
- [ ] Grafana-Panels für `consensus_vrf_verification_time_ms` und
      `consensus_quorum_verifications_total{result="failure"}` prüfen, Screenshots an die Auditor:innen
      weitergeben.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:docs/observability/consensus.md†L1-L70】
- [ ] RPC-Checks (`GET /status/consensus`) für erfolgreiche und abgelehnte Blöcke protokollieren; die
      Vorgehensweise ist im [Operator Guide](../rpp_node_operator_guide.md#phase-2-consensus-proof-validation-checks) und
      im [Observability-Runbook](../runbooks/observability.md#phase-2-consensus-proof-audits) beschrieben.【F:docs/rpp_node_operator_guide.md†L120-L174】【F:docs/runbooks/observability.md†L1-L120】

