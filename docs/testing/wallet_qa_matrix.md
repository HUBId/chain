# Wallet QA matrix

The wallet nightly workflow (`.github/workflows/wallet-nightly.yml`) exercises a multi-dimensional matrix of scenarios so that regressions surface before release validation. This document lists the coverage provided by each CI job, explains how flakes are quarantined, and outlines the process for rehabilitating disabled suites.

## Job matrix

| Job | Scope | Target OS | Feature flags | Notes |
| --- | --- | --- | --- | --- |
| `wallet-e2e` | Backup/export, policy enforcement, RBAC/mTLS, watch-only, pending locks, workflow snapshot, rescan/resume | Linux, macOS, Windows | `wallet-integration`, `policies`, `prover`, `watch-only` (as applicable per matrix row) | Executes discrete end-to-end suites listed inside the workflow matrix. Each matrix entry publishes suite logs and failure manifests for the flake tracker. |
| `wallet-ui-contract` | RPC/UI compatibility contract | Linux | Stable toolchain | Runs `cargo test -p rpp-rpc --test wallet_ui_contract` to ensure the CLI/UI contract stays in sync with RPC payloads. |
| `wallet-fuzz` | DB Ser/De invariants, transaction builder invariants, RPC payload fuzzing | Linux | Nightly toolchain for fuzzing | Sequentially runs targeted `cargo test` patterns for codec/builder modules and executes `cargo fuzz run wallet_rpc` with a bounded budget. |
| `wallet-performance` | Deterministic performance probes | Linux | Stable toolchain | Runs the `wallet_perf` criterion benchmark and exports JSON metrics to the job summary so capacity trends are easy to track. |
| `wallet-quarantine` | Known flaky suites | Linux | Stable toolchain | Executes `wallet_zsi_flow_e2e`, `wallet_pending_locks_e2e`, and `wallet_workflow_snapshot` in isolation with `continue-on-error` so flakes never hide signal from healthy suites. |
| `flake-tracker` | Stability aggregation | Linux | N/A | Downloads all failure manifests, labels quarantined vs new flakes, emits a markdown table, uploads `wallet-artifacts/flake-summary.json`, and records workflow-level trend data via `gh run list`. |

### Mapping scenarios to suites

| Scenario | Test target | CI job |
| --- | --- | --- |
| Backup export/import fidelity | `tests/wallet_backup_recovery_e2e.rs` | `wallet-e2e` (Linux + macOS) |
| Watch-only ledger synchronization | `tests/wallet_watch_only_e2e.rs` | `wallet-e2e` (Linux + Windows) |
| Policy and fee recovery | `tests/wallet_policies_fee_e2e.rs` | `wallet-e2e` (Linux full feature row) |
| RBAC + mutual TLS flows | `tests/wallet_rbac_mtls_e2e.rs` | `wallet-e2e` (Linux full feature row) |
| Pending lock durability | `tests/wallet_pending_locks_e2e.rs` | `wallet-e2e` (Linux watch row) + `wallet-quarantine` |
| Workflow snapshot regression | `tests/wallet_workflow_snapshot.rs` | `wallet-e2e` (Windows) + `wallet-quarantine` |
| Rescan/resume semantics | `tests/wallet_rescan_resume_e2e.rs` | `wallet-e2e` (macOS) |
| RPC/UI compatibility | `rpp/rpc/tests/wallet_ui_contract.rs` | `wallet-ui-contract` |
| DB codec Ser/De invariants | `rpp/wallet/src/db/codec.rs` tests | `wallet-fuzz` |
| Transaction builder invariants | `rpp/wallet/src/engine/tests.rs` tests | `wallet-fuzz` |
| RPC payload fuzzing | `rpp/wallet/fuzz/fuzz_targets/wallet_rpc.rs` | `wallet-fuzz` |
| UI smoke/policies/perf dashboards | `benchmark/benches/wallet_perf.rs` | `wallet-performance` |
| ZSI lifecycle/pending lock flake checks | `tests/wallet_zsi_flow_e2e.rs`, `tests/wallet_pending_locks_e2e.rs` | `wallet-quarantine` |

## Flake quarantine and rehabilitation

1. **Detection** – Every test runner writes a `<job>_failures.json` manifest that lists suites and failing test functions. The `flake-tracker` job merges those manifests, tags each entry as `quarantined` (if the suite/test appears in `WALLET_QUARANTINE`) or `new`, and publishes a markdown table and JSON artifact.
2. **Labelling** – Any failure emitted by `flake-tracker` is effectively labelled in the job summary, making it trivial to grep for `new` vs `quarantined` regressions. Owners can subscribe to summary notifications or consume the JSON artifact to annotate issues automatically.
3. **Quarantine** – Known offenders must be listed under the `WALLET_QUARANTINE` env var in the workflow. Those suites run inside the `wallet-quarantine` job with `continue-on-error` so that flakes do not break the entire workflow but still emit telemetry.
4. **Rehabilitation** – When a flaky test is fixed, remove it from `WALLET_QUARANTINE` and re-run the nightly workflow. If the suite passes for three consecutive runs (as shown in the stability JSON summary), leave it out of quarantine. If it fails again, re-add it and open an issue referencing the failing summary row to maintain accountability.

## Adding new coverage

* Update `.github/workflows/wallet-nightly.yml` with the new suite entry (matrix row, fuzz target, etc.).
* Document the new scenario here by extending the tables above.
* If the suite is unstable, add it to the quarantine list temporarily and include rehabilitation steps in the owning team's backlog.

This QA matrix should be updated whenever wallet surface area changes so downstream teams can reason about CI guarantees at a glance.
