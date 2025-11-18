# Wallet Release Status

This status note summarizes the four wallet delivery phases, highlights the
capabilities that ship with the Phase 4 cut, and captures any deferred items that
operators should plan around before promoting a release. Use it together with
the per-phase guides, the operator runbook, and the CI dashboards referenced
below.

## Phase completion snapshot

| Phase | Status | Evidence & references |
| --- | --- | --- |
| Phase 1 – Minimal runtime | ✅ Complete. Baseline runtime wiring, RPC surfaces, telemetry opt-in defaults, and CLI quickstart are documented for staging environments. | [Wallet Phase 1 guide](wallet_phase1_minimal.md) covers the knobs and RPC references for the foundational rollout.【F:docs/wallet_phase1_minimal.md†L1-L75】 |
| Phase 2 – Policies & prover | ✅ Complete. Policy tunables, fee estimator behaviour, rescans, and prover configuration are locked down for spend readiness. | [Wallet Phase 2 guide](wallet_phase2_policies_prover.md) enumerates the policy scopes, prover modes, and troubleshooting workflows.【F:docs/wallet_phase2_policies_prover.md†L1-L120】 |
| Phase 3 – GUI | ✅ Complete. iced-based MVU GUI, tab flows, telemetry, and GUI-specific build/test steps ship alongside the runtime. | [Wallet Phase 3 guide](wallet_phase3_gui.md) documents the UI architecture, feature toggles, and test flows layered on the Phase 2 runtime.【F:docs/wallet_phase3_gui.md†L1-L120】 |
| Phase 4 – Advanced operations | ✅ Complete. Backup rotation, watch-only projections, multisig hooks, ZSI workflows, mTLS/RBAC security, and hardware bridges are available. | [Wallet Phase 4 guide](wallet_phase4_advanced.md) details the configuration, migrations, and troubleshooting steps for each advanced feature.【F:docs/wallet_phase4_advanced.md†L1-L208】 |

## Delivered capabilities

* **Wallet engine and policies** – The engine, policy, fee, signing, and
  address subsystems under `rpp/wallet/src/engine/*` supply deterministic
  transaction construction, coin selection, and limits that align with the
  Phase 2 policy knobs and backup-ready schema.【F:docs/rpp_wallet_architecture.md†L38-L145】【F:docs/wallet_phase2_policies_prover.md†L84-L120】
* **GUI** – The iced GUI with History/Send/Receive/Node tabs remains feature
  complete from Phase 3 and inherits the security hardening from Phase 4,
  including RBAC/mTLS prompts and policy surfacing in the UI flows.【F:docs/wallet_phase3_gui.md†L1-L120】【F:docs/wallet_phase4_advanced.md†L90-L152】
* **Backup and recovery** – Deterministic, encrypted backups (manual or
  scheduled) and ZSI imports/exports protect the wallet state and form part of
  the acceptance drills required before shipping a build.【F:docs/wallet_phase4_advanced.md†L9-L76】【F:docs/wallet_operator_runbook.md†L33-L68】
* **Security envelope** – Optional watch-only projections, multisig hooks,
  hardware signing, and hardened RPC security (mTLS+RBAC) all gate their CLI and
  RPC surfaces behind explicit feature flags and configuration scopes so
  operators can audit what was compiled into a release.【F:README.md†L28-L114】【F:docs/wallet_phase4_advanced.md†L40-L208】

## Deferred items and limitations

* **Hardware vendor packaging** – The repository ships generic HID/USB/TCP
  transports for hardware signing, but per-vendor firmware packaging and
  rollouts are deferred. Operators must stage devices manually and keep
  `fallback_to_software` enabled until the vendor’s firmware attestation program
  is complete.【F:docs/wallet_phase4_advanced.md†L140-L206】
* **External HSM configuration** – The runtime does not yet expose an HSM
  backend in `KEY_MANAGEMENT.md`; selecting `hsm` currently errors out, so the
  filesystem or Vault providers remain mandatory for validator/wallet keys until
  the hardware integration is finished.【F:docs/KEY_MANAGEMENT.md†L11-L20】
* **Advanced multisig coordination** – The wallet exposes hook surfaces and CLI
  plumbing when `wallet_multisig_hooks` is compiled, but end-to-end coordinator
  automation still depends on site-specific scripts (`scripts/multisig/*`). Plan
  manual testing for quorum reconciliation until vendor integrations land.【F:docs/wallet_phase4_advanced.md†L60-L109】
* **Vendor Electrs telemetry opt-in** – Telemetry endpoints stay disabled by
  default; enabling them requires a reachable observability stack per the config
  sample. Operators who have not provisioned telemetry endpoints must keep the
  scopes off, which limits real-time monitoring until observability catches up.【F:config/wallet.toml†L144-L168】【F:docs/telemetry.md†L1-L68】

## Dependency, feature, and platform requirements

* **Cargo feature flags** – All wallet capabilities map to explicit cargo
  features (runtime, backup, GUI, multisig, ZSI, mTLS, hardware). The feature
  table in the top-level README is authoritative and enforces runtime guardrails
  if configuration enables a scope without compiling the matching feature. Audit
  the build command to confirm the required features are compiled before
  distributing artifacts.【F:README.md†L28-L115】【F:config/wallet.toml†L1-L45】
* **Supported toolchains** – The workspace pins Rust stable `1.79.0` for the
  main build/test flows and `nightly-2025-07-14` for prover work. Use the
  corresponding `make build:stable` / `make test:stable` and nightly targets to
  reproduce CI coverage locally.【F:README.md†L116-L176】
* **CI feature coverage** – GitHub Actions run wallet-specific `cargo xtask`
  feature matrices (default, GUI, security bundle) plus runtime smoke tests so
  every feature permutation compiles and passes tests. Reproduce with
  `cargo xtask test-wallet-feature-matrix` when preparing releases.【F:docs/test_validation_strategy.md†L15-L90】
* **Configuration prerequisites** – Sample settings under `config/wallet.toml`
  illustrate the mTLS/RBAC bindings, telemetry endpoints, watch-only/multisig
  scopes, and node gossip prerequisites. Editing the config requires a runtime
  restart; enable `[wallet.rpc.security]`, `[wallet.security]`, `[wallet.backup]`,
  `[wallet.watch_only]`, `[wallet.multisig]`, `[wallet.hw]`, and `[electrs.*]`
  only after staging the matching secrets and connectivity.【F:config/wallet.toml†L1-L168】

## Verification checklist

Before shipping a wallet release, complete the following and attach the evidence
links/timestamps to the change record:

1. **Runbook walkthrough** – Execute the acceptance sequence from the
   [Wallet Operator Runbook](wallet_operator_runbook.md), covering prerequisites,
   configuration validation, feature-flag verification, acceptance tests
   (send/receive, watch-only, backup/restore, security envelopes, hardware), and
   telemetry verification.【F:docs/wallet_operator_runbook.md†L1-L196】
2. **CI health** – Confirm the latest `main` branch CI is green, paying attention
   to the wallet feature matrix jobs and runtime smoke tests described in the
   validation strategy doc. Archive the job URLs in the release ticket.【F:docs/test_validation_strategy.md†L15-L118】
3. **Regression re-run** – Locally invoke `make wallet-regression` to execute the
   wallet feature matrix and guard suite, then re-run any Phase-specific tests if
   changes touched those areas (e.g., GUI smoke tests from Phase 3, backup/restore
   drills from Phase 4). Attach logs/screenshots for auditor review.【F:docs/wallet_operator_runbook.md†L123-L171】【F:Makefile†L1-L23】
4. **Runbook-linked documents** – Cross-reference the relevant guides (Phase 1–4,
   runbook, policies/operations) in the release notes so operators know which
   documents describe the current behaviour and regression evidence.

## References

* [Wallet documentation index](README.md#wallet-documentation-index)
* [Wallet operator runbook](wallet_operator_runbook.md)
* [Sample configuration](../config/wallet.toml)
* [Validation strategy](test_validation_strategy.md)
