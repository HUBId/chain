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
| Phase 5 – Long-term service | 🚧 In progress. Release governance, SBOM/provenance requirements, SemVer tiering, and GHSA coordination now ship as part of every wallet cut. | [Wallet release checklist](release_checklist.md) and the [wallet support policy](wallet_support_policy.md) define the deliverables and timelines for the post-Phase 4 program.【F:docs/release_checklist.md†L1-L62】【F:docs/wallet_support_policy.md†L1-L120】 |

## Phase 5 – Long-term service scope

Phase 5 formalises the ongoing maintenance expectations for the wallet. The
release workflow emits SBOMs, checksums, signatures, and provenance metadata for
every artifact, while the [release checklist](release_checklist.md) and [wallet
support policy](wallet_support_policy.md) enforce SemVer tiering and EOL
tracking before a tag is promoted. Operators should reference the new
[wallet advisory template](security/wallet_advisory_template.md) when GHSA
coordination is required.【F:docs/release_checklist.md†L1-L62】【F:docs/wallet_support_policy.md†L1-L120】【F:docs/security/wallet_advisory_template.md†L1-L80】

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
* **External HSM configuration** – The runtime now exposes an HSM emulator that
  persists VRF material alongside `library_path`, but PKCS#11 integrations and
  vendor attestations are still pending before production-grade hardware
  support ships.【F:docs/KEY_MANAGEMENT.md†L11-L32】
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
5. **Packaging workflow** – Use `scripts/build_release.sh --wallet-version <tag>`
   followed by the `wallet-bundle`/`wallet-installer` xtasks to produce the
   installers for every supported triple. Follow the
   [wallet release workflow](wallet_release_workflow.md) so the canonical naming
   scheme, embedded docs, per-artifact checksums, SBOMs, and provenance statements
   are preserved when uploading the release payloads. Capture the signed
   `SHA256SUMS.txt` plus `*.intoto.jsonl` evidence referenced in the [release
   checklist](release_checklist.md).【F:scripts/build_release.sh†L12-L320】【F:docs/wallet_release_workflow.md†L1-L48】【F:docs/release_checklist.md†L34-L62】

6. **Documentation & support sign-off** – Confirm the release notes, install
   guides, and [wallet release status](wallet_release_status.md) capture the final
   SemVer tier and support window. Point reviewers to the [wallet support
   policy](wallet_support_policy.md) and file GHSA drafts via the new security
   template when needed.【F:docs/wallet_support_policy.md†L1-L120】【F:docs/security/wallet_advisory_template.md†L1-L80】

## SemVer and support expectations

Wallet releases follow the SemVer and lifecycle rules documented in the [wallet
support policy](wallet_support_policy.md). Use the matrix below to record the
current end-of-life targets and documentation hooks for every tier:

| Tier | SemVer marker | Support/EOL window | Notes |
| --- | --- | --- | --- |
| **Long-Term Support** | `vMAJOR.MINOR.PATCH` + `lts/MAJOR.MINOR` tag | 12 months after the LTS announcement. | Requires the signed SBOM/checksum/provenance bundle exported by `.github/workflows/release.yml` and the completed [release checklist](release_checklist.md). |
| **Maintenance** | `vMAJOR.MINOR.PATCH` | 6 months or until the next Maintenance release supersedes it. | Document the promotion timeline in this file plus the release notes so auditors know when support transitions occur. |
| **Experimental** | `exp/MAJOR.MINOR.PATCH` tag (in addition to the canonical tag) | Best-effort support only; no security SLA. | Use the [wallet advisory template](security/wallet_advisory_template.md) to communicate when experimental builds receive fixes outside of the standard windows. |

Release managers must keep this matrix aligned with the [`wallet_support_policy.md`](wallet_support_policy.md)
source of truth and link back to the policy in every release announcement.

## References

* [Wallet documentation index](README.md#wallet-documentation-index)
* [Wallet operator runbook](wallet_operator_runbook.md)
* [Sample configuration](../config/wallet.toml)
* [Validation strategy](test_validation_strategy.md)
