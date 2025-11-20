# Wallet roadmap beyond Phase 4

Phase 4 delivered the advanced operations baseline (backup rotation, watch-only,
multisig hooks, RBAC/mTLS, and hardware fallbacks), but multiple initiatives are
already queued for the next planning cycle. The sections below summarize the
prioritized work, dependencies, and research items so contributors can pick up
open issues quickly.

## Short-term initiatives (next 1–2 releases)

1. **Hardware vendor packaging & attestations** – Operators still provision
   hardware devices manually and keep `fallback_to_software = true` because
   per-vendor firmware attestation, packaging, and rotation processes are
   deferred.【F:docs/wallet_release_status.md†L30-L48】 Track the SDK evaluation
   and packaging tasks under the `wallet-hw` label in the issue tracker:
   <https://github.com/ava-labs/chain/issues?q=is%3Aopen+label%3Awallet-hw>.
2. **HSM-backed key management** – `KEY_MANAGEMENT.md` now exposes an HSM
   emulator so CLI flows can persist VRF material without hard dependencies on
   filesystem or Vault backends, but PKCS#11 drivers and vendor attestation still
   need to be wired up for hardware-backed signing.【F:docs/KEY_MANAGEMENT.md†L11-L32】
   The `wallet-hsm` issue list (<https://github.com/ava-labs/chain/issues?q=is%3Aopen+label%3Awallet-hsm>)
   tracks SDK prototyping, key wrap policies, and audit export formats.
3. **Telemetry adoption during rollouts** – New monitoring guidance needs to be
   linked from every deployment ticket so on-call responders follow the same
   sync/prover/RBAC dashboards. Ensure the `wallet-observability` issues stay in
   sync with [`docs/wallet_monitoring.md`](wallet_monitoring.md).

## Mid-term initiatives (next 2–4 releases)

1. **Mobile/tablet UI exploration** – The Phase 3 GUI is desktop-focused and
   relies on iced windowing. Future releases should evaluate a mobile-friendly UI
   layer or a responsive shell that leverages the existing RPC APIs so hardware
   pilots can include companion devices.【F:docs/wallet_phase3_gui.md†L8-L210】 Use
   the `wallet-mobile` issue label to track UI toolkit spikes and authentication
   research: <https://github.com/ava-labs/chain/issues?q=is%3Aopen+label%3Awallet-mobile>.
2. **Platform-native key stores** – Windows and macOS builds still default to the
   filesystem keystore even though the runtime scaffolding for audit directories
   and wallet security paths exists.【F:rpp/runtime/config.rs†L3188-L3214】 Research
   integrating DPAPI/Secure Enclave backends via the `wallet-platform-keystore`
   issues (<https://github.com/ava-labs/chain/issues?q=is%3Aopen+label%3Awallet-platform-keystore>).
3. **Electrs/observability bundles** – Telemetry endpoints (`[electrs.*]`) remain
   disabled until operators wire a reachable stack, limiting parity with the new
   monitoring guide.【F:config/wallet.toml†L140-L168】 Track deliverables under the
   `wallet-telemetry` issue list so dashboards ship with pre-wired scrape configs:
   <https://github.com/ava-labs/chain/issues?q=is%3Aopen+label%3Awallet-telemetry>.

## Long-term initiatives (multi-release)

1. **Multisig coordinator completion** – Phase 4 exposes multisig hooks and CLI
   plumbing, but end-to-end coordinators still require site-specific scripts.
   Future work should add bundled coordinators, GUI surfaces, and watch-only
   projections for quorum reconciliation.【F:docs/wallet_phase4_advanced.md†L60-L109】
   Follow the `wallet-multisig` issue label for RFCs and prototypes:
   <https://github.com/ava-labs/chain/issues?q=is%3Aopen+label%3Awallet-multisig>.
2. **Advanced privacy / ZSI tooling** – The ZSI workflows exist behind
   `wallet_zsi`, but privacy-preserving audits and identity binding require
   additional UX work plus backend proofs before production rollouts.【F:docs/wallet_phase4_advanced.md†L45-L66】 Keep research
   notes under `wallet-zsi` issues and link to relevant RFCs inside
   `docs/roadmap_implementation_plan.md` when proposals graduate.
3. **End-to-end release automation** – The release policy already enforces STWO
   builds, but the tagging/signing process for wallet-only bundles should be
   scripted (Task 64 follow-up). Coordinate with the release team under the
   `wallet-release` label (<https://github.com/ava-labs/chain/issues?q=is%3Aopen+label%3Awallet-release>).

## Sharing & collaboration

* Add this roadmap to contributor onboarding (README) and release notes so new
  volunteers know which areas need help next.
* Reference the linked labels/RFCs when filing issues so the backlog stays
  searchable and stakeholders can align priorities quickly.
