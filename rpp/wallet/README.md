# rpp-wallet

The `rpp-wallet` crate bundles the wallet runtime, JSON-RPC surface, and CLI used by RPP operators. It shares storage and configuration conventions with the hybrid runtime so node operators can co-locate services.

## Schema versioning & storage guards

`WalletStore` persists its schema marker under `wallet/schema_version` and upgrades migrations on open. New storage surfaces such as the backup metadata bucket (`wallet/backup_meta/…`) and security registries (`wallet/security/{rbac,mtls}/…`) land in schema version 3. Callers **must** check `WalletStore::schema_version()` and refuse to operate when the result is less than `SCHEMA_VERSION_V3`; this prevents features like backup exports or RBAC provisioning from touching pre-migrated databases.【F:rpp/wallet/src/db/store.rs†L47-L64】【F:rpp/wallet/src/db/schema.rs†L4-L48】 Ensure the runtime or CLI opens the wallet once after upgrading so the buckets and metadata sentinels materialise before enabling those flows. Pair these checks with the [Wallet Operator Runbook](../../docs/wallet_operator_runbook.md), which captures the prerequisite inventory and acceptance tests that change-management teams require before promoting a schema or configuration change.

## Phase 2: What's new

Phase 2 introduces policy, fee, locking, and prover upgrades that require operator attention.【F:docs/wallet_phase2_policies_prover.md†L1-L71】 Highlights include:

* **Configurable spend policies** – Tune gap limits, minimum confirmations, dust limits, and daily spend caps via `wallet.policy.*`, and persist signed policy statements over RPC or `rpp-wallet policy set`.【F:docs/wallet_phase2_policies_prover.md†L5-L17】
* **Fee estimator revamp** – Automatic congestion-aware quotes with override validation and caching; use `rpp-wallet fees estimate` to sample current guidance before a send.【F:docs/wallet_phase2_policies_prover.md†L18-L27】
* **Pending lock tooling** – Deterministic locks guard draft inputs, backed by `rpp-wallet locks list|release` and tunable expiry via `wallet.policy.pending_lock_timeout`.【F:docs/wallet_phase2_policies_prover.md†L28-L38】
* **Targeted rescans** – `rpp-wallet rescan --from-height/--lookback-blocks` coordinates focused re-indexing while `wallet.rescan.*` governs automatic sweeps.【F:docs/wallet_phase2_policies_prover.md†L40-L45】
* **Pluggable prover backends** – Configure mock or STWO proofs with `wallet.prover.*` and the crate’s `prover-*` feature flags.【F:docs/wallet_phase2_policies_prover.md†L46-L55】

### Requirements & rollout checklist

* **Configuration:** Update `config/wallet.toml` (or environment-specific overlays) to set the new `wallet.policy`, `wallet.fees`, `wallet.rescan`, and `wallet.prover` keys. See [Wallet Phase 2 Policies & Prover Guide](../../docs/wallet_phase2_policies_prover.md) for detailed defaults and operational guidance.【F:docs/wallet_phase2_policies_prover.md†L1-L71】
* **Runtime restarts:** Changing policy, fee, or prover settings requires restarting the wallet runtime; there is no live reload yet.【F:config/wallet.toml†L1-L55】
* **Operational playbooks:** Extend on-call procedures with the troubleshooting steps for fee underruns, lock conflicts, and prover timeouts outlined in the Phase 2 guide.【F:docs/wallet_phase2_policies_prover.md†L57-L71】

### Feature flags

The crate ships with feature-gated prover integrations. Enable them via `cargo`:

* `prover-mock` (default) – Lightweight mock backend for development and CI.
* `prover-stwo` – STWO backend; requires `wallet.prover.enabled = true` in config to activate at runtime.
* `prover-stwo-simd` – STWO backend with SIMD acceleration; implies `prover-stwo`.

Refer to `Cargo.toml` for the complete flag graph and dependency list.【F:rpp/wallet/Cargo.toml†L7-L23】

### GUI unit tests

The iced wallet UI models and state machines are only compiled when the
`wallet_gui` feature flag is enabled. Run their unit tests explicitly with:

```
cargo test -p rpp-wallet --features wallet_gui
```

The CI `cargo xtask test-unit` entry point also enables `wallet_gui` to cover
these suites.【F:xtask/src/main.rs†L138-L171】

## Phase 3: GUI available (`wallet_gui`)

Phase 3 ships the optional iced-based GUI behind the `wallet_gui` feature flag.
See [Wallet Phase 3 – GUI Guide](../../docs/wallet_phase3_gui.md) for the MVU
architecture, tab flows, security affordances, error handling, and telemetry
coverage.【F:docs/wallet_phase3_gui.md†L1-L169】 Highlights for operators:

* **Feature flags** – Build with `--features "wallet_gui telemetry"` to enable
  the graphical shell and event reporting. Omit `telemetry` if metrics are not
  required.【F:docs/wallet_phase3_gui.md†L129-L141】
* **Launch command** – Start the GUI from the repo root with
  `cargo run -p rpp-wallet --features wallet_gui -- gui` after configuring the
  `[wallet.gui]` section in `config/wallet.toml`.【F:docs/wallet_phase3_gui.md†L133-L137】【F:config/wallet.toml†L1-L55】
* **Capabilities** – Multi-tab experience for overview, send, and prover
  workflows with policy-aware validation and prover progress tracking.【F:docs/wallet_phase3_gui.md†L60-L116】
* **Limitations** – The GUI depends on the existing JSON-RPC service, does not
  support hot policy edits, and inherits Phase 2 restart requirements after
  config changes.【F:docs/wallet_phase3_gui.md†L35-L56】【F:config/wallet.toml†L1-L55】
* **Validation** – Run GUI-focused tests via
  `cargo test -p rpp-wallet --features wallet_gui -- ui` or rely on
  `cargo xtask test-unit`, which already enables the flag.【F:docs/wallet_phase3_gui.md†L139-L147】【F:xtask/src/main.rs†L138-L171】

## Phase 4: Advanced operations

Phase 4 focuses on operational resiliency and secure integrations. See
[Wallet Phase 4 – Advanced Operations](../../docs/wallet_phase4_advanced.md) for the
complete rollout guide.【F:docs/wallet_phase4_advanced.md†L1-L176】 Highlights include:

* **Encrypted backups** – Deterministic archives with Argon2id passphrase policies and
  retention controls.【F:docs/wallet_phase4_advanced.md†L9-L33】
* **Watch-only projection** – Project balance state without spend keys for monitoring
  deployments.【F:docs/wallet_phase4_advanced.md†L35-L54】
* **Multisig hooks** – Register external coordinators and quorum policies for shared
  custody.【F:docs/wallet_phase4_advanced.md†L56-L78】
* **Zero State Import** – Bootstrap from vetted snapshots with checksum verification.【F:docs/wallet_phase4_advanced.md†L80-L97】
* **RPC hardening** – Opt-in mTLS and RBAC enforcement with certificate rotation guidance.【F:docs/wallet_phase4_advanced.md†L99-L138】
* **Hardware signing** – Optional HID/USB/TCP devices with safe fallback logic.【F:docs/wallet_phase4_advanced.md†L140-L168】

### Prerequisites

* **Schema version** – Run `rpp-wallet migrate` and confirm `WalletStore::schema_version()`
  reports 4 before enabling Phase 4 features.【F:docs/wallet_phase4_advanced.md†L170-L186】
* **Configuration** – Extend `config/wallet.toml` with the new `wallet.backup`,
  `wallet.watch_only`, `wallet.multisig`, `wallet.zsi`, `wallet.rpc.security`, and
  `wallet.hw` sections. Safe defaults keep features disabled until explicitly enabled.【F:config/wallet.toml†L1-L120】
* **Certificates** – Stage server and client certificates in the paths referenced by
  `[wallet.rpc.security]` before toggling mTLS or RBAC.【F:config/wallet.toml†L11-L36】【F:docs/wallet_phase4_advanced.md†L106-L124】

### Quickstart commands

```bash
# Export an encrypted backup (manual rotation)
cargo run -p rpp-wallet --features "backup" -- backup export --output ./backups/manual.rppb

# Restore from backup with policy enforcement
cargo run -p rpp-wallet --features "backup" -- backup restore --path ./backups/manual.rppb

# Launch watch-only daemon (read-only RPC)
cargo run -p rpp-wallet -- watch-only start

# Register multisig coordinator hooks
cargo run -p rpp-wallet --features "wallet_multisig_hooks" -- multisig register --config ./config/multisig.toml

# Import a ZSI bundle after staging checksums
cargo run -p rpp-wallet --features "wallet_zsi" -- zsi import --bundle ./zsi/bootstrap.tar.gz

# Start hardened RPC with GUI
cargo run -p rpp-wallet --features "wallet_gui wallet_rpc_mtls" -- gui --require-mtls

# Pilot hardware signing workflows
cargo run -p rpp-wallet --features "wallet_hw" -- hw test --transport hid
```

Ensure the CLI commands run from the repository root so cargo finds the workspace manifest.
When running the GUI with RPC security enabled, launch the daemon once with matching
certificate paths before opening the window.【F:docs/wallet_phase4_advanced.md†L99-L168】

### Feature flags

Phase 4 crates introduce additional cargo features alongside the prover and GUI options.
The wallet runtime also has configuration-only toggles (for example `[wallet.watch_only]`)
that do not correspond to cargo features. The table below lists the compile-time flags and
their runtime counterparts:

| Feature flag | Default | Related configuration | Notes |
| --- | --- | --- | --- |
| `runtime` | Enabled | All `[wallet.*]` sections | Required for the JSON-RPC service and background tasks. Disable only when building the CLI without a daemon.【F:rpp/wallet/Cargo.toml†L7-L32】 |
| `backup` | Enabled | `[wallet.backup]` | Provides backup CLI commands and hashing dependencies. Configuration alone controls automation windows; there is no `wallet_backup` flag.【F:config/wallet.toml†L17-L33】 |
| `wallet_multisig_hooks` | Disabled | `[wallet.multisig]` | Compiles the multisig RPC surface and CLI helpers. The runtime returns `WalletError::MultisigDisabled` when the config enables hooks but the feature is missing.【F:rpp/wallet/src/wallet/mod.rs†L358-L430】 |
| `wallet_zsi` | Disabled | `[wallet.zsi]` | Enables Zero State Import RPCs, CLI commands, and telemetry. Config toggles gate actual imports and checksum enforcement.【F:rpp/wallet/src/lib.rs†L77-L111】 |
| `wallet_rpc_mtls` | Disabled | `[wallet.rpc.security]`, `[wallet.security]` | Adds the mTLS/RBAC middleware as well as GUI/CLI controls. Without the flag, security sections error out during parsing.【F:rpp/runtime/config.rs†L3072-L3218】 |
| `wallet_hw` | Disabled | `[wallet.hw]` | Builds hardware wallet backends and CLI tests. The config section fails fast if the binary was built without the feature.【F:rpp/wallet/src/config/wallet.rs†L81-L96】 |
| `wallet_gui` | Disabled | `[wallet.gui]` | Compiles the iced GUI shell. Runtime configuration controls UX defaults and inactivity locks.【F:config/wallet.toml†L60-L84】 |

Use configuration toggles such as `[wallet.watch_only]`, `[wallet.backup]`, and
`[wallet.multisig]` to opt into behaviours at runtime after compiling with the relevant
features. There are no `wallet_watch_only`, `wallet_backup`, or `wallet_rpc_security`
features; those names refer to configuration scopes.

### Wallet feature matrix

`cargo xtask test-wallet-feature-matrix` runs `cargo check` and `cargo test` for the
following `rpp-wallet` build combinations:

1. Default features.
2. `runtime,prover-mock,backup` with `wallet_zsi` enabled.
3. `runtime,prover-mock,backup` with `wallet_multisig_hooks` enabled.
4. `runtime,prover-mock,backup` with `wallet_hw` enabled.
5. `runtime,prover-mock,backup` with `wallet_rpc_mtls` enabled.
6. `runtime,prover-mock,backup` with all wallet features enabled simultaneously.

The CI workflow runs this xtask on every pull request to surface integration issues when
features are enabled individually or combined.【F:.github/workflows/ci.yml†L551-L564】

### Troubleshooting & security considerations

* **Passphrase policies** – Keep `wallet.backup.passphrase_profile` on `argon2id` and require
  12+ character phrases with mixed classes. Rotate passphrases quarterly and store recovery
  material in sealed envelopes tracked by dual control logs.【F:docs/wallet_phase4_advanced.md†L15-L33】【F:docs/wallet_phase4_advanced.md†L188-L196】
* **Certificate management** – Maintain a short-lived internal CA, automate renewals with
  `rpp-wallet cert renew`, and restrict private keys to `0600` permissions. Document rotation
  playbooks alongside RBAC audits.【F:docs/wallet_phase4_advanced.md†L106-L138】【F:docs/wallet_phase4_advanced.md†L188-L196】
* **ZSI safety** – Keep `wallet.zsi.enabled` false outside import windows and ensure checksum
  verification stays enabled to prevent tampered bundles.【F:docs/wallet_phase4_advanced.md†L80-L97】
* **Hardware operations** – Leave `wallet.hw.fallback_to_software = true` until hardware health
  monitoring is in place; review `HardwareFallback` events for drift.【F:config/wallet.toml†L37-L110】【F:docs/wallet_phase4_advanced.md†L140-L168】
