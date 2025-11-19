# Wallet platform support & validation matrix

This guide documents how the wallet CLI and GUI artifacts build and run on the
supported operating systems, including cross-compilation steps, smoke tests, and
OS-specific quirks. Pair it with the support policy so release engineers and
operators share the same expectations for deployment targets.【F:docs/wallet_support_policy.md†L1-L68】

## Build matrix and tooling

* **Authoritative bundles** – `cargo xtask wallet-bundle` builds the CLI
  (`rpp-wallet`) and GUI (`rpp-wallet-gui`) binaries with pinned feature sets,
  copies the sample configs, writes manifests, and emits per-target tarballs.
  Pass `--target <triple>` and `--tool <cargo|cross>` to compile Linux, macOS,
  or Windows bundles from any host.【F:xtask/src/wallet_bundle.rs†L40-L220】
* **Runtime launcher** – `rpp-wallet` (from `rpp/wallet-runner`) embeds the
  wallet mode inside `rpp-node`, exposes subcommands, and reuses the runtime
  options so both GUI and CLI builds share the same configuration entry points.
  Windows/macOS builds rely on the same CLI parsing surface.【F:rpp/wallet-runner/src/main.rs†L1-L40】
* **GUI entry point** – `rpp-wallet-gui` is gated behind the `wallet_gui` cargo
  feature; invoking the binary on a build without the feature exits with an
  explicit error so automated tests catch missing GUI support early.【F:rpp/wallet/src/ui/main.rs†L1-L40】

## Linux (x86_64/aarch64)

* **Build** – Use `cargo xtask wallet-bundle --target x86_64-unknown-linux-gnu \
  --profile release --version <tag>` to reproduce the CI bundle. Cross-compile
  `aarch64` builds locally via `--tool cross` when targeting ARM hosts.【F:xtask/src/wallet_bundle.rs†L40-L220】
* **Runtime directories** – Defaults place runtime state in `./data`, wallet
  engine data/keystores under `./data/wallet`, and audit logs in
  `wallet/audit/`. The runtime ensures these directories exist before starting
  so Linux package managers can drop configs into `/etc/rpp-wallet`.【F:config/wallet.toml†L1-L83】【F:rpp/runtime/config.rs†L3188-L3214】
* **Smoke tests** – The Linux CI suite runs the sync/rescan checkpoints test,
  fee-policy send/receive flows, and encrypted backup round-trips against mocked
  infrastructure (`tests/wallet_rescan_resume_e2e.rs`,
  `tests/wallet_policies_fee_e2e.rs`, `tests/wallet_backup_recovery_e2e.rs`).
  Each test boots the runtime, waits for mocked deposits, issues sends, and
  verifies policy enforcement so Linux remains the reference host.【F:tests/wallet_rescan_resume_e2e.rs†L1-L128】【F:tests/wallet_policies_fee_e2e.rs†L21-L118】【F:tests/wallet_backup_recovery_e2e.rs†L22-L130】
* **Quirks** – Clipboard auto-clear works on modern X11/Wayland desktops.
  Hardened terminals should run the CLI via `scripts/run_wallet_mode.sh` so
  readiness probes gate automation and logs capture the active mode.【F:docs/wallet_phase3_gui.md†L198-L208】【F:scripts/run_wallet_mode.sh†L1-L57】

## macOS (Apple Silicon & Intel)

* **Build** – Invoke `cargo xtask wallet-bundle --target aarch64-apple-darwin`
  (or `x86_64-apple-darwin`) from macOS hosts to produce notarization-ready
  tarballs. Cross-compiling from Linux is supported via `--tool cross` provided
  the corresponding SDK is installed.【F:xtask/src/wallet_bundle.rs†L40-L220】
* **Runtime behavior** – The GUI prompts for passphrases using foreground modal
  dialogs and enforces clipboard timeouts, aligning with the Phase 3 security
  UX spec so macOS users see the same lock/clipboard safeguards as Linux.
  Operators should enable the `wallet_gui` feature when building to expose these
  flows.【F:docs/wallet_phase3_gui.md†L198-L209】
* **Smoke tests** – Reuse the Linux smoke scripts; macOS builds run the same
  send/receive and backup tests via Rosetta or native arch when `wallet_gui`
  binaries are available. Document test runs in release tickets until CI adds
  native macOS runners.
* **Quirks** – System dialogs can steal focus when clipboard auto-clear runs.
  Keep `wallet.gui.clipboard_auto_clear` enabled (default) so the UI reminds
  operators to clear the clipboard when the OS refuses programmatic wipes.【F:config/wallet.toml†L61-L90】【F:docs/wallet_phase3_gui.md†L198-L206】

## Windows (x86_64-msvc)

* **Build** – Use the Windows runner (or `cross` from Linux) to build
  `--target x86_64-pc-windows-msvc` bundles. The CI job added in `.github/workflows/ci.yml`
  exercises `cargo build --locked -p rpp-wallet --features "runtime,wallet_gui,prover-stwo"`
  plus the runner binary so regressions surface before release (see the new
  `wallet-windows-build` job for reference).【F:.github/workflows/ci.yml†L1-L120】
* **Runtime behavior** – GUI and CLI binaries share the same configuration and
  key-directory defaults; the template writes keystores under
  `./data/wallet/keystore.toml` so Windows paths stay relative. Operators should
  override `wallet.engine.data_dir` to `%PROGRAMDATA%\RPP\wallet` in production
  and keep `fallback_to_software = true` while HID stacks stabilise.【F:config/wallet.toml†L1-L83】【F:docs/wallet_phase4_advanced.md†L140-L206】
* **Smoke tests** – Run the same init/sync/send flows on Windows by executing
  `rpp-wallet init`, `rpp-wallet sync-status`, and GUI send/receive workflows
  against mock data. Clipboard guards emit banner reminders when Windows API
  restrictions prevent auto-clear, so testers should verify the warning banner
  appears during acceptance.【F:docs/wallet_phase3_gui.md†L198-L206】
* **Quirks** – Windows console prompts do not inherit ANSI colors by default.
  Set `RPP_WALLET_LOG_LEVEL=info` to avoid control characters leaking in PowerShell.
  GUI scaling respects OS DPI but fonts may differ from Linux/macOS; confirm the
  wallet tabs render correctly before sign-off.

## Platform-specific defaults & configuration

* `[wallet.engine]` now records both `data_dir` and `backup_path` defaults, and
  the runtime ensures those directories exist on every platform before launching
  so installers can drop configs without pre-creating folders.【F:config/wallet.toml†L120-L152】【F:rpp/runtime/config.rs†L3188-L3214】
* GUI preferences store overrides next to the config or data directory (falling
  back to `./data/wallet/wallet-gui-settings.toml`), simplifying cross-platform
  backup/restore and making clipboard or telemetry settings portable.【F:rpp/wallet/src/ui/preferences.rs†L60-L120】

## Smoke-test checklist

1. **Init & unlock** – Run `rpp-wallet init` plus GUI unlock on each platform to
   verify keystore prompts and passphrase double-confirmations still match the
   Phase 3 UX requirements.【F:docs/wallet_phase3_gui.md†L198-L206】
2. **Sync mock data** – Execute the rescan/resume suite to confirm checkpoints
   and node hints behave identically on every OS.【F:tests/wallet_rescan_resume_e2e.rs†L1-L128】
3. **Receive/send** – Re-run the fee-policy and send workflows to validate
   policy enforcement, mempool hints, and prover round-trips.【F:tests/wallet_policies_fee_e2e.rs†L21-L118】
4. **Backup/restore** – Export and import encrypted backups to ensure directory
   permissions and keystore paths remain portable across hosts.【F:tests/wallet_backup_recovery_e2e.rs†L22-L130】

Capture the command transcripts or GUI screenshots for each OS and attach them
to release tickets so reviewers can audit the coverage before promoting a tag to
LTS.【F:docs/wallet_support_policy.md†L1-L68】
