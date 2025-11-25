# Wallet operations guide

This guide supplements the wallet operator runbook with deployment patterns for
RPC hosting, security envelopes, log collection, backups, telemetry, and
readiness drills.

## RPC hosting models

* **Embedded service** – `scripts/run_wallet_mode.sh` launches the wallet via
  `rpp-node wallet …` and polls `/health/live` plus `/health/ready` before
  handing control back to operators. Use it for staging or single-node
  deployments before moving to service managers.【F:scripts/run_wallet_mode.sh†L1-L47】
* **Systemd/Launchd/Windows Service** – Packages install the `rpp-wallet-rpc`
  unit and hooks so the runtime listens on the `[wallet.rpc].listen` endpoint
  specified in `wallet.toml`. Always restart the service after editing the config
  because live reload is disabled.【F:INSTALL.wallet.md†L1-L38】【F:config/wallet.toml†L1-L20】
* **Remote RPC proxying** – When exposing the wallet beyond localhost, front it
  with the same reverse proxies used for node RPC and pin certificates to the
  wallet service account so TLS private keys never leave the host.

## mTLS and RBAC envelope

Phase 4 builds add optional mutual TLS and role-based access control around the
wallet RPC surface. Enable them together:

1. Set `wallet.rpc.security.mtls_required = true` and provide CA bundles,
   server cert, and private key paths. The runtime refuses unauthenticated
   clients when the feature flag `wallet_rpc_mtls` was compiled in.【F:docs/wallet_phase4_advanced.md†L124-L149】
2. Toggle `wallet.rpc.security.role_enforcement = true` and fill
   `wallet.rpc.security.role_bindings_path` with the RBAC mapping used by
   `rpp-wallet rbac lint` before deployment.【F:config/wallet.toml†L15-L37】
3. Set `[wallet.security]` bindings so GUI tokens, CLI tokens, or client
   certificates inherit the right roles for send, read-only, or backup actions.
4. Capture TLS handshake logs (set `RPP_WALLET_LOG_LEVEL=debug`) and include them
   in security change tickets.

## GUI security controls

* Enable `[wallet.gui].auto_lock_secs` and `clipboard_auto_clear` for all desktop
  deployments so idle windows relock and sensitive data does not linger in the
  clipboard.【F:config/wallet.toml†L61-L74】
* Stage GUI screenshots following the training overlays to prove the configured
  theme, tab states, and auto-lock flows rendered correctly on each platform.
* When hardware signing is required, ensure `wallet.hw.enabled = true` and set
  `device_selector` or `transport` as described in the Phase 4 guide so GUI send
  flows surface the device prompts.【F:docs/wallet_phase4_advanced.md†L158-L195】

## Log collection and retention

* STDOUT/ERR from `scripts/run_wallet_mode.sh` is the canonical log stream during
  staging and is controlled by `RPP_WALLET_LOG_LEVEL`. Redirect it to your log
  collector or `/var/log/rpp-wallet/*.log` for long-running services.【F:scripts/run_wallet_mode.sh†L1-L57】
* Production services should also forward `/var/log/journal` (Linux) or
  `~/Library/Logs/rpp-wallet.log` (macOS) entries tagged with the wallet unit so
  TLS, RBAC, and backup events are preserved.
* Attach log excerpts showing RPC binds, GUI unlocks, and backup exports to
  release tickets to satisfy the runbook acceptance checklist.【F:docs/wallet_operator_runbook.md†L80-L120】

## Backup rotation and recovery

* Configure `[wallet.backup]` with an export directory, passphrase profile, and
  `max_generations` that matches your retention policy. Automatic exports stay
  disabled until `auto_export_enabled = true` is set.【F:config/wallet.toml†L86-L105】
* Document manual `rpp-wallet backup export` runs plus periodic restore drills.
  Stage restore hosts with the same `[wallet.rpc.security]` settings to prove
  maintenance works while mTLS/RBAC are active.【F:docs/wallet_phase4_advanced.md†L12-L40】
* Ship backups off-host according to your compliance plan and record hashes in
  the change tracker so auditors can match archives to deployment notes.

## Telemetry, crash reports, and privacy

* `[wallet.telemetry]` controls Prometheus/OTLP and crash reporting. Leave
  `metrics = false`/`crash_reports = false` to opt out or set the `endpoint` and
  `machine_id_salt` fields when opting in.【F:config/wallet.toml†L144-L168】
* Crash reporting spools redacted stack traces under
  `<wallet.engine.data_dir>/crash_reports` and only uploads after operators
  acknowledge entries via CLI/GUI, as described in the crash reporting guide.【F:docs/wallet_crash_reporting.md†L1-L18】
* If telemetry is disabled, document the decision (`config diff` plus lack of
  listener logs) following the runbook’s opt-out instructions.【F:docs/wallet_operator_runbook.md†L120-L134】

## Upgrades and drills

* Run `make wallet-regression` (which wraps `cargo xtask test-wallet-feature-matrix`)
  before promoting a new build to prove every wallet feature combination compiles
  and passes guard checks.【F:Makefile†L1-L20】
* Execute the acceptance walkthrough in the wallet operator runbook (unlock,
  sync, send/receive, backup/restore, watch-only toggle, security envelope) for
  each release candidate.【F:docs/wallet_operator_runbook.md†L68-L117】
* Map drills and screenshots back to the UAT checklist so evidence stays
  centralized.【F:docs/wallet_uat_checklist.md†L3-L34】
* Run the pruning snapshot smoke test (`cargo xtask test-integration`) to prove
  that wallet backups survive directory wipes and restores. The test publishes
  `logs/wallet-pruning-snapshot/summary.json` so responders can review balances
  and submission counts without re-running the drill.【F:xtask/src/main.rs†L575-L604】【F:docs/testing/wallet_pruning_snapshot.md†L1-L29】

## Runbook drills and escalation

* Keep links to this guide, the operator runbook, and the troubleshooting catalog
  (`docs/troubleshooting/wallet.md`) in your on-call handbooks.
* During incidents, capture the command outputs referenced above plus GUI
  screenshots. Attach them to your incident log and reference the relevant
  troubleshooting section when paging additional teams.
