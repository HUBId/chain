# Wallet troubleshooting catalog

Use this catalog to triage wallet alerts, RPC errors, and GUI issues before
escalating to engineering. Pair it with the operator runbook acceptance steps
and the wallet operations guide.

## Error codes and remediation

| Error / code | What it means | Remediation |
| --- | --- | --- |
| `WalletError::MultisigDisabled` | `[wallet.multisig]` was enabled without compiling the `wallet_multisig_hooks` feature, so multisig RPC/CLI calls abort immediately.【F:rpp/wallet/src/wallet/mod.rs†L50-L83】 | Rebuild with `--features wallet_multisig_hooks` or disable the config scope until the correct binary lands. Capture the new build hash in the release ticket. |
| `WatchOnlyError::SigningDisabled` / `WatchOnlyError::BroadcastDisabled` | Watch-only mode is still active, preventing signing/broadcast flows until the daemon restarts in hot-wallet mode.【F:rpp/wallet/src/wallet/mod.rs†L85-L107】 | Disable `[wallet.watch_only].enabled`, restart the runtime, and rerun the send/receive walkthrough to confirm normal mode returned. |
| `WalletError::HardwareFeatureDisabled` / `HardwareUnavailable` | Hardware signing was toggled in config or GUI without building with `wallet_hw` or without attaching the device.【F:rpp/wallet/src/wallet/mod.rs†L68-L83】 | Compile with `--features wallet_hw`, enable `[wallet.hw]`, and verify the configured transport/device selector sees the target hardware before retrying. |
| `RouterError::SyncUnavailable` | The `/wallet/sync_status` RPC or CLI sync helpers could not access the sync task handle (wallet not running or still booting).【F:rpp/wallet/src/rpc/mod.rs†L939-L990】 | Wait for the runtime to finish initialization or restart it; confirm `/health/ready` is green before reissuing sync queries. |
| `RouterError::RescanInProgress` / `RescanOutOfRange` | A rescan request overlapped with an active scan or targeted a height beyond the known chain head.【F:rpp/wallet/src/rpc/mod.rs†L992-L1033】 | Inspect the pending ranges in `wallet_sync_status`, wait for the current rescan to finish, or provide a lower `from_height`. |
| `RouterError::Backup(...)` | Backup export/import/validate operations failed because the underlying backup module returned an error (invalid passphrase, checksum mismatch, unwritable path).【F:rpp/wallet/src/rpc/mod.rs†L1035-L1143】 | Review the CLI error payload, ensure the passphrase confirmation matches, and confirm the destination directory inherits the correct permissions before retrying. |

## Health checks

1. **Service readiness** – `scripts/run_wallet_mode.sh` or your service manager
   should probe `/health/live` and `/health/ready` on the configured RPC host
   before declaring the deployment healthy.【F:scripts/run_wallet_mode.sh†L1-L47】
2. **Sync progress** – Call `/wallet/sync_status` (or `rpp-wallet sync status`)
   to ensure `latest_height`, checkpoints, and pending ranges advance. Use the
   `last_error` and `node_issue` fields when escalating sync stalls.【F:rpp/wallet/src/rpc/mod.rs†L939-L990】
3. **Policy + watch-only state** – Invoke `rpp-wallet watch-only status` and
   `rpp-wallet policy preview --draft <id>` to verify policy enforcement matches
   expectations before approving spends.
4. **Backup posture** – Run `rpp-wallet backup validate --path <archive>` on an
   isolated host to confirm archives decrypt and verify; failure returns a backup
   error code and should block rollout.【F:rpp/wallet/src/rpc/mod.rs†L1035-L1143】

## Self-diagnostics and escalation checklist

1. **Security envelope** – `rpp-wallet rbac lint` validates the RBAC bindings
   referenced by `[wallet.rpc.security]` before you enforce role checks. Pair it
   with TLS handshake logs collected via `RPP_WALLET_LOG_LEVEL=debug` per the
   Phase 4 guide.【F:docs/wallet_phase4_advanced.md†L124-L158】
2. **Telemetry and crash reports** – Use `rpp-wallet telemetry status` and
   `rpp-wallet telemetry crash-reports list|ack` to confirm whether metrics and
   crash uploads are enabled. Compare the output with `[wallet.telemetry]` and
   the crash-report guide to document opt-in/out decisions.【F:config/wallet.toml†L144-L168】【F:docs/wallet_crash_reporting.md†L1-L18】
3. **GUI sanity checks** – Follow the training guide overlays to capture fresh
   screenshots of the History, Send, Receive, and Node tabs whenever a GUI bug is
   reported; attach them to the incident ticket so reviewers can compare the
   rendered state with the documented contracts.【F:docs/training/wallet_operator_training.md†L58-L140】
4. **Regression safety net** – If repeated errors appear after an upgrade, rerun
   `make wallet-regression` plus the operator runbook acceptance suite to verify
   the feature matrix and guard rails are intact before escalating to engineering.【F:Makefile†L1-L20】【F:docs/wallet_operator_runbook.md†L68-L117】
5. **Hand-off package** – When opening an incident, include readiness probe
   output, the latest `wallet_sync_status`, relevant backup/log snippets, and a
   link to this troubleshooting catalog in the ticket so responders can continue
   the investigation without re-collecting basics.
