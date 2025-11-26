# Wallet Operator Runbook

This runbook codifies the prerequisites, configuration validation, feature-flag
checks, acceptance walkthrough, and troubleshooting flows required to promote an
RPP wallet deployment. It assumes familiarity with the sample configuration at
`config/wallet.toml`, the Phase 4 capabilities described in the advanced
operations guide, and the orientation material in the
[Wallet Operator Training Guide](./training/wallet_operator_training.md).

## 1. Prerequisite inventory

1. **Data and key directories** – Confirm the wallet data directory, keystore,
and backup folders exist on the target host (defaults under `./data`,
`./data/wallet/keystore.toml`, and `./backups`).【F:config/wallet.toml†L5-L83】
2. **RPC binding and security artifacts** – Stage certificates, CA bundles,
RBAC bindings, and optional HTTP auth tokens referenced under
`[wallet.rpc]`, `[wallet.rpc.security]`, and `[wallet.security]`. Do not enable
mTLS or RBAC until the files resolve and permissions are correct.【F:config/wallet.toml†L10-L37】
3. **Hardware dependencies** – Provision HID/USB/TCP access and leave
`wallet.hw.fallback_to_software = true` until monitoring catches `HardwareFallback`
alerts during staging drills.【F:config/wallet.toml†L47-L55】【F:docs/wallet_phase4_advanced.md†L140-L159】
4. **Feature-complete binaries** – Ensure the build includes the features needed
for the deployment (`wallet_multisig_hooks`, `wallet_zsi`, `wallet_rpc_mtls`,
`wallet_hw`, `wallet_gui`, etc.). The Phase 4 guide lists the full matrix of
feature flags, how they pair with configuration scopes, and the CI xtask that
validates every combination.【F:docs/wallet_phase4_advanced.md†L160-L184】
5. **Telemetry opt-in** – Decide whether to publish metrics through Electrs or
   external scrapes. Enable `[electrs.cache.telemetry]` or
   `[electrs.tracker.telemetry_endpoint]` only when the observability stack is
   reachable, and plan Prometheus/OTLP endpoints per the telemetry overview.【F:config/wallet.toml†L144-L168】【F:docs/telemetry.md†L1-L68】
6. **Monitoring hand-off** – Link the deployment ticket to the
   [`wallet_monitoring.md`](wallet_monitoring.md) guide so on-call responders know
   which dashboards (sync, fee estimator, prover, RBAC) and alert thresholds to
   watch during rollout. Capture which Grafana folders host the Wallet Intake/
   Proof Validation exports listed in the guide.【F:docs/wallet_monitoring.md†L1-L70】
7. **Platform references** – Attach the relevant OS install guide under
   `docs/install/`, the [wallet operations guide](operations/wallet.md), and the
   [troubleshooting catalog](troubleshooting/wallet.md) to every rollout ticket
   so responders have the RPC/mTLS, log, and error-code references at hand.

## 2. Configuration validation checklist

1. **Schema and migration gating** – Run `rpp-wallet migrate` once after a
binary upgrade and refuse to proceed unless `WalletStore::schema_version()`
reports the Phase-appropriate level (≥ 3 for baseline backups/RBAC, ≥ 4 for
Phase 4). Keep the CLI output with change tickets so migrations remain auditable
and reference this runbook for the acceptance evidence.【F:rpp/wallet/README.md†L5-L95】
2. **Configuration diffs** – Validate that overlays kept in Git or your secrets
manager include all `[wallet.backup]`, `[wallet.watch_only]`, `[wallet.multisig]`,
`[wallet.zsi]`, `[wallet.hw]`, and `[wallet.rpc.security]` sections. Missing
sections revert to the defaults shown in `config/wallet.toml`, which disable the
features entirely.【F:config/wallet.toml†L70-L110】
3. **Budget alignment** – Confirm throughput caps such as
`wallet.budgets.submit_transaction_per_minute` and `wallet.budgets.pipeline_depth`
match operational expectations before launch to avoid throttling surprises.
Adjust as needed with the same restart guard noted atop the sample config.【F:config/wallet.toml†L56-L74】
4. **Node embedding** – Decide whether to embed a node (`[node].embedded = true`)
or point to remote gossip endpoints. Validate `gossip_endpoints` by probing
reachability before unlocking the wallet.【F:config/wallet.toml†L140-L143】

## 3. Feature-flag verification

1. **Build-time audit** – Record the `cargo build` command (including
`--features` arguments) that produced the binary. Compare the feature list
against the Phase 4 feature table to ensure every requested capability is backed
by a compiled feature and configuration toggle.
2. **Runtime smoke test** – Launch the wallet through `scripts/run_wallet_mode.sh`
with `RPP_WALLET_LOG_LEVEL=debug` so startup logs capture the active feature
flags. The helper script passes the log level to `rpp-node wallet` when no
`--log-level` flag is set and monitors the `/health/live` and `/health/ready`
endpoints for readiness.【F:scripts/run_wallet_mode.sh†L9-L57】
3. **CLI surface** – Invoke `rpp-wallet --help` plus flag-specific subcommands
   (e.g., `multisig`, `zsi`, `hw`) to confirm the CLI exposes the flows enabled in
   configuration. Missing commands indicate a feature mismatch (for example,
   `WalletError::MultisigDisabled` when `wallet_multisig_hooks` was not compiled).【F:rpp/wallet/src/wallet/mod.rs†L50-L95】【F:docs/wallet_phase4_advanced.md†L60-L89】

4. **Dashboard alignment** – While the runtime is running, open the sync/prover
   panels referenced in `wallet_monitoring.md` and confirm the metrics (`rpp.runtime.wallet.*`)
   reflect the current deployment. Save screenshots with the acceptance evidence
   so responders know which Prometheus labels map to the node you’re rolling out.【F:docs/wallet_monitoring.md†L1-L70】

## 4. Feature-flag and configuration acceptance test

Perform the following steps whenever promoting a wallet build. Capture terminal
output, log excerpts, and screenshots (for GUI flows) to satisfy audit trails.

1. **Unlock and auto-lock** – Start the runtime, unlock the keystore, and ensure
the GUI or CLI respects `[wallet.gui].auto_lock_secs` (default 300 s).【F:config/wallet.toml†L61-L74】
2. **Sync and chain head verification** – Observe the sync task until
`wallet_sync_status` reports the target height. Confirm `wallet.engine.birthday_height`
when restoring from older seeds to avoid missing historical deposits. If synced height stalls or lags the chain tip by >20 blocks, jump to the lag investigation workflow in §6 before retrying a restart.【F:docs/wallet_phase4_advanced.md†L55-L57】
3. **Receive funds** – Derive a new external address via `rpp-wallet address new`
or GUI equivalent, send a regtest transfer, and watch Electrs indexers produce a
new digest with proof/VRF metadata. Use the tracker scenario as a reference for
expected audit envelopes (`proof.envelope`, `vrf.output.randomness`).【F:rpp/wallet-integration-tests/tests/vendor_electrs_tracker_scenario.rs†L127-L287】
4. **Send funds** – Draft a spend with policy-compliant amounts. Ensure policy
evaluations propagate to the UI/RPC when exceeding tier limits as described in
the wallet operations guide, and that the prover completes with the expected
backend (mock vs. STWO).【F:docs/wallet/operations.md†L1-L24】
5. **Backup export** – Trigger `rpp-wallet backup export` (manual) or force an
auto-export if `wallet.backup.auto_export_enabled = true`. Verify the archive is
written under `wallet.backup.export_dir` with the configured passphrase profile
(Argon2id by default).【F:docs/wallet_phase4_advanced.md†L9-L36】【F:config/wallet.toml†L75-L83】
6. **Restore drill** – Import the archive on an isolated host using
`rpp-wallet backup restore --path <file>` and confirm checksum/passphrase
validation occurs. Reject any restore that attempts to skip the current profile
in production.【F:docs/wallet_phase4_advanced.md†L19-L36】
7. **Watch-only projection** – Toggle `[wallet.watch_only].enabled = true` with
an exported xpub and restart the daemon. Confirm RPC responses label accounts as
`watch_only` and that attempts to sign or broadcast return the expected
`WatchOnlyError::{SigningDisabled,BroadcastDisabled}` codes, proving that spends
are blocked.【F:docs/wallet_phase4_advanced.md†L40-L58】【F:rpp/wallet/src/wallet/mod.rs†L59-L210】
8. **Send/receive after watch-only disable** – Restore the hot wallet mode and
repeat send/receive to ensure disabling watch-only clears the restrictions.
9. **Security envelope** – Enable `[wallet.rpc.security]` (mTLS/RBAC) and
`[wallet.security]` bindings, restart, and verify mutual TLS handshakes succeed.
Observe the wallet log for `tls::Error` if the handshake fails; confirm RBAC
responses align with the configured roles and that unauthorized calls emit
`401/403` responses with audit entries in the RBAC logbook.【F:docs/wallet_phase4_advanced.md†L109-L140】【F:config/wallet.toml†L15-L37】
10. **Backup/restore in hardened mode** – Repeat the export/restore while mTLS
and RBAC are enabled to ensure the security middleware does not block maintenance
flows.
11. **Hardware signing (optional)** – When `[wallet.hw].enabled = true`, run
`rpp-wallet hw test` to exercise the selected transport and ensure `HardwareUnavailable`
or `HardwareDisabled` errors do not appear during normal sends.【F:config/wallet.toml†L47-L55】【F:rpp/wallet/src/wallet/mod.rs†L68-L82】
12. **Regression validation** – Run `make wallet-regression` to execute
`cargo xtask test-wallet-feature-matrix` across the supported feature sets and the
wallet feature guards before shipping artifacts. Capture the test log and attach
it to the change record.【F:Makefile†L1-L40】

## 5. Key rotation drills

1. **Hot→cold→hot rotation** – Transition the daemon into watch-only mode to
   simulate removal of the hot key, confirm signing/broadcast attempts return
   `WatchOnlyError::{SigningDisabled,BroadcastDisabled}`, then re-enable the hot
   wallet and submit a fresh draft to prove nonces/locks continue to advance
   after the rotation.【F:tests/wallet_key_rotation_e2e.rs†L1-L124】
2. **Missing key detection** – Exercise a watch-only rotation without an xpub to
   confirm the runtime surfaces the "signing disabled" guard instead of falling
   back to a partially configured keyring.【F:tests/wallet_key_rotation_e2e.rs†L126-L170】
3. **Outdated key handling** – Rotate to an intentionally stale cold profile
   (birthday height ahead of the indexed tip) and verify broadcasts are blocked
   with the same watch-only guard until the hot key is restored.【F:tests/wallet_key_rotation_e2e.rs†L149-L170】
4. **Runbook evidence** – Capture CLI logs for the enable/disable operations and
   attach them alongside the regression test output so responders can trace the
   rotation attempt and the expected error paths.

## 6. Troubleshooting quick reference

| Symptom | Likely cause | Remediation |
| --- | --- | --- |
| `WalletError::MultisigDisabled` surfaced by RPC/CLI | Binary was not compiled with `wallet_multisig_hooks` while `[wallet.multisig].enabled = true` | Rebuild with the feature flag or disable the config scope until the next deploy.【F:rpp/wallet/src/wallet/mod.rs†L358-L436】 |
| `WatchOnlyError::SigningDisabled` or `WatchOnlyError::BroadcastDisabled` when attempting to send | Watch-only mode still active or the daemon failed to reload after toggling config | Disable watch-only, restart the runtime, and confirm the lock screen clears before retrying.【F:rpp/wallet/src/wallet/mod.rs†L59-L210】 |
| `WalletError::HardwareFeatureDisabled` / `HardwareUnavailable` | Binary lacks `wallet_hw` or `[wallet.hw].enabled` remains false | Rebuild with `--features wallet_hw` and enable the config scope once devices are connected.【F:rpp/wallet/src/wallet/mod.rs†L68-L82】【F:config/wallet.toml†L47-L55】 |
| TLS handshake failures in logs | CA chain, certificate paths, or RBAC bindings mismatched | Inspect the wallet log (`RPP_WALLET_LOG_LEVEL=debug`) and re-stage certificates per the Phase 4 RPC security section.【F:docs/wallet_phase4_advanced.md†L109-L140】【F:scripts/run_wallet_mode.sh†L12-L47】 |
| Wallet height is >20 blocks behind chain tip or last sync success >10 m ago | Gossip endpoints unreachable, stalled tracker, or telemetry/probe mismatch | Compare `/health/ready` heights against Grafana’s `rpp.runtime.wallet.sync.*` panels (see `wallet_monitoring.md`). If both show lag, test gossip endpoints and node reachability, then trigger a controlled restart. If probes show current height but metrics lag, treat as scrape/OTLP drift and re-scrape before restarting. |
| Sync stalls / `RouterError::Sync` codes | Node gossip endpoints unreachable or birthday height mis-set | Verify `[node].gossip_endpoints` connectivity and adjust `wallet.engine.birthday_height` before rescanning.【F:config/wallet.toml†L107-L143】【F:docs/wallet_phase4_advanced.md†L55-L57】 |

Reference the [wallet troubleshooting catalog](troubleshooting/wallet.md) for a
longer list of RPC/CLI error codes, health checks, and diagnostic commands.

Lag alerts raised from `wallet_monitoring.md` should always run through the health-probe workflow below so responders can distinguish real catch-up issues from telemetry drift before recycling the process.

**Health probes** – `/health/ready` now includes wallet-specific booleans:
`wallet_signer_ready` (watch-only or signer failures), `wallet_connected`
(runtime attached to a node), and `wallet_key_cache_ready` (keystore present).
When those three values are all `true`, the payload also exposes
`wallet_synced_height`, `wallet_chain_tip`, `wallet_sync_lag`, and
`wallet_last_sync_timestamp` so operators can confirm the daemon is caught up
and quantify drift before accepting traffic. Use the probes as the first step of
the lag workflow:

1. Compare `wallet_synced_height` vs. `wallet_chain_tip` and the reported `wallet_sync_lag`; treat >20 blocks for >5 m as actionable lag.
2. Check `wallet_last_sync_timestamp`; if older than 10 m and `wallet_connected=false`, test gossip endpoints and node RPC reachability before restarting.
3. Cross-check Grafana’s `rpp.runtime.wallet.sync.*` panels; if probes show current height but metrics lag, re-run scrapes/OTLP exporters before restarting the wallet.
4. After connectivity is restored, restart the runtime once, monitor the lag panel for a descending trend, and only escalate to a rescan when lag increases or plateaus for two consecutive intervals.

**Log locations** – When running via `scripts/run_wallet_mode.sh`, STDOUT/ERR is
the primary log stream. Override `RPP_WALLET_LOG_LEVEL` or pass
`--log-level debug` to surface TLS, RBAC, and sync traces. Redirect the process
output to `/var/log/rpp-wallet/*.log` (or your platform convention) during
long-lived deployments and include timestamps in collection pipelines.【F:scripts/run_wallet_mode.sh†L12-L57】
See the [wallet operations guide](operations/wallet.md#log-collection-and-retention)
for platform-specific log shipping and retention recommendations.

## 7. Audit log review & telemetry verification

1. **Proof/VRF audit trail** – The Electrs tracker embeds proof envelopes and
VRF audit objects in transaction metadata. Use `rpp-wallet history` or the GUI
to inspect entries and verify they mirror the expected envelope hashes and VRF
randomness as illustrated by the tracker scenario test.
Capture these records during acceptance so auditors can compare production
entries with the reference digest path.【F:rpp/wallet-integration-tests/tests/vendor_electrs_tracker_scenario.rs†L127-L287】
2. **RBAC and token audit** – Changes to `wallet.rpc.security.role_bindings_path`
and `[wallet.security.bindings]` must be recorded alongside this runbook and the
`rpp-wallet rbac lint` output to prove the bindings were verified before
deployment.【F:config/wallet.toml†L15-L37】
3. **Telemetry opt-in** – When telemetry is enabled, validate that the endpoints
emit metrics matching the telemetry overview. For Electrs and wallet tracker
integrations, confirm `telemetry_endpoint` values respond on their configured
ports and capture sample scrapes for change tickets.【F:config/wallet.toml†L152-L168】【F:docs/telemetry.md†L1-L68】

## 8. Telemetry opt-out verification

If telemetry remains disabled, document the decision by capturing `config diff`
output showing `enabled = false` under `[electrs.cache.telemetry]` and
`[electrs.tracker]`. Attach the logs from a wallet launch proving no telemetry
listener was bound (absence of `Listening on …telemetry…` messages).

## 9. Reorg handling playbook

1. **Detect divergence quickly** – Keep the wallet RPC `sync_status` panel on the
   dashboard during deployments. A sudden drop in `latest_height` paired with a
   rescan request indicates a reorg is underway. Encourage operators to cross
   check the node tip hash before retrying submissions so they avoid replaying
   transactions on an outdated fork.【F:docs/wallet_monitoring.md†L24-L53】
2. **Pause outbound flows** – When a reorg is detected, pause CLI or REST
   submissions and let the wallet finish its automatic rescan. Pending locks
   should clear once the reorged height is rescanned; retry drafts only after
   `mode = Rescan` transitions back to `Resume` in the sync status view.
3. **Confirm balances and nonces** – After the rescan, run `rpp-wallet balance`
   or the REST `wallet.balance` call to confirm spendable funds reflect the new
   chain. Draft lock identifiers should advance when you rebuild a payment,
   proving nonces were recalculated on the post-reorg tip.
4. **Escalate lingering divergence** – If pending locks remain or the sync mode
   sticks on `Rescan`, restart the wallet with increased log verbosity and file
   a ticket with the rescan range and tip hashes attached. Capture the RPC
   responses from `sync_status`, `pending_locks`, and the node head to speed up
   incident triage.

## 10. Regression automation hook

The repository ships a lightweight regression target for wallet operators:

```sh
make wallet-regression
```

This wraps `cargo xtask test-wallet-feature-matrix` so you can prove the build
supports every wallet feature combination and the guard coverage before
promoting an artifact. Only the `rpp-wallet` feature matrix is exercised,
keeping runtime short while still providing coverage evidence for change
control boards.【F:Makefile†L1-L40】
