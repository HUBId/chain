# Wallet Operator Training Guide

**Scope:** This guide orients new wallet operators before they dive into the
phase-specific runbooks. Pair it with the configuration sample
(`config/wallet.toml`), the Phase 4 advanced operations reference, and the
Wallet Operator Runbook for change-control evidence.【F:config/wallet.toml†L1-L178】【F:docs/wallet_phase4_advanced.md†L1-L200】【F:docs/wallet_operator_runbook.md†L1-L168】

## 1. Architecture overview

* **Runtime layers** – The wallet process orchestrates embedded node services,
  Electrs trackers, and proof backends through configuration scopes such as
  `[wallet.rpc.*]`, `[wallet.hw]`, `[wallet.watch_only]`, and `[wallet.backup]`.
  Feature gates (`wallet_multisig_hooks`, `wallet_rpc_mtls`, `wallet_hw`, etc.)
  must match the enabled scopes to avoid runtime guards (`WalletError::*`).【F:config/wallet.toml†L27-L145】【F:docs/wallet_phase4_advanced.md†L68-L142】
* **Security envelope** – Phase 4 adds mTLS/RBAC for JSON-RPC, RBAC token
  bindings, hardened backup formats, hardware signing, and watch-only flows.
  Operators stage CA bundles, certificates, and RBAC bindings before enabling
  the scopes documented under `wallet.rpc.security` and `wallet.security`.【F:docs/wallet_phase4_advanced.md†L109-L199】【F:config/wallet.toml†L27-L55】
* **Telemetry pipeline** – Heartbeats export consensus, mempool, and peer data
  via `/validator/*` endpoints while Electrs trackers report proofs and VRF
  metadata. Prometheus/OTLP taps stay disabled until `[electrs.*.telemetry]
  enabled = true` and the telemetry overview’s binding guidance is followed.【F:docs/telemetry.md†L3-L95】【F:config/wallet.toml†L152-L178】

## 2. Daily operations

### 2.1 Startup and readiness

1. Launch the runtime with `scripts/run_wallet_mode.sh --config <path>` so the
   helper enforces health checks on `/health/live` and `/health/ready`, applies
   `RPP_WALLET_LOG_LEVEL`, and surfaces TLS/RBAC traces when `--log-level` is
   omitted.【F:scripts/run_wallet_mode.sh†L9-L58】
2. Record the `cargo build` command (features and target triple) plus
   `config/wallet.toml` diffs inside change tickets per the runbook’s migration
   guard section.【F:docs/wallet_operator_runbook.md†L16-L74】
3. Confirm budgets such as `wallet.budgets.submit_transaction_per_minute` and
   `pipeline_depth` align with the day’s volume plan before the next unlock.
   Restart the runtime after edits because live reload is not supported.【F:config/wallet.toml†L1-L83】

### 2.2 Health/telemetry drill

* **Pipeline/consensus visibility** – The dashboard polls `/validator/status`,
  `/validator/proofs`, `/validator/peers`, `/validator/telemetry`, and the
  wallet UI contracts so operators can verify consensus receipts, proof queues,
  peer latency, and wallet state without curling each endpoint manually.【F:validator-ui/src/App.tsx†L9-L55】【F:validator-ui/src/components/WalletTabs.tsx†L20-L120】
* **Telemetry checkpoints** – Compare `telemetry.rollout.feature_gates` vs.
  desired posture, ensure `telemetry.telemetry.enabled` remains true when OTLP
  exports are expected, and confirm Prometheus scrapes reach the configured
  `listen` port if you opt in to metrics.【F:docs/telemetry.md†L3-L95】【F:config/wallet.toml†L152-L178】
* **Acceptance cadence** – Re-run the runbook smoke (unlock, send, receive,
  backup, restore, watch-only toggle, security envelope) whenever binaries or
  feature gates change to keep audit evidence fresh.【F:docs/wallet_operator_runbook.md†L80-L111】

## 3. GUI workflows with reproducible callouts

> **Why no embedded PNGs?** The repository disallows binary artifacts, so the
> guide ships textual overlays instead. When training operators, launch the
> wallet UI by building/running the Docker image in `validator-ui/README.md` and
> take local screenshots. Use the callout tables below to annotate those
> captures consistently before distributing decks or tabletop drills.【F:validator-ui/README.md†L1-L33】

### 3.1 History tab

```
[1] ┌─────────────── History ───────────────┐   [2]
    |  Pending   Confirmed   Pruned        |
    |  txn rows + tracker metadata         |
[3] └──────────────────────────────────────┘
```

| Callout | UI element | Operational notes |
| --- | --- | --- |
| 1 | Tab selector | Confirms which workflow is active; when the auto-lock fires the selector greys out until you unlock again (ties back to `[wallet.gui].auto_lock_secs`).【F:config/wallet.toml†L73-L85】 |
| 2 | Status badges | Track `Pending/Confirmed/Pruned` and highlight pipeline alerts (`timed_out`, `double_spend`, conflicts) per the UI history contract. |
| 3 | Tracker summary | Mirrors Electrs tracker metadata (`script_metadata`, `tracker.mempool_fingerprint`) for proof/VRF audit capture.【F:validator-ui/src/components/WalletTabs.tsx†L43-L116】 |

### 3.2 Send tab

```
[1] Recipient + memo inputs
[2] Amount / fee sliders + policy guard rails
[3] Preview drawer showing nonce + balance deltas
```

| Callout | UI element | Operational notes |
| --- | --- | --- |
| 1 | Recipient & memo inputs | Respect validation in the send contract; the UI blocks empty addresses or invalid numbers before calling the preview RPC. |
| 2 | Amount & fee controls | Keep amounts within `[wallet.policy]` limits and align fees with `[wallet.fees]` defaults before escalating for overrides.【F:config/wallet.toml†L129-L140】 |
| 3 | Preview drawer | Shows nonce/balance deltas from `/wallet/ui/send/preview` so you can log acceptance artifacts prior to signing.【F:validator-ui/src/components/WalletTabs.tsx†L118-L210】 |

### 3.3 Receive tab

```
Header → contract/version banner [1]
Address list w/ derivation indices [2]
QR payload + rpp: URI preview [3]
```

| Callout | UI element | Operational notes |
| --- | --- | --- |
| 1 | Contract version | Confirms the UI contract matches the runtime build. |
| 2 | Derivation indices | Use to reconcile addresses when watch-only instances are enabled (`[wallet.watch_only]`).【F:config/wallet.toml†L96-L103】 |
| 3 | QR payload | Provides `rpp:` URIs with index hints for mobile capture or manual channel verification.【F:validator-ui/src/components/WalletTabs.tsx†L212-L258】 |

### 3.4 Node tab

```
[1] Local metrics pane (tier, uptime, block counters)
[2] Consensus receipt mirror of /validator/status
[3] Pipeline flow grid showing submission state
```

| Callout | UI element | Operational notes |
| --- | --- | --- |
| 1 | Local metrics | Reputation, tier, uptime, and block counters derived from the node contract keep you ahead of health alerts. |
| 2 | Consensus receipt | Mirrors `/validator/status` so you can verify the latest proposer/height/round from the wallet UI during incident calls.【F:validator-ui/src/components/WalletTabs.tsx†L260-L344】 |
| 3 | Pipeline flows | Snapshot of orchestrated submissions; match hashes and nonces against pipeline alerts before escalating timeouts.【F:validator-ui/src/components/WalletTabs.tsx†L266-L344】 |

## 4. Command & RPC quick reference

| Workflow | Command/RPC | Purpose |
| --- | --- | --- |
| Migration gate | `rpp-wallet migrate` (per runbook) | Ensures schema ≥ Phase 4 before enabling new scopes; capture CLI output for change tickets.【F:docs/wallet_operator_runbook.md†L16-L42】 |
| Manual backup | `rpp-wallet backup export` | Writes encrypted archives to `wallet.backup.export_dir` with Argon2id policy; store hash in audit log.【F:docs/wallet_phase4_advanced.md†L18-L36】【F:config/wallet.toml†L87-L95】 |
| Restore drill | `rpp-wallet backup restore --path <file>` | Verifies checksum/passphrase policy and documents recovery readiness.【F:docs/wallet_phase4_advanced.md†L19-L36】 |
| Watch-only toggle | Edit `[wallet.watch_only]` + restart | Deploy read-only projections or revert to hot wallet flows; confirm RPCs surface `watch_only` flag and signing is blocked.【F:docs/wallet_phase4_advanced.md†L68-L89】 |
| ZSI | `rpp-wallet zsi verify/import --bundle <path>` | Validate signatures then import Zero State bundles before first sync.【F:docs/wallet_phase4_advanced.md†L48-L58】 |
| Multisig | `rpp-wallet multisig cosigners list|set`, `multisig scope get` | Manage quorum definitions and cosigners once the `wallet_multisig_hooks` feature is compiled in.【F:docs/wallet_phase4_advanced.md†L90-L117】 |
| Security audit | `rpp-wallet rbac lint` + RBAC log export | Proves role bindings match certificates/tokens before enabling enforcement.【F:docs/wallet_operator_runbook.md†L132-L146】 |
| UI contracts | `GET /wallet/ui/{history,receive,node}` | Fetch the same JSON the GUI renders for scripting or headless checks.【F:validator-ui/src/components/WalletTabs.tsx†L100-L344】 |

## 5. Security practices

* **mTLS/RBAC sequencing** – Stage CA directories, server certs, private keys,
  and `role_bindings_path` entries before flipping `mtls_required`/`role_enforcement`
  flags; watch the logs for `tls::Error` immediately after restart.【F:config/wallet.toml†L27-L55】【F:docs/wallet_phase4_advanced.md†L156-L190】
* **Hardware signing** – Keep `wallet.hw.fallback_to_software = true` until the
  device fleet is stable and telemetry watches for `HardwareFallback` events;
  run `rpp-wallet hw test` during maintenance windows.【F:config/wallet.toml†L59-L67】【F:docs/wallet_phase4_advanced.md†L190-L199】
* **Backups & ZSI** – Enforce Argon2id passphrase profiles, retain at least
  three generations, and practice restore drills on isolated hosts before
  relying on the archives in production.【F:docs/wallet_phase4_advanced.md†L18-L65】
* **Watch-only segregation** – Treat exported xpubs as sensitive metadata even
  though they do not permit spending; restrict RPC exposure until downstream
  consumers are ready.【F:docs/wallet_phase4_advanced.md†L68-L89】

## 6. Logs & telemetry interpretation

* **Primary log stream** – `scripts/run_wallet_mode.sh` routes STDOUT/ERR and
  allows `RPP_WALLET_LOG_LEVEL` overrides; redirect to `/var/log/rpp-wallet/`
  (or platform-specific targets) for long-lived services.【F:scripts/run_wallet_mode.sh†L12-L57】【F:docs/wallet_operator_runbook.md†L126-L130】
* **Audit artifacts** – Capture Electrs tracker proofs/VRF randomness from the
  history view or `rpp-wallet history`, archive RBAC binding diffs plus
  `rpp-wallet rbac lint`, and store telemetry opt-in/out evidence alongside the
  runbook per release.【F:docs/wallet_operator_runbook.md†L132-L150】
* **Telemetry decoding** – `NodeMetrics` and `MetaTelemetryReport` export block
  height, verifier metrics, peer IDs, and latency stats; Prometheus collectors
  attach via `[rollout.telemetry.metrics]` when enabled. Cross-check dashboards
  with the telemetry overview before closing incidents.【F:docs/telemetry.md†L3-L95】

## 7. Troubleshooting & escalation

1. **Common error codes** – Reference the quick table in the runbook for
   `WalletError::MultisigDisabled`, `WatchOnlyError::*`, hardware guards, TLS
   handshakes, and sync stalls. The remedies explain whether to rebuild with the
   correct feature flag, toggle config scopes, or fix CA bindings before
   retrying.【F:docs/wallet_operator_runbook.md†L118-L130】
2. **Audit logs** – Persist Electrs proof envelopes, RBAC binding updates, and
   telemetry opt-in/out evidence in the audit trail so compliance can reproduce
   readiness artifacts. The RBAC logbook must capture every role change when
   `wallet.rpc.security.role_enforcement = true`.【F:docs/wallet_operator_runbook.md†L132-L146】
3. **Diagnostics for support** – When incidents persist after local triage,
   bundle:
   * Recent wallet logs (with `--log-level debug`),
   * `config/wallet.toml` deltas covering `[wallet.rpc.security]`, `[wallet.hw]`,
     `[node]`, and `[wallet.budgets]`,
   * Outputs from `/validator/status`, `/wallet/ui/node`, and telemetry scrapes,
   * Evidence from the validator troubleshooting guide (VRF checks, snapshot
     probes, telemetry toggles) before paging engineering.【F:docs/validator_troubleshooting.md†L1-L138】
4. **Escalation triggers** – Engage the on-call or release manager if VRF
   mismatches persist after key rotation, snapshots fail to advance despite disk
   capacity, or telemetry outages exceed two sampling intervals. Include the
   diagnostics above to accelerate RCA.【F:docs/validator_troubleshooting.md†L126-L138】

## 8. Telemetry & support hand-off checklist

Use this list during onboarding sessions and quarterly drills:

- [ ] Health scripts: demonstrate `scripts/run_wallet_mode.sh` with real health
      probes and log collection pipeline.【F:scripts/run_wallet_mode.sh†L12-L57】
- [ ] GUI review: walk through the four tabs above, explaining how callouts map
      to pipeline, consensus, receive, and send workflows.【F:validator-ui/src/components/WalletTabs.tsx†L43-L344】
- [ ] Evidence capture: export proof/VRF entries, RBAC lint output, and backup
      hashes to the audit log as described in the runbook.【F:docs/wallet_operator_runbook.md†L132-L150】
- [ ] Troubleshooting: rehearse VRF, snapshot, and telemetry triage from the
      validator troubleshooting guide so support can escalate with complete
      context.【F:docs/validator_troubleshooting.md†L1-L138】
