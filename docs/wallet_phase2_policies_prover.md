# Wallet Phase 2 Policies & Prover Guide

> **Phase navigation:** Previous phase: [Wallet runtime configuration (Phase 1)](wallet_phase1_minimal.md) · Next phase:
> [Wallet Phase 3 – GUI Guide](wallet_phase3_gui.md) · [Wallet documentation index](README.md#wallet-documentation-index)
>
> **Sections:** [Policies](#policies) · [GUI](#gui) · [Backup](#backup) · [Security](#security)

Phase 2 extends the wallet runtime with configurable spend policies, a heuristics-driven fee estimator, durable pending-input locks, targeted rescans, and an opt-in proof backend. This guide explains how to operate those surfaces, which configuration keys and RPC methods they map to, and how to diagnose common failure modes.

## Policies

### Policy knobs

Wallet policy defaults live in `wallet.policy.*` and control address discovery, spend eligibility, and post-draft enforcement.【F:rpp/wallet/src/config/wallet.rs†L63-L118】 Key fields include:

* `wallet.policy.external_gap_limit` / `internal_gap_limit` – cap unused receive/change addresses tracked before the wallet derives more.【F:rpp/wallet/src/config/wallet.rs†L66-L83】 Use `rpp-wallet addr new` to confirm address cursors advance once fresh outputs land.【F:rpp/wallet/src/cli/wallet.rs†L469-L502】
* `wallet.policy.min_confirmations` – minimum depth before UTXOs participate in coin selection.【F:rpp/wallet/src/config/wallet.rs†L66-L83】 Drafts referencing younger inputs fail with an "insufficient funds" policy error.
* `wallet.policy.dust_limit` and `max_change_outputs` – enforce change budgeting and dust avoidance during plan construction.【F:rpp/wallet/src/config/wallet.rs†L66-L95】 `rpp-wallet send preview` surfaces these limits before you build a draft.【F:rpp/wallet/src/cli/wallet.rs†L706-L743】
* `wallet.policy.spend_limit_daily` – optional soft cap on aggregate sends per 24 hours; exceeding the limit aborts draft creation with policy diagnostics.【F:rpp/wallet/src/config/wallet.rs†L66-L95】【F:rpp/wallet/src/engine/mod.rs†L336-L347】
* `wallet.policy.pending_lock_timeout` – age (seconds) before stale input locks auto-release; see “Pending lock lifecycle.”【F:rpp/wallet/src/config/wallet.rs†L66-L95】
* `wallet.policy.tier.*` – toggles tier-aware hooks that downstream services can observe via the policy preview RPC.【F:rpp/wallet/src/config/wallet.rs†L100-L118】【F:rpp/wallet/src/wallet/mod.rs†L138-L147】

Runtime policy snapshots complement static config. Operators can inspect the compiled rules (`policy_preview`), fetch persisted statements (`get_policy`), or update them (`set_policy`) using the wallet RPC or CLI (`rpp-wallet policy get|set`).【F:rpp/wallet/src/rpc/mod.rs†L188-L201】【F:rpp/wallet/src/cli/wallet.rs†L522-L607】 Statements are versioned and timestamped inside the wallet store.【F:rpp/wallet/src/wallet/mod.rs†L150-L171】 Persisted revisions let you stage governance approvals without rebuilding the binary.

### Fee estimator behaviour

Fee estimation combines operator overrides, node telemetry, and deterministic fallbacks:

1. **Explicit overrides** – If `send create` receives a `--fee-rate` (or RPC override), `FeeEstimator::resolve` first validates the value against `wallet.fees.min_sats_per_vbyte` and `max_sats_per_vbyte`.【F:rpp/wallet/src/engine/fees.rs†L22-L80】【F:rpp/wallet/src/config/wallet.rs†L120-L152】 Violations surface as `fee_rate below minimum` or `fee_rate above maximum` errors.
2. **Node heuristics** – When connected to a node, the estimator samples mempool utilization and recent blocks up to `wallet.fees.target_confirmations`, classifies congestion, and clamps the candidate inside `wallet.fees.heuristic_min_sats_per_vbyte` / `heuristic_max_sats_per_vbyte`.【F:rpp/wallet/src/engine/fees.rs†L32-L172】 Successful quotes are cached for `wallet.fees.cache_ttl_secs` to avoid hammering RPCs.【F:rpp/wallet/src/engine/fees.rs†L89-L111】
3. **Config fallback** – Without node hints (or when heuristics fail), the estimator returns `wallet.fees.default_sats_per_vbyte`, still bounded by the configured min/max.【F:rpp/wallet/src/engine/fees.rs†L49-L53】 Draft summaries report the applied fee rate and source so operators can justify spend decisions.【F:rpp/wallet/src/cli/wallet.rs†L888-L905】

You can query the latest quote via `rpp-wallet fees estimate --target <blocks>` (`estimate_fee` RPC).【F:rpp/wallet/src/cli/wallet.rs†L609-L639】【F:rpp/wallet/src/rpc/mod.rs†L202-L205】 When the node rejects a broadcast for being underpriced, the sync status surfaces actionable hints to bump the rate.【F:rpp/wallet/src/wallet/runtime.rs†L433-L445】

### Pending lock lifecycle

Every draft locks its inputs immediately so concurrent workflows cannot double-spend the same UTXO.【F:rpp/wallet/src/engine/mod.rs†L315-L344】 The wallet filters locked candidates out of future selections, which can make subsequent drafts fail with `insufficient funds` until the locks clear.【F:rpp/wallet/src/engine/utxo_sel.rs†L98-L140】 Locks carry backend metadata (`mock` vs `stwo`, witness size, proof duration) once the prover signs the draft.【F:rpp/wallet/src/wallet/mod.rs†L173-L193】 They are released when:

* The prover fails (timeout, witness overflow, cancellation); `sign_and_prove` automatically drops locks before surfacing the error.【F:rpp/wallet/src/wallet/mod.rs†L173-L198】
* Broadcast succeeds; the runtime evicts locks for the draft fingerprint on acceptance.【F:rpp/wallet/src/wallet/mod.rs†L202-L214】
* Broadcast fails; the wallet releases all inputs tied to that draft so you can retry or adjust fees.【F:rpp/wallet/src/wallet/mod.rs†L202-L214】
* Locks age past `wallet.policy.pending_lock_timeout`; polling `pending_locks` automatically expires stale entries before returning them.【F:rpp/wallet/src/engine/mod.rs†L222-L254】
* Operators call `rpp-wallet locks release` (`release_pending_locks` RPC) to forcefully clear them.【F:rpp/wallet/src/cli/wallet.rs†L641-L680】【F:rpp/wallet/src/rpc/mod.rs†L206-L214】

The CLI also exposes `rpp-wallet locks list` to audit held inputs and prover metadata.【F:rpp/wallet/src/cli/wallet.rs†L641-L680】 Use these commands before escalating “lock conflict” incidents.

## GUI

Phase 2 itself does not introduce GUI components, but every change above feeds the user experience shipped in [Phase 3](wallet_phase3_gui.md). Keep policy statements, fee estimator defaults, and lock diagnostics healthy so the iced-based UI has the same authoritative state as the CLI when you upgrade.

## Backup

Durable backups remain optional in Phase 2. Continue taking periodic filesystem snapshots and plan to adopt the encrypted archives introduced in [Phase 4](wallet_phase4_advanced.md#backuprecovery-formats-and-rotation) once you complete the Phase 3 GUI rollout. Rescan workflows described below ensure the database can be rebuilt from peers if a manual restore is needed before backup automation lands.

## Security

### Rescan modes and scheduling

The sync coordinator tracks three modes: full (from birthday), resume (from last checkpoint), and targeted rescan (explicit height).【F:rpp/wallet/src/indexer/scanner.rs†L40-L176】 A `rescan` RPC/CLI request accepts either `--from-height` or `--lookback-blocks` and queues a targeted pass once the latest height is known.【F:rpp/wallet/src/rpc/dto.rs†L332-L382】【F:rpp/wallet/src/rpc/mod.rs†L215-L233】【F:rpp/wallet/src/cli/wallet.rs†L803-L833】 Sync status responses expose the active mode, pending height ranges, and checkpoint timestamps so dashboards can track progress.【F:rpp/wallet/src/rpc/dto.rs†L326-L358】

Configuration toggles under `wallet.rescan.*` control automatic safety sweeps. Setting `auto_trigger = true` instructs the runtime bootstrapper to schedule a lookback from `wallet.rescan.lookback_blocks` in `wallet.rescan.chunk_size` batches, which is logged during startup to confirm the knobs applied.【F:rpp/runtime/config.rs†L3233-L3264】【F:rpp/node/src/lib.rs†L814-L823】 Even with auto-trigger enabled, ad-hoc rescans remain available via the RPC for incident response.

### Prover configuration (mock vs. STWO)

`wallet.prover.*` toggles determine whether drafts are proven and which backend to use.【F:rpp/wallet/src/config/wallet.rs†L154-L180】 By default the mock prover runs in-process (`--features prover-mock`), enforces `max_witness_bytes`, applies `job_timeout_secs`, and gates concurrency via a semaphore sized by `max_concurrency`.【F:rpp/wallet/src/engine/signing/prover.rs†L57-L125】【F:rpp/wallet/src/engine/signing/prover.rs†L212-L291】

To enable the STWO backend, build the crate with `--features prover_stwo_backend` (an alias for `prover-stwo`) and set `wallet.prover.enabled = true`. When compiled, `build_wallet_prover` instantiates the STWO backend; otherwise the runtime requires `mock_fallback = true` or it refuses to start with a "STWO prover requested but feature disabled" error.【F:rpp/wallet/src/engine/signing/prover.rs†L40-L64】 STWO proofs record the same metadata as the mock backend and honour the shared timeouts and witness limits.【F:rpp/wallet/src/engine/signing/prover.rs†L127-L190】

Feature flags:

* `prover-mock` (default) – lightweight mock circuit for dev/test.
* `prover-stwo` / `prover-stwo-simd` – full STWO backend, optionally with SIMD acceleration.【F:rpp/wallet/Cargo.toml†L7-L23】

### Wallet RPC error codes

Wallet RPC responses now embed a stable Phase 2 error code in `error.data.code` alongside
structured diagnostics under `error.data.details`. External clients can key off the string
values below while still surfacing the human-readable `message` field. Core codes include:

| Code | Description | Details payload |
| --- | --- | --- |
| `WALLET_POLICY_VIOLATION` | Draft violates configured policy limits (confirmations, dust, daily spend). | `violations[]` entries explaining each breach. |
| `PENDING_LOCK_CONFLICT` | Not enough unlocked UTXOs to satisfy the draft because other drafts hold locks. | `required`, `total_available` (or `available`). |
| `FEE_TOO_LOW` | Fee rate below wallet minimum or rejected by the node; hints advise the minimum bump. | `minimum`/`required`, optional node `hint`, `hints[]`, `phase2_code`. |
| `FEE_TOO_HIGH` | Requested fee rate exceeds the configured ceiling. | `requested`, `maximum`. |
| `PROVER_TIMEOUT` | Wallet prover exceeded `job_timeout_secs` and abandoned the proof. | `timeout_secs`. |
| `PROVER_FAILED` | Prover backend/serialization/runtime error (mock or STWO). | `kind`, `message`. |
| `WITNESS_TOO_LARGE` | Witness size breached the configured limit. | `size_bytes`, `limit_bytes`. |
| `RESCAN_IN_PROGRESS` | A targeted rescan is already queued; new requests report the pending start height. | `requested`, `pending_from`. |
| `RESCAN_OUT_OF_RANGE` | Requested rescan starts above the latest indexed height. | `requested`, `latest`. |
| `SYNC_UNAVAILABLE` | RPC invoked without a running sync coordinator. | *(empty)* |
| `NODE_UNAVAILABLE` / `NODE_REJECTED` / `NODE_POLICY` | Execution node errors (network failure, mempool rejection, policy rejection). | `phase2_code`, `reason`, structured `hint`, `hints[]`. |
| `DRAFT_NOT_FOUND` / `DRAFT_UNSIGNED` | Draft lifecycle errors exposed by the CLI and RPC. | `draft_id`. |

Clients can also encounter standard JSON-RPC codes (`INVALID_PARAMS`, `METHOD_NOT_FOUND`, etc.).
Those use the same envelope, letting scripts branch on the code string while operators read the
friendly CLI messaging.

### Troubleshooting Phase 2 errors

### Fee rate too low
* **Symptom:** Broadcast rejects with `fee rate too low (required N sats/vB)` and the sync status lists a fee hint.【F:rpp/wallet/src/wallet/runtime.rs†L433-L445】
* **Action:** Re-run `rpp-wallet send create` with `--fee-rate N` (or higher) or let the estimator pick a new rate after increasing `wallet.fees.default_sats_per_vbyte`. Confirm via `rpp-wallet fees estimate` before broadcasting.【F:rpp/wallet/src/engine/fees.rs†L22-L172】【F:rpp/wallet/src/cli/wallet.rs†L609-L639】

### Pending lock conflict / insufficient funds
* **Symptom:** Draft creation fails because UTXOs remain locked from earlier attempts; the locks list shows the inputs held by pending drafts.【F:rpp/wallet/src/engine/utxo_sel.rs†L98-L140】【F:rpp/wallet/src/cli/wallet.rs†L641-L680】
* **Action:** Inspect with `rpp-wallet locks list`, decide whether to finish signing/broadcasting, or release them via `rpp-wallet locks release`. If stale locks recur, shorten `wallet.policy.pending_lock_timeout` to recycle inputs faster.【F:rpp/wallet/src/engine/mod.rs†L230-L254】【F:rpp/wallet/src/config/wallet.rs†L66-L95】

### Prover timeout
* **Symptom:** `send sign` errors with `prover timeout` and no proof materialises; locks are auto-cleared but the UI shows the failure.【F:rpp/wallet/src/engine/signing/prover.rs†L212-L291】【F:rpp/wallet/src/wallet/mod.rs†L173-L198】
* **Action:** Increase `wallet.prover.job_timeout_secs` or reduce concurrency (`max_concurrency`) to keep runtimes within resource budgets. Large drafts may also exceed `max_witness_bytes`; raise the limit or split the spend. When STWO is disabled, ensure `mock_fallback` remains `true` so the runtime can service proofs without rebuilding.【F:rpp/wallet/src/config/wallet.rs†L154-L180】【F:rpp/wallet/src/engine/signing/prover.rs†L40-L125】

Refer back to this guide whenever you adjust the wallet config or roll out new prover infrastructure.

---

> **Phase navigation:** Previous phase: [Wallet runtime configuration (Phase 1)](wallet_phase1_minimal.md) · Next phase:
> [Wallet Phase 3 – GUI Guide](wallet_phase3_gui.md) · [Wallet documentation index](README.md#wallet-documentation-index)
