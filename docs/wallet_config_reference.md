# Wallet configuration reference

This guide collects the runtime and GUI fields operators flip most often: prover
policies, rescan controls, hybrid runner toggles, and telemetry/privacy knobs.
Use it alongside [`config/wallet.toml`](../config/wallet.toml) and the phased
wallet guides when building environment-specific profiles.

## Prover and proof enforcement

| Field | Description |
| --- | --- |
| `[wallet.prover].enabled` | Turns prover orchestration on/off. Leave `true` for production so drafts include witness data.|
| `[wallet.prover].backend` | Select `mock` for dev or `stwo` for production proof generation.|
| `[wallet.prover].require_proof` | When `true`, signing fails without an attached proof (fail-closed).|
| `[wallet.prover].allow_broadcast_without_proof` | Leave `false` to block broadcasts if a proof is missing or times out.|
| `[wallet.prover].timeout_secs`, `max_concurrency`, `max_witness_bytes` | Bound per-job execution and memory before retrying or surfacing RPC errors.|

These fields gate the send pipeline described in Phase 2 and feed the GUI error
banners documented in the Phase 3 dictionary.【F:config/wallet.toml†L125-L132】【F:docs/wallet_phase3_gui.md†L74-L113】 Restart the runtime after
changing any prover setting; live reload is not supported.【F:config/wallet.toml†L1-L3】

## Rescan and lifecycle controls

| Field | Description |
| --- | --- |
| `[wallet.rescan].auto_trigger` | Enables automatic lookback when sync gaps are detected.|
| `[wallet.rescan].lookback_blocks` | Bounds how far the runtime walks history during auto-rescan.|
| `[wallet.rescan].chunk_size` | Tunes batch size for replay jobs.|
| `[wallet.engine].birthday_height` | Optional starting height for partial syncs.|

CLI operators can still schedule manual jobs via `wallet rescan --from-height`;
the GUI Overview card surfaces the same pending ranges so both surfaces agree on
state.【F:config/wallet.toml†L95-L110】【F:docs/wallet_phase1_minimal.md†L238-L263】

## Hybrid runner toggles

Hybrid mode starts a node and wallet in one process for demos and staging:

| Field | Description |
| --- | --- |
| `config/hybrid.toml` | Node defaults consumed by `scripts/run_hybrid_mode.sh`.|
| `--wallet-config <path>` | CLI flag passed through the hybrid wrapper to select a wallet profile.| 
| `RPP_NODE_DATA_DIR`, `RPP_HYBRID_LOG_LEVEL` | Environment overrides for data paths and logging without editing configs.| 

Use `scripts/run_hybrid_mode.sh` to bootstrap the combined runtime and block
until health probes pass.【F:scripts/run_hybrid_mode.sh†L1-L55】

## Telemetry and privacy

Wallet telemetry stays opt-in. Key controls live under `[wallet.telemetry]`:

| Field | Description |
| --- | --- |
| `metrics` | Enables metrics upload (GUI + CLI share the flag).|
| `crash_reports` | Allows crash report uploads from the runtime and GUI.| 
| `endpoint` | HTTPS endpoint for telemetry batches.| 
| `machine_id_salt` | Salt used to derive an anonymous machine identifier.| 

GUI-specific controls live under `[wallet.gui]` (theme, `auto_lock_secs`,
clipboard clearing) and the Phase 3 telemetry opt-in switch; both report to the
same uploader when `metrics = true`.【F:config/wallet.toml†L69-L87】【F:docs/wallet_phase1_minimal.md†L1-L35】

## Example profiles

### Local development (fast feedback)

```toml
[wallet.prover]
backend = "mock"
require_proof = false
allow_broadcast_without_proof = true
max_concurrency = 1

[wallet.rescan]
auto_trigger = false
chunk_size = 32
```

### Staging with hybrid runner

```toml
[wallet.prover]
backend = "stwo"
require_proof = true
allow_broadcast_without_proof = false
max_concurrency = 2

[wallet.rescan]
auto_trigger = true
lookback_blocks = 2880

[wallet.telemetry]
metrics = true
endpoint = "https://telemetry.example.com/v1"
machine_id_salt = "staging"
```
Run via: `RPP_HYBRID_LOG_LEVEL=info scripts/run_hybrid_mode.sh --wallet-config ./config/wallet.toml`.

### Production hardened profile

```toml
[wallet.prover]
backend = "stwo"
require_proof = true
allow_broadcast_without_proof = false
timeout_secs = 600
max_concurrency = 4
max_witness_bytes = 16777216

[wallet.rescan]
auto_trigger = true
lookback_blocks = 5760
chunk_size = 64

[wallet.telemetry]
metrics = true
crash_reports = true
endpoint = "https://telemetry.example.com/v1"
machine_id_salt = "rotate-me"
```

Pair the production profile with Phase 4 security hardening (mTLS/RBAC) and the
GUI auto-lock to keep lifecycle controls aligned.【F:config/wallet.toml†L15-L47】【F:config/wallet.toml†L69-L87】
