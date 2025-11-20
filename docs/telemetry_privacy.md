# Wallet telemetry and privacy guarantees

The wallet ships with anonymized runtime telemetry that helps operators
understand crash frequency, RPC latencies, and how far users get through the
send/rescan flows. Telemetry is **disabled by default** and no data leaves the
host until an operator explicitly opts in.

## What gets collected

All batches are JSON documents written to `data/wallet/telemetry/*.json` before
upload. Each event is stamped with milliseconds since the Unix epoch and
contains only the following normalized fields:

| Event | Fields |
| --- | --- |
| `session` | `phase` (`start` or `stop`) |
| `rpc` | `method`, `latency_ms`, `outcome` (`ok`/`err`), optional `code` derived from the Phase 2 RPC error catalog |
| `send_stage` | `stage` (`draft`, `sign`, `broadcast`), `outcome`, `proof_required` |
| `prover` | `backend` (`mock`/`stwo`), `require_proof`, `allow_broadcast_without_proof`, `outcome`, optional `timeout_ms` |
| `rescan` | `stage` (`reschedule`), optional `latency_ms`, `outcome` |
| `lifecycle` | `event` (`auto_lock`, `hybrid_start`), optional `height`/`reason` |
| `error` | `code`, optional human-readable `context` |

Sensitive material such as addresses, node hints, and transaction amounts never
leave the device. Proof enforcement toggles (`require_proof`/
`allow_broadcast_without_proof`) and lifecycle controls (rescan scheduling,
auto-lock, hybrid runner launch) are only reported as booleans/labels so policy
choices are visible without leaking payment data.【F:config/wallet.toml†L69-L132】【F:docs/wallet_phase3_gui.md†L148-L162】 Telemetry
batches are tagged with the wallet build version, the optional `GIT_COMMIT_SHA`,
and a salted machine identifier computed via `sha256(machine_id_salt ||
hostname)` so installations cannot be correlated across operators.

## Local retention and upload policy

Batches are buffered on disk (up to 512 KiB) under
`<wallet data dir>/telemetry`. The exporter retries uploads every time a batch
is recorded; if the HTTPS endpoint is unavailable the files remain on disk until
connectivity returns. Operators can inspect and manually remove the JSON files
at any time to audit exactly what would be uploaded.

## Enabling telemetry

1. Configure the `[wallet.telemetry]` section in `config/wallet.toml`:

   ```toml
   [wallet.telemetry]
   metrics = true
   crash_reports = false
   endpoint = "https://telemetry.example.com/v1"
   machine_id_salt = "rotate-me"
   ```

2. Alternatively, use the CLI helpers:

   ```bash
   # Show the current status
   wallet telemetry metrics status

   # Enable metrics uploads (HTTPS endpoint required)
   wallet telemetry metrics enable \
       --endpoint https://telemetry.example.com/v1 \
       --machine-id-salt rotate-me

   # Disable metrics and keep the on-disk batches
   wallet telemetry metrics disable
   ```

3. Restart the wallet runtime/GUI so the exporter can initialize and flush the
   pending batches.

## Auditing uploads

* Inspect the local queue by opening `data/wallet/telemetry/*.json` with `jq` or
  another JSON viewer.
* Confirm the GUI’s “Enable telemetry opt-in” switch or the CLI status command
  shows `false` when telemetry must stay disabled.
* Use a local HTTPS proxy when opt-ing in to verify that only the documented
  schema above is transmitted.

Crash reporting continues to use the existing spool at
`data/wallet/crash_reports` and can be managed independently via
`wallet telemetry crash-reports …`.
