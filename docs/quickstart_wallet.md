# Wallet quickstart (CLI + GUI)

This quickstart walks through the init → sync → receive → send lifecycle for the
wallet runtime and GUI. Pair the steps with the platform install guides for
bundle verification and service wiring:
[Linux](install/linux.md) · [macOS](install/macos.md) · [Windows](install/windows.md).

## 1. Initialise the wallet

Run the CLI bootstrap to create the keystore and data directories, then unlock
the GUI if you prefer a visual flow:

```bash
cargo run -p rpp-wallet -- init --keys-path ./keys/wallet.toml
```

The command prompts for a passphrase (or accepts `--passphrase-*` flags) and
prints the data/keystore paths so you can stash them in your change ticket.【F:docs/wallet_phase1_minimal.md†L200-L238】

## 2. Sync the chain view

Keep the wallet aligned with the node before receiving or sending funds:

```bash
cargo run -p rpp-wallet -- sync
```

The output shows the latest height, pending ranges, and last error so you can
escalate stalled coordinators. GUI operators can rely on the Overview tab card
below to confirm the same status without leaving the desktop.

```
+---------------------------+
| Overview (GUI wireframe)  |
| Sync: height 12345  ✔     |
| Balances: confirmed 1.2   |
| Pending ops: 0            |
| [Refresh] [Rescan]        |
+---------------------------+
```

Use the rescan helper when history needs to be replayed:

```bash
cargo run -p rpp-wallet -- rescan --from-height 100_000
```

The CLI confirms scheduling, while the GUI shows the job in the Overview card
so both surfaces stay in sync.【F:docs/wallet_phase1_minimal.md†L238-L263】【F:config/wallet.toml†L95-L102】

## 3. Receive funds

Derive a fresh external address for inbound payments:

```bash
cargo run -p rpp-wallet -- addr new
```

GUI operators can pull from the Receive tab without touching the CLI:

```
+---------------------------+
| Receive (GUI wireframe)   |
| Address: wallet1...       |
| [Copy] [New address]      |
| Tooltip: rotate per use   |
+---------------------------+
```

## 4. Send funds (with proof enforcement)

Draft, sign, and broadcast a spend while respecting prover policy:

```bash
cargo run -p rpp-wallet -- send preview
cargo run -p rpp-wallet -- send create --to wallet1... --amount 50000
cargo run -p rpp-wallet -- send sign --draft-id <draft>
cargo run -p rpp-wallet -- send broadcast --draft-id <draft>
```

Set `[wallet.prover].require_proof = true` to block broadcasts until a proof is
attached; keep `allow_broadcast_without_proof = false` for fail-closed
behaviour.【F:docs/wallet_phase1_minimal.md†L246-L271】【F:config/wallet.toml†L125-L132】

GUI send flow callouts:

```
+---------------------------+
| Send (GUI wireframe)      |
| To: [_____________]       |
| Amount: [______] sats     |
| Fee slider [---|----]     |
| Proof: STWO (required)    |
| [Preview] [Sign] [Send]   |
| Error banner slot         |
+---------------------------+
```

Proof status mirrors the RPC error codes documented in the GUI dictionary so the
Send tab’s banner matches CLI failures.【F:docs/wallet_phase3_gui.md†L74-L113】

## 5. Hybrid runner activation

Use the hybrid mode to launch the node and wallet together during staging or
demos:

```bash
scripts/run_hybrid_mode.sh --config ./config/hybrid.toml --wallet-config ./config/wallet.toml
```

The wrapper injects health checks for `/health/live` and `/health/ready`, then
waits for readiness before returning control so you can open the GUI or run
follow-up CLI calls.【F:scripts/run_hybrid_mode.sh†L1-L55】 Export `RPP_NODE_DATA_DIR`
or `RPP_HYBRID_LOG_LEVEL` to override paths without editing configs.

## 6. Enable the STWO prover backend

Switch the prover to STWO when you are ready for production proofs:

1. Edit `config/wallet.toml`:
   ```toml
   [wallet.prover]
   enabled = true
   backend = "stwo"
   require_proof = true
   allow_broadcast_without_proof = false
   timeout_secs = 600
   max_concurrency = 2
   ```
2. Restart the runtime/GUI (hot reload is not supported) and verify the Send tab
   shows `Proof: STWO (required)` in the footer.
3. Cross-check prover API compatibility with [`docs/stwo_official_api.md`](stwo_official_api.md)
   if you integrate external proving services.

The config above enforces fail-closed behaviour so broadcasts cannot skip proofs
if the backend stalls.【F:config/wallet.toml†L125-L132】【F:config/wallet.toml†L1-L3】
