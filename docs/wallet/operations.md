# Wallet Operations Guide

## Tiered UTXO policy

The wallet enforces the tiered limits described in [`policies.md`](./policies.md)
whenever it constructs a spend. The evaluator runs during
`transaction_bundle` assembly and returns user-facing errors such as
`"utxo input count"`, `"total debit"`, or `"change value"` when a request
exceeds its tier envelope. These messages surface in the wallet RPC and the UI
so operators can immediately identify policy violations.

### Configuration surface

The limits are compiled into the wallet runtime and currently do not have a
`wallet.toml` toggle. Operators that need different envelopes must ship a custom
build with adjusted limits or co-ordinate an on-chain governance change. The
policy module is deliberately centralised under `wallet/ui/policy` to simplify
code review and future feature flags.

### Operational checklist

* Keep the wallet identity ZSI-validated; policy evaluation only occurs after
  governance tier checks succeed.
* Monitor rejection messages in wallet logs and telemetry dashboards to confirm
  the correct rule triggered the failure.
* When consolidating UTXOs for validator-grade tiers (TL5), plan sweeps so they
  stay within the unlimited tier before promoting funds to lower tiers.

## Monitoring sync lag

The wallet RPCs now surface explicit lag counters so operators can alert on
stale indexers before users notice missing balances:

* `sync_status` includes a `lag_blocks` field that reports how many blocks the
  wallet is behind the current indexer tip.
* `sync.lag` returns `account_lag_blocks` plus per-address entries (including
  `last_synced_height` and `lag_blocks`) so you can pinpoint which addresses are
  delayed.

Example request/response using `curl`:

```bash
curl -s https://wallet.local/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"sync.lag","params":{}}'
```

```json
{"jsonrpc":"2.0","id":1,"result":{
  "target_height":120,
  "account_lag_blocks":30,
  "addresses":[
    {"address":"...","change":false,"index":0,"last_synced_height":80,"lag_blocks":40}
  ]
}}
```

SDKs expose the same endpoint via `WalletRpcClient::sync_lag`, and
`list_addresses` now returns a `last_synced_height` hint you can stash in your
monitoring dashboards. Alert on large `account_lag_blocks` values and on any
address `lag_blocks` that remain non-zero after a successful catch-up.

## Pruning validation for wallet indices

Wallet balance and nonce indices must survive pruning snapshots so wallet proofs
stay consistent across prover backends. Operators can reuse the pruning
cross-backend harness to verify this invariant:

```bash
RPP_PROVER_DETERMINISTIC=1 \
cargo test -p rpp-chain --locked --test pruning_cross_backend -- \
  wallet_snapshot_round_trip_default_backend

RPP_PROVER_DETERMINISTIC=1 \
cargo test -p rpp-chain --locked --features backend-rpp-stark --test pruning_cross_backend -- \
  wallet_snapshot_round_trip_rpp_stark_backend
```

Both runs assert the restored snapshot keeps every wallet balance/nonce witness
identical to the pre-pruning index, covering both the default and `backend-rpp-
stark` prover stacks. Run these checks when validating new pruning snapshots or
after storage changes that touch wallet account tables.

## Customizing wallet messages

Operators that white-label the wallet CLI or GUI can override the user-visible
strings that ship with the runtime. The default catalog lives in
`rpp/wallet/wallet_messages.toml` and includes the friendly RPC error text, CLI
prompts, and identity workflow errors that surface in the GUI. To customise the
copy:

1. Copy `rpp/wallet/wallet_messages.toml` into your deployment assets and edit
   the values you want to override.
2. Point the wallet runtime, CLI, or GUI at the new catalog by exporting
   `WALLET_MESSAGES_PATH=/path/to/overrides.toml` before launching the
   binary. The loader caches the parsed file, and missing entries fall back to
   the built-in English defaults.

Avoid changing message keys or the documented RPC error codes; downstream tools
parse those fields to decide whether an operation should be retried or reported
as a policy violation. Keep the catalog focused on rewording text or translating
it for your audience while leaving the machine-readable identifiers untouched.
