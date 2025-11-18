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
