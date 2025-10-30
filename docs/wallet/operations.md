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
