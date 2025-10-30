# Wallet UTXO Policies

Wallet spends are gated by a tier-aware policy that constrains how many inputs
may be consumed, how large the debit may be, and how much change a transfer is
allowed to return. The policy mirrors the runtime evaluator implemented in
`wallet/ui/policy` and is applied while assembling a `transaction_bundle`
workflow. A violation aborts the spend with an error describing the failing
rule, ensuring callers receive a deterministic reason without mutating wallet
state.

## Tiered spend limits

| Tier | Max inputs | Max debit (native) | Max change (native) |
| ---- | ---------- | ------------------ | ------------------- |
| TL0  | 1          | 50,000             | 0                   |
| TL1  | 2          | 100,000            | 10,000              |
| TL2  | 4          | 250,000            | 50,000              |
| TL3  | 6          | 1,000,000          | 100,000             |
| TL4  | 8          | 5,000,000          | 500,000             |
| TL5  | 16         | unlimited          | unlimited           |

The debit column captures the total spend (requested amount + fee) that a tier
may authorise in a single transaction. The change column caps how much value can
be routed back to the sender, preventing lower tiers from splitting inputs into
many tiny change outputs.

## Evaluation order

1. **Input density** – The number of UTXOs selected for the spend must be less
   than or equal to the tier’s `max_inputs`. The evaluator fails with
   `"utxo input count"` when the limit is exceeded.
2. **Debit ceiling** – The total debit must not exceed the tier’s
   `max_debit_value`. The error message begins with `"total debit"` when the
   request surpasses the ceiling.
3. **Change budget** – Any change routed back to the sender must stay within the
   tier’s `max_change_value`. Rejections surface `"change value"` to align with
   operational dashboards.

The evaluator stops at the first failing rule. Tier 5 intentionally leaves the
limits unbounded to mirror validator-grade wallets that need to consolidate
inputs and sweep larger balances.
