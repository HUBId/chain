# Plonky3 Experimental Test Plan & Results

## Scope

Validate that the Plonky3 backend remains an acknowledged experimental path
without cryptographic guarantees:

* Prover/Verifier constructors panic without an explicit opt-in.
* End-to-end fixtures continue to produce deterministic artifacts once the guard
  is satisfied.
* Runtime and RPC layers surface "experimental" warnings.

## Test Commands

| Command | Purpose |
| --- | --- |
| `cargo test --package rpp-chain --lib --features backend-plonky3` | Ensures unit/integration tests behind the feature gate honour the experimental guard. |
| `cargo test --tests --features backend-plonky3` | Runs workspace integration tests (e.g. `tests/plonky3_*`) under the guard. |

Environment variable `CHAIN_PLONKY3_EXPERIMENTAL=1` must be set (or the CLI flag
used) before running these commands.

## Results

| Command | Outcome |
| --- | --- |
| `cargo +nightly-2025-07-14 test --package rpp-chain --lib --features backend-plonky3` | ⚠️ Unable to complete within the evaluation window; compiling the full workspace under nightly emitted numerous vendor warnings and was cancelled to avoid exhausting runtime resources.【4429c3†L1-L16】【e39421†L1-L47】 |
