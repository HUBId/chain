# Wallet STWO circuit coverage

This note tracks the wallet-level circuits that gate STWO proof generation.
Each circuit mirrors the blueprint requirements for `wallet.stwo_circuits` and
is backed by unit tests under `prover/stwo/tests/`.

## Balance circuit

* **Witness** – captures sender and recipient account snapshots together with
the transfer amount and fee (`BalanceWitness`).
* **Constraints** – verifies the sender nonce increment, debits/credits the
  balances without overflow, and guarantees non-empty addresses.
* **Implementation** – `prover/stwo/src/circuits/balance.rs` exposes the
  `BalanceCircuit` which is instantiated through
  `build_balance_circuit` in `prover/stwo/src/lib.rs`. The wallet calls the
  builder from `rpp/wallet/src/proofs/mod.rs` before proving a transaction.
* **Tests** – `prover/stwo/tests/circuit_fixtures.rs::balance_*` cover both the
  success case and a failure caused by inconsistent balances.

## Double-spend circuit

* **Witness** – models available and consumed nonces as outpoints
  (`DoubleSpendWitness`).
* **Constraints** – ensures consumed inputs exist in the available set, remain
  unique, and are not reintroduced as outputs. This defends against nonce reuse
  double spends in the account-based wallet pipeline.
* **Implementation** – `prover/stwo/src/circuits/double_spend.rs` with the
  `build_double_spend_circuit` helper.
* **Tests** – exercised via
  `prover/stwo/tests/circuit_fixtures.rs::double_spend_*`.

## Tier attestation circuit

* **Witness** – records the attested and required tiers together with a
  signature flag and digest binding (`TierAttestationWitness`).
* **Constraints** – rejects proofs when the attested tier falls below the
  required tier or when signature validation fails.
* **Implementation** – `prover/stwo/src/circuits/tier_attestation.rs` and the
  associated builder in `prover/stwo/src/lib.rs`.
* **Tests** – `prover/stwo/tests/circuit_fixtures.rs::tier_attestation_*` cover
  both acceptance and failure.

## Wallet integration

`rpp/wallet/src/proofs/mod.rs` wires the builders into the runtime. When the
`prover-stwo` feature is active the wallet validates the transaction witness via
all three circuits before delegating to the STWO prover. Builds without the
feature surface a configuration error instead of silently skipping the checks.

With these circuits and tests in place the `wallet.stwo_circuits` blueprint item
is considered complete.
