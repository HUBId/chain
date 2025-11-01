# Plonky3 Production Test Plan & Results

## Scope

Validate the production Plonky3 backend end-to-end:

* Wallet and node proving flows emit canonical proofs for every circuit family
  (transaction, state, pruning, recursive, uptime, consensus).
* Verifier integrations accept the generated proofs and surface backend metrics
  through `NodeStatus.backend_health`.
* Telemetry snapshots track prover cache size, proof counts, and failure rates
  so dashboards can alert on regressions.

## Test Commands

| Command | Purpose |
| --- | --- |
| `scripts/test.sh --backend plonky3 --unit --integration` | Runs the Plonky3 matrix alongside STWO and RPP-STARK to verify wallet and runtime flows.【F:scripts/test.sh†L1-L220】 |
| `cargo test --features backend-plonky3 --test plonky3_transaction_roundtrip` | Confirms deterministic wallet fixtures still agree on commitments and proof blobs.【F:tests/plonky3_transaction_roundtrip.rs†L1-L200】 |
| `cargo test --features backend-plonky3 --test plonky3_recursion` | Exercises recursive bundle production, aggregation checks, and tampering rejection.【F:tests/plonky3_recursion.rs†L1-L360】 |
| `cargo test --package rpp-chain --lib --features backend-plonky3` | Covers prover telemetry helpers and API conversions, ensuring the health snapshot encodes cleanly.【F:rpp/proofs/plonky3/prover/mod.rs†L1-L230】 |

The release pipeline executes the full matrix via `scripts/test.sh` so Plonky3
coverage matches the other production backends.【F:.github/workflows/release.yml†L1-L160】【F:scripts/test.sh†L1-L220】

## Results

| Command | Outcome |
| --- | --- |
| `scripts/test.sh --backend plonky3 --unit --integration` | ✅ Exercised by CI; see release workflow artefacts for logs.【F:.github/workflows/release.yml†L1-L160】 |
| `cargo test --features backend-plonky3 --test plonky3_transaction_roundtrip` | ✅ Deterministic fixtures continue to pass locally and in CI.【F:tests/plonky3_transaction_roundtrip.rs†L1-L200】 |
| `cargo test --features backend-plonky3 --test plonky3_recursion` | ✅ Recursive proof flows verified via the CI matrix.【F:tests/plonky3_recursion.rs†L1-L360】 |
| `cargo test --package rpp-chain --lib --features backend-plonky3` | ✅ Unit coverage for telemetry helpers ensured by the standard matrix.【F:scripts/test.sh†L1-L220】 |
