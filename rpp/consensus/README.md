# RPP Consensus crate

The consensus crate coordinates validator selection, leader election, and
zero-knowledge proof integration for the rollup prototype. It depends on the
shared `rpp-crypto-vrf` library to derive deterministic VRF outputs during unit
and integration testing.

## Backend features

Consensus proof generation delegates to a pluggable prover backend configured
through Cargo features:

- `prover-mock` (default): swaps in the deterministic mock backend from
  `rpp/zk/prover_mock_backend`, useful for lightweight development flows and
  stable releases.
- `prover-stwo`: wires the STWO backend. This pathway currently provides
  transaction proof support, while consensus proofs rely on the local fixture
  backend shipped with the tests. Nightly builds must explicitly enable this
  feature (or the workspace-level `stwo` convenience flag) to pick up the STWO
  stack.
- `prover-stwo-simd`: extends `prover-stwo` and allows the STWO fork to enable
  its SIMD acceleration when supported by the host CPU.

Only one backend feature should be active at a time. The crate enforces mutual
exclusion at compile time.

## Testing consensus proofs

The consensus test-suite exercises a full proof round-trip (witness encoding →
proving → verification) whenever a backend exposes the necessary APIs. To run
those tests end-to-end, enable the `prover-mock` feature:

```bash
cargo test -p rpp-consensus --features prover-mock -- --nocapture
```

When the mock backend is unavailable (for example, when compiling with the
`prover-stwo` feature or with all backends disabled), the tests fall back to
deterministic fixture artifacts so that the rest of the suite remains
runnable.
