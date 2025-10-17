# STWO Prover Crate

This crate bundles the proving backend that powers StarkWare's STWO stack. The
`core` module exposes finite-field primitives, polynomials, and transcript
utilities shared between the prover and verifier, while the `prover` module
contains SIMD-accelerated implementations of polynomial commitment, lookup, FRI,
and Merkle operations.

Most consumers enable the `std` and `prover` features which unlock the backend
traits and SIMD backends. The crate still supports `no_std` builds for the
verifier with the `std` feature disabled.

## Layout

- `src/core`: Field arithmetic, polynomial utilities, commitment layers, and
  transcript channels.
- `src/prover`: SIMD-accelerated prover pipeline split into `backend`, `pcs`,
  `fri`, and lookup components.
- `benches`: Criterion benchmarks covering hot prover primitives (FFT,
  prefix-sum, Merkle hashing, lookup folding, etc.).

## Running the benchmarks

The benches require the `std` and `prover` features so that the SIMD backend is
compiled in. Run them from the workspace root with Cargo:

```bash
cargo bench -p stwo --features "std prover" --bench field
```

Replace `field` with any of the bench targets under `benches/` to focus on a
particular primitive:

- `bit_rev`
- `eval_at_point`
- `fft`
- `field`
- `fri`
- `lookups`
- `merkle`
- `pcs`
- `prefix_sum`
- `quotients`

You can pass extra Criterion options after `--`, for example to reduce the run
length while iterating locally:

```bash
cargo bench -p stwo --features "std prover" --bench fft -- --sample-size 20
```

The benchmark harnesses emit human-readable summaries and Criterion stores raw
measurements under `target/criterion/` for further inspection.
