# Prover backend architecture

This document summarises the prover-relevant crates that ship in the RPP
workspace and the contracts that tie them together.

## Workspace entry points

The root crate `rpp-chain` exposes prover functionality behind feature flags.
`prover-stwo` enables the nightly STWO integration, while `prover-mock`
selects the stable mock implementation.  Both use the shared
`prover-backend-interface` dependency, and the STWO backend is wired in via the
`stwo` alias so existing modules can keep their imports.【F:Cargo.toml†L6-L33】

`rpp-chain` re-exports the backend interface under `proof_backend`, allowing
consumer crates such as `rpp/node`, `rpp/wallet`, or `rpp/consensus` to depend
on the trait instead of concrete prover implementations.【F:src/lib.rs†L1-L66】

## Shared backend interface

`rpp/zk/backend-interface` provides the canonical trait and shared data types
for prover integrations.  It defines the `ProofBackend` trait along with the
serialization helpers (`WitnessBytes`, `ProofBytes`) and enumerates the supported
backend identifiers.  Implementations return a `BackendResult` that captures
serialization failures and backend-specific errors, making it possible for
callers to handle them uniformly.【F:rpp/zk/backend-interface/src/lib.rs†L1-L307】

The runtime maps these backend errors into the chain-wide `ChainError`, keeping
error handling consistent across core crates regardless of which prover backend
is selected.【F:rpp/runtime/errors.rs†L1-L37】

## Backend implementations

### Nightly STWO backend

`rpp/zk/prover_stwo_backend` hosts the nightly-only STWO integration.  Its
`backend` module exposes a thin `StwoBackend` adapter that implements the shared
`ProofBackend` trait while deferring specialised functionality to the existing
STWO modules.  This keeps the nightly dependencies isolated from consumers that
only need the trait interface.【F:rpp/zk/prover_stwo_backend/src/backend.rs†L1-L43】

### Stable mock backend

`rpp/zk/prover_mock_backend` offers a deterministic mock backend designed for
stable toolchains.  It implements the same trait but produces in-memory witness
artifacts, allowing wallet and node flows to exercise the prover pipeline
without nightly dependencies.【F:rpp/zk/prover_mock_backend/src/lib.rs†L1-L87】

## Proof pipeline integration

The blueprint definitions under `rpp/proofs` rely on the backend interface to
encode witnesses.  `ProofSystemKind` values from the blueprint are converted to
backend identifiers before constructing `WitnessHeader` instances, ensuring a
single source of truth for backend selection while keeping the blueprint enums
unchanged.【F:rpp/proofs/rpp.rs†L1-L77】

