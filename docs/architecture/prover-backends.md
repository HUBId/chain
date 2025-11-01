# Prover backend architecture

This document summarises the prover-relevant crates that ship in the RPP
workspace and the contracts that tie them together.

## Workspace entry points

The root crate `rpp-chain` exposes prover functionality behind feature flags.
`prover-stwo` enables the nightly STWO integration, while `prover-mock`
selects the stable mock implementation.  Both use the shared
`prover-backend-interface` dependency, and the STWO backend is wired in via the
`stwo` alias so existing modules can keep their imports.【F:Cargo.toml†L6-L33】

`rpp-chain` re-exports the backend interface under `proof_backend`, so external
callers still program against the trait.  When the `prover-stwo` feature is
active the workspace members `rpp/node`, `rpp/wallet`, and `rpp/consensus`
enable a direct dependency on `prover/prover_stwo_backend`, ensuring the STWO
implementation is compiled alongside their proof system plumbing.  The
`prover-mock` flag keeps the backend dependency disabled, letting consumers stay
on the interface-only mock path.【F:rpp/node/Cargo.toml†L1-L32】【F:rpp/wallet/Cargo.toml†L1-L40】【F:rpp/consensus/Cargo.toml†L1-L32】

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

`prover/prover_stwo_backend` hosts the nightly-only STWO integration.  Its
`backend` module exposes a thin `StwoBackend` adapter that implements the shared
`ProofBackend` trait while deferring specialised functionality to the existing
STWO modules.  This keeps the nightly dependencies isolated from consumers that
only need the trait interface.【F:prover/prover_stwo_backend/src/backend.rs†L1-L43】

Nightly-specific code now lives under `prover/prover_stwo_backend/src/official`,
which mirrors the previous blueprint layout so downstream modules can keep their
imports while picking up the re-exported modules from the backend crate.  The
directory contains the relocated `air`, `circuit`, `conversions`, `fri`,
`official_adapter`, `params`, `proof`, and `verifier` modules, isolating every
`stwo_official` dependency behind the backend feature gate.【F:prover/prover_stwo_backend/src/official/mod.rs†L1-L8】
The feature graph wires `prover-stwo` to `official`, ensuring that enabling the
STWO backend automatically pulls in the nightly-only code path.【F:prover/prover_stwo_backend/Cargo.toml†L12-L23】

For reference, the following files were moved from `rpp/proofs/stwo` into the
backend crate:

- `rpp/proofs/stwo/air/` → `prover/prover_stwo_backend/src/official/air/`
- `rpp/proofs/stwo/circuit/` → `prover/prover_stwo_backend/src/official/circuit/`
- `rpp/proofs/stwo/conversions.rs` → `prover/prover_stwo_backend/src/official/conversions.rs`
- `rpp/proofs/stwo/fri.rs` → `prover/prover_stwo_backend/src/official/fri.rs`
- `rpp/proofs/stwo/official_adapter.rs` → `prover/prover_stwo_backend/src/official/official_adapter.rs`
- `rpp/proofs/stwo/params/` → `prover/prover_stwo_backend/src/official/params/`
- `rpp/proofs/stwo/proof.rs` → `prover/prover_stwo_backend/src/official/proof.rs`
- `rpp/proofs/stwo/verifier/` → `prover/prover_stwo_backend/src/official/verifier/`

`rpp/proofs/stwo` now re-exports these backend modules and retains only the
stable aggregation, FFI, and wallet prover code that integrates with the rest of
the chain runtime.【F:rpp/proofs/stwo/mod.rs†L1-L12】【F:rpp/proofs/stwo/prover/mod.rs†L1-L73】

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

