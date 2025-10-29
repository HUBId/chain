# STWO Official Public API Survey (v0.1.1)

This document records the results of running `cargo +nightly-2025-07-14 public-api` against the vendored `stwo-official` crate (commit/tag v0.1.1) to check for the types that the RPP toolchain expects to re-export.

```
cargo +nightly-2025-07-14 public-api -p stwo-official --manifest-path prover/prover_stwo_backend/vendor/stwo-dev/crates/stwo/Cargo.toml > /tmp/stwo_public_api.txt
```

## Summary of findings

| Expected item | Result in `stwo-official` | Notes |
| --- | --- | --- |
| `field::Felt` / `PrimeField` trait | *Not present* | The public API exposes `core::fields::m31::BaseField` and `core::fields::qm31::SecureField`, but there is no type alias named `Felt`, nor an exposed `PrimeField` trait implementation. |
| `hash::poseidon2::{Poseidon2, Poseidon2Config}` | *Not present* | The crate provides `core::channel::Poseidon252Channel` and `core::vcs::poseidon252_merkle::Poseidon252MerkleHasher`, but no Poseidon2 helpers. |
| `fri::{FriParams, FriProof}` | *Not present* | FRI internals are confined to `core::fri`. No public structs named `FriParams` or `FriProof` exist. |
| `stark::{Proof, ProvingKey, VerifyingKey, Prover, Verifier, Params, PublicInputs}` | *Not present* | The exposed proof object is `core::proof::StarkProof`. There are no top-level `Prover`/`Verifier` orchestration types or key structs in the public API. |
| `merkle::{MerkleTree, MerkleProof}` | *Not present* | Merkle utilities live under `core::vcs`; concrete types such as `Poseidon252MerkleHasher` are exposed instead. |
| `Proof::to_bytes` / `Proof::from_bytes` | *Not present* | `StarkProof` is a tuple struct around `quotients::CommitmentSchemeProof`, which has no inherent byte (de)serialisation helpers. |

## Implication

The automation requested for re-export generation, parameter builders, and recursive proof adapters cannot be derived from the current `stwo-official` surface because the expected symbols do not exist. Any generator built on top of `cargo public-api` would necessarily fail with compiler errors until `stwo-official` publishes the missing types or adapter layers are added upstream.

For reference, the top-level proof type currently available is:

```
pub struct stwo::core::proof::StarkProof<H: stwo::core::vcs::MerkleHasher>(
    pub stwo::core::pcs::quotients::CommitmentSchemeProof<H>
)
```

Developers migrating away from the mock backend will therefore need either:

1. A wrapper crate that exposes the expected `Poseidon2`, FRI, and Stark interfaces, or
2. A revised integration plan that aligns with the structures actually provided in `stwo-official` (e.g. re-exporting `StarkProof` directly and implementing serialization locally).

Until such an abstraction exists, attempting to auto-generate the requested adapters would yield immediate compile-time failures.
