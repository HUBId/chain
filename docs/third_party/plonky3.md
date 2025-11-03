# Plonky3 third-party inventory

The `backend-plonky3` and `backend-plonky3-gpu` workspace features gate every
Plonky3 dependency, allowing the proof system to be compiled in or out of the
`rpp-chain` binary matrix as needed.【F:rpp/chain/Cargo.toml†L38-L125】 This
section captures the upstream provenance, license posture, and export-relevant
notes for each crate that the backend introduces.

## Proof system crates (CPU path)

The core backend crate lives inside the repository, while all `p3-*`
primitives are consumed from the upstream Plonky3 releases. The metadata table
below is derived from the Cargo resolution captured in
`docs/third_party/plonky3_deps.json` so reviewers can audit the license fields
and pinned sources without hitting the network.【F:docs/third_party/plonky3_deps.json†L1-L210】

| Crate | License | Source pin | Export assessment |
| --- | --- | --- | --- |
| `plonky3-backend` | MIT | workspace path (v0.1.0) | Consensus proof harness bridging node <-> Plonky3 backend |
| `p3-air` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-baby-bear` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-bn254-fr` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-challenger` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-circle` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-commit` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-dft` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-field` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-fri` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-goldilocks` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-interpolation` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-keccak` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-keccak-air` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-koala-bear` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-matrix` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-maybe-rayon` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-mds` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-merkle-tree` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-mersenne-31` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-monty-31` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-multilinear-util` | MIT OR Apache-2.0 | git 80803612ff4b (v0.3.0) | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-poseidon` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-poseidon2` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-poseidon2-air` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-rescue` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-sha256` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-uni-stark` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |
| `p3-util` | MIT OR Apache-2.0 | crates.io v0.3.0 | ZK/STARK primitive within Plonky3 suite (cryptography) |

The upstream git dependency (`p3-multilinear-util`) is pinned to
commit `80803612ff4b6634519e12fa4bf075f679afcc1c`, matching the version the
backend was validated against.【F:docs/third_party/plonky3_deps.json†L109-L138】

## Optional GPU helpers

Enabling the `plonky3-gpu` feature pulls in GPU allocation helpers from
crates.io and activates the lightweight shim in
`prover/plonky3_backend/src/gpu.rs`, which wires the descriptor allocator and
warm-up requests into the backend for smoke testing.【F:prover/plonky3_backend/Cargo.toml†L8-L15】【F:prover/plonky3_backend/src/gpu.rs†L1-L37】
The pinned versions and licenses are captured in
`docs/third_party/plonky3_gpu_deps.json` for offline auditing.【F:docs/third_party/plonky3_gpu_deps.json†L1-L64】

| Crate | License | Source pin | Export assessment |
| --- | --- | --- | --- |
| `gpu-alloc` | MIT OR Apache-2.0 | crates.io v0.6.0 | GPU memory allocator used when `plonky3-gpu` is enabled |
| `gpu-descriptor` | MIT OR Apache-2.0 | crates.io v0.3.2 | GPU descriptor heap utility used when `plonky3-gpu` is enabled |

