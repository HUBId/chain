# Toolchain Compatibility Matrix

| Component | Feature Flags | Toolchain | Notes |
| --- | --- | --- | --- |
| Workspace default | *(none)* | Rust 1.79 | Stable verifier-only build; STWO prover disabled. |
| Workspace + `backend-rpp-stark` | `backend-rpp-stark` | Rust 1.79 | Stable verifier stack with RPP-STARK integration. |
| Workspace + `prover-stwo` | `prover-stwo` | Rust nightly | Guard rails emit compile errors on stable builds to avoid accidental activation. |
| Workspace + `prover-stwo,prover-stwo-simd` | `prover-stwo,prover-stwo-simd` | Rust nightly | Optional SIMD profile; covered by the nightly prover workflow. |

> Nightly-only rows require `cargo +nightly …` invocations. Attempting to compile them on stable triggers the message:
> “STWO Prover requires Rust nightly (portable_simd / array_chunks etc.). Build without these features or use Nightly.”
