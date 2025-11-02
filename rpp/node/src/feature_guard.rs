#![allow(dead_code)]

#[cfg(all(feature = "backend-plonky3", feature = "prover-mock"))]
compile_error!(
    "The Plonky3 backend cannot be combined with the mock prover feature. Disable `prover-mock` when enabling `backend-plonky3`.",
);
