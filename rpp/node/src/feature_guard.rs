#![allow(dead_code)]

#[cfg(all(
    any(feature = "backend-plonky3", feature = "backend-plonky3-gpu"),
    feature = "prover-mock",
))]
compile_error!(
    "The Plonky3 backend cannot be combined with the mock prover feature. Disable `prover-mock` when enabling `backend-plonky3` or `backend-plonky3-gpu`.",
);
