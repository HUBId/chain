#[cfg(all(
    feature = "backend-plonky3",
    any(feature = "prod", feature = "validator")
))]
compile_error!(
    "The experimental Plonky3 backend cannot be enabled together with the `prod` or `validator` features."
);
