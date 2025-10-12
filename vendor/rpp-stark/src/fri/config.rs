//! Canonical configuration descriptions for the FRI protocol.
//! Provides named profiles that are shared between prover and verifier.

/// Canonical digest representation for a FRI parameter set.
///
/// The digest is computed over the canonical serialization of the
/// folding factor, folding mode, query schedule, and target depth
/// using BLAKE3.
/// The hexadecimal strings exposed below allow integrators to pin
/// protocol parameters without embedding executable verification logic.
pub type ParameterDigest = &'static str;

/// Describes a complete FRI profile that can be referenced by the
/// STARK configuration and transcript builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FriProfile {
    /// Human readable profile identifier.
    pub name: &'static str,
    /// Folding factor applied to each layer; we expose the canonical binary
    /// folding schedule in this module.
    pub folding_factor: usize,
    /// Number of sampling queries performed by the verifier.
    pub query_count: usize,
    /// Target depth (logarithmic size) of the final layer after folding.
    pub target_depth: usize,
    /// Digest binding the profile to a concrete transcript layout.
    pub parameter_digest: ParameterDigest,
}

/// Standard security profile targeting typical rollup deployments.
pub const STANDARD_FRI_PROFILE: FriProfile = FriProfile {
    name: "standard",
    folding_factor: 2,
    query_count: 64,
    target_depth: 6,
    parameter_digest: "5570706d57436b4fa198d0e8c8a6d3fa01d8c348c602248b066ee8f3fe0eb566",
};

/// High security profile with an increased query budget.
pub const HISEC_FRI_PROFILE: FriProfile = FriProfile {
    name: "hisec",
    folding_factor: 2,
    query_count: 96,
    target_depth: 8,
    parameter_digest: "40b923845a41a78da7bdef951f541ae1b6b30794b0244a54b19fc5801d686b06",
};
