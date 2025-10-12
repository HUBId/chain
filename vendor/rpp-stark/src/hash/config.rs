//! Hash configuration definitions shared across prover and verifier.
//! Parameters ensure deterministic hash usage within transcripts and commitments.

/// Version identifier for the Poseidon parameter set with `t = 12`.
pub const POSEIDON_PARAMETERS_V1_ID: &str = "poseidon-v1-t12-r8-c4-alpha5-rf8-rp56";

/// Domain separation tag applied to arithmetic hashes performed inside the field.
pub const POSEIDON_ARITHMETIC_DOMAIN_TAG: &[u8] = b"rpp-stark:poseidon:arith";

/// Version identifier for the Blake2s transcript hash used for commitments.
pub const BLAKE2S_PARAMETERS_V1_ID: &str = "blake2s-v1-transcript";

/// Domain separation tag for Blake2s when hashing external commitments or transcript data.
pub const BLAKE2S_COMMITMENT_DOMAIN_TAG: &[u8] = b"rpp-stark:blake2s:commit";

/// Poseidon parameter set descriptor.
#[derive(Debug, Clone, Copy)]
pub struct PoseidonParameters {
    /// Version identifier matching [`POSEIDON_PARAMETERS_V1_ID`].
    pub id: &'static str,
    /// Domain separation tag for arithmetic sponge usage.
    pub domain_tag: &'static [u8],
    /// Number of full rounds in the permutation.
    pub full_rounds: usize,
    /// Number of partial rounds in the permutation.
    pub partial_rounds: usize,
    /// Width of the permutation state.
    pub width: usize,
}

impl PoseidonParameters {
    /// Creates a new parameter set with deterministic defaults.
    pub const fn new(
        id: &'static str,
        domain_tag: &'static [u8],
        full_rounds: usize,
        partial_rounds: usize,
        width: usize,
    ) -> Self {
        Self {
            id,
            domain_tag,
            full_rounds,
            partial_rounds,
            width,
        }
    }
}

/// Blake2s parameter descriptor for transcript usage.
#[derive(Debug, Clone, Copy)]
pub struct Blake2sParameters {
    /// Version identifier matching [`BLAKE2S_PARAMETERS_V1_ID`].
    pub id: &'static str,
    /// Fixed domain separation label applied to every message chunk.
    pub domain_tag: &'static [u8],
}

impl Blake2sParameters {
    /// Creates a new descriptor.
    pub const fn new(id: &'static str, domain_tag: &'static [u8]) -> Self {
        Self { id, domain_tag }
    }
}

/// Aggregate hash parameters used by the STARK engine.
#[derive(Debug, Clone, Copy)]
pub struct HashParameters {
    /// Poseidon permutation configuration.
    pub poseidon: PoseidonParameters,
    /// Blake2s transcript configuration.
    pub blake2s: Blake2sParameters,
}

impl HashParameters {
    /// Constructs aggregate parameters.
    pub const fn new(poseidon: PoseidonParameters, blake2s: Blake2sParameters) -> Self {
        Self { poseidon, blake2s }
    }
}
