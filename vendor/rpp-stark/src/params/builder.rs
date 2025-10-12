use super::types::{
    ChallengeBounds, Endianness, FieldKind, FriFolding, FriParams, HashKind, LdeOrder, LdeParams,
    MerkleArity, MerkleParams, ProofParams, SecurityBudget, TranscriptParams,
};
use super::{ParamsError, StarkParams};

/// Builder used to assemble [`StarkParams`] with validation.
///
/// | Field | Default |
/// |-------|---------|
/// | `params_version` | `1` |
/// | `field` | [`FieldKind::Goldilocks`] |
/// | `hash` | [`HashKind::Poseidon2 { parameter_set: 0 }`] |
/// | `lde` | Blowup `8`, row-major order, coset tag `0x504152414d533031` |
/// | `fri` | `r = 4`, `queries = 30`, `domain_log2 = 22`, natural folding, `num_layers = 5` |
/// | `merkle` | Little-endian leaves, width `4`, binary arity, domain sep `0x4d4b4c5f50415231` |
/// | `transcript` | Protocol tag `0x5354524b5f50524f`, deterministic seed, challenge bounds `16..=64` |
/// | `proof` | Version `1`, `max_size_kb = 512` |
/// | `security` | Target `96` bits, slack `16` bits |
#[derive(Debug, Clone)]
pub struct StarkParamsBuilder {
    pub params_version: u16,
    pub field: FieldKind,
    pub hash: HashKind,
    pub lde: LdeParams,
    pub fri: FriParams,
    pub merkle: MerkleParams,
    pub transcript: TranscriptParams,
    pub proof: ProofParams,
    pub security: SecurityBudget,
}

impl StarkParamsBuilder {
    /// Returns a builder initialised with safe defaults.
    pub fn new() -> Self {
        Self::from_profile(BuiltinProfile::PROFILE_X8)
    }

    /// Loads one of the built-in profiles.
    ///
    /// | Profile | Description | Field | Hash | Blowup | Queries | Arity | Target Bits |
    /// |---------|-------------|-------|------|--------|---------|-------|-------------|
    /// | `PROFILE_X8` | Balanced performance profile with blowup 8 | Goldilocks | Poseidon2 (set 0) | 8 | 30 | Binary | 96 |
    /// | `PROFILE_HISEC_X16` | High security profile with blowup 16 | BN254 | Rescue (set 1) | 16 | 48 | Quaternary | 128 |
    pub fn from_profile(profile: BuiltinProfile) -> Self {
        match profile {
            BuiltinProfile::PROFILE_X8 => StarkParamsBuilder {
                params_version: 1,
                field: FieldKind::Goldilocks,
                hash: HashKind::Poseidon2 { parameter_set: 0 },
                lde: LdeParams {
                    blowup: 8,
                    order: LdeOrder::RowMajor,
                    coset_tag: 0x5041_5241_4d53_3031,
                },
                fri: FriParams {
                    r: 4,
                    queries: 30,
                    domain_log2: 22,
                    folding: FriFolding::Natural,
                    num_layers: 5,
                },
                merkle: MerkleParams {
                    leaf_encoding: Endianness::Little,
                    leaf_width: 4,
                    arity: MerkleArity::Binary,
                    domain_sep: 0x4d4b_4c5f_5041_5231,
                },
                transcript: TranscriptParams {
                    protocol_tag: 0x5354_524b_5f50_524f,
                    seed: *b"RPP-STARK-PROFILE-X8___________0",
                    challenge_bounds: ChallengeBounds {
                        minimum: 16,
                        maximum: 64,
                    },
                },
                proof: ProofParams {
                    version: 1,
                    max_size_kb: 512,
                },
                security: SecurityBudget {
                    target_bits: 96,
                    soundness_slack_bits: 16,
                },
            },
            BuiltinProfile::PROFILE_HISEC_X16 => StarkParamsBuilder {
                params_version: 2,
                field: FieldKind::Bn254,
                hash: HashKind::Rescue { parameter_set: 1 },
                lde: LdeParams {
                    blowup: 16,
                    order: LdeOrder::ColMajor,
                    coset_tag: 0x5041_5241_4d53_4831,
                },
                fri: FriParams {
                    r: 5,
                    queries: 48,
                    domain_log2: 26,
                    folding: FriFolding::Coset,
                    num_layers: 6,
                },
                merkle: MerkleParams {
                    leaf_encoding: Endianness::Big,
                    leaf_width: 8,
                    arity: MerkleArity::Quaternary,
                    domain_sep: 0x484d_524b_5f48_4953,
                },
                transcript: TranscriptParams {
                    protocol_tag: 0x5354_524b_5f48_4953,
                    seed: *b"RPP-STARK-HISEC-X16___________00",
                    challenge_bounds: ChallengeBounds {
                        minimum: 24,
                        maximum: 96,
                    },
                },
                proof: ProofParams {
                    version: 2,
                    max_size_kb: 768,
                },
                security: SecurityBudget {
                    target_bits: 128,
                    soundness_slack_bits: 32,
                },
            },
        }
    }

    /// Validates the builder fields and emits a [`StarkParams`] instance.
    pub fn build(&self) -> Result<StarkParams, ParamsError> {
        StarkParams::try_from_builder(self)
    }
}

/// Supported built-in profiles.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinProfile {
    /// Balanced performance profile with blowup 8.
    PROFILE_X8,
    /// High security profile with blowup 16.
    PROFILE_HISEC_X16,
}

impl Default for StarkParamsBuilder {
    fn default() -> Self {
        Self::new()
    }
}
