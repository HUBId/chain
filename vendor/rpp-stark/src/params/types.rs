use serde::{Deserialize, Serialize};

/// Prime field families supported by the STARK pipeline.
///
/// | Variant | Modulus | Notes |
/// |---------|---------|-------|
/// | `Goldilocks` | 2<sup>64</sup> - 2<sup>32</sup> + 1 | Default field for polynomial arithmetic. |
/// | `Bn254` | BN254 scalar field | Suitable for pairing-friendly aggregation. |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldKind {
    /// Goldilocks prime field.
    Goldilocks,
    /// BN254 scalar field.
    Bn254,
}

impl FieldKind {
    pub(crate) const fn code(self) -> u16 {
        match self {
            FieldKind::Goldilocks => 1,
            FieldKind::Bn254 => 2,
        }
    }

    pub(crate) const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(FieldKind::Goldilocks),
            2 => Some(FieldKind::Bn254),
            _ => None,
        }
    }
}

/// Hash families that may be used for commitments and transcripts.
///
/// | Variant | Digest Bits | Notes |
/// |---------|-------------|-------|
/// | `Poseidon2` | 256 | Algebraic sponge tuned for Goldilocks. |
/// | `Rescue` | 256 | Algebraic cipher for prime fields. |
/// | `Blake2s` | 256 | Byte-oriented Blake2s XOF. |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum HashFamily {
    /// Poseidon2 algebraic sponge.
    Poseidon2,
    /// Rescue prime field hash.
    Rescue,
    /// Blake2s byte hash.
    #[default]
    Blake2s,
}

impl HashFamily {
    pub(crate) const fn code(self) -> u8 {
        match self {
            HashFamily::Poseidon2 => 1,
            HashFamily::Rescue => 2,
            HashFamily::Blake2s => 3,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(HashFamily::Poseidon2),
            2 => Some(HashFamily::Rescue),
            3 => Some(HashFamily::Blake2s),
            _ => None,
        }
    }
}

/// Specific hash kind including parameter identifiers.
///
/// | Variant | Parameter Column | Description |
/// |---------|-----------------|-------------|
/// | `Poseidon2 { parameter_set }` | Sponge width identifier | Field-optimised Poseidon2. |
/// | `Rescue { parameter_set }` | S-box width identifier | Rescue prime cipher. |
/// | `Blake2s { digest_size }` | Output bytes | Byte-level Blake2s digests. |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashKind {
    /// Poseidon2 sponge with a concrete parameter set identifier.
    Poseidon2 { parameter_set: u16 },
    /// Rescue sponge with a concrete parameter set identifier.
    Rescue { parameter_set: u16 },
    /// Blake2s configuration with a digest size identifier.
    Blake2s { digest_size: u16 },
}

impl HashKind {
    /// Returns the hash family backing this configuration.
    pub const fn family(self) -> HashFamily {
        match self {
            HashKind::Poseidon2 { .. } => HashFamily::Poseidon2,
            HashKind::Rescue { .. } => HashFamily::Rescue,
            HashKind::Blake2s { .. } => HashFamily::Blake2s,
        }
    }

    pub(crate) const fn parameter_id(self) -> u16 {
        match self {
            HashKind::Poseidon2 { parameter_set }
            | HashKind::Rescue { parameter_set }
            | HashKind::Blake2s {
                digest_size: parameter_set,
            } => parameter_set,
        }
    }

    pub(crate) const fn from_codes(family: HashFamily, parameter: u16) -> Self {
        match family {
            HashFamily::Poseidon2 => HashKind::Poseidon2 {
                parameter_set: parameter,
            },
            HashFamily::Rescue => HashKind::Rescue {
                parameter_set: parameter,
            },
            HashFamily::Blake2s => HashKind::Blake2s {
                digest_size: parameter,
            },
        }
    }
}

/// Memory ordering for Low Degree Extension tables.
///
/// | Variant | Layout |
/// |---------|--------|
/// | `RowMajor` | Row-wise stride |
/// | `ColMajor` | Column-wise stride |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LdeOrder {
    /// Rows are laid out sequentially.
    RowMajor,
    /// Columns are laid out sequentially.
    ColMajor,
}

impl LdeOrder {
    pub(crate) const fn code(self) -> u8 {
        match self {
            LdeOrder::RowMajor => 1,
            LdeOrder::ColMajor => 2,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(LdeOrder::RowMajor),
            2 => Some(LdeOrder::ColMajor),
            _ => None,
        }
    }
}

/// Low Degree Extension configuration.
///
/// | Field | Type | Endianness |
/// |-------|------|------------|
/// | `blowup` | `u32` | Little-endian |
/// | `order` | [`LdeOrder`] | `u8` discriminant |
/// | `coset_tag` | `u64` | Little-endian |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdeParams {
    /// Multiplicative blowup factor for the evaluation domain.
    pub blowup: u32,
    /// Memory layout of the extended trace table.
    pub order: LdeOrder,
    /// Domain separation tag for coset selection.
    pub coset_tag: u64,
}

/// FRI folding schedule.
///
/// | Variant | Meaning |
/// |---------|---------|
/// | `Natural` | Standard binary folding. |
/// | `Coset` | Coset switching between rounds. |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FriFolding {
    /// Natural folding strategy.
    Natural,
    /// Coset switching folding strategy.
    Coset,
}

impl FriFolding {
    pub(crate) const fn code(self) -> u8 {
        match self {
            FriFolding::Natural => 1,
            FriFolding::Coset => 2,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(FriFolding::Natural),
            2 => Some(FriFolding::Coset),
            _ => None,
        }
    }
}

/// Parameters for the FRI proof system.
///
/// | Field | Type | Endianness |
/// |-------|------|------------|
/// | `r` | `u8` | Little-endian |
/// | `queries` | `u16` | Little-endian |
/// | `domain_log2` | `u16` | Little-endian |
/// | `folding` | [`FriFolding`] | `u8` discriminant |
/// | `num_layers` | `u8` | Little-endian |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriParams {
    /// Number of constraints combined per FRI round.
    pub r: u8,
    /// Number of queries performed during verification.
    pub queries: u16,
    /// Log<sub>2</sub> of the evaluation domain size.
    pub domain_log2: u16,
    /// Folding strategy across layers.
    pub folding: FriFolding,
    /// Number of FRI layers executed.
    pub num_layers: u8,
}

/// Merkle arity options supported by the commitment scheme.
///
/// | Variant | Branching |
/// |---------|-----------|
/// | `Binary` | 2 |
/// | `Quaternary` | 4 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MerkleArity {
    /// Binary Merkle tree.
    Binary,
    /// Quaternary Merkle tree.
    Quaternary,
}

impl MerkleArity {
    pub(crate) const fn code(self) -> u8 {
        match self {
            MerkleArity::Binary => 2,
            MerkleArity::Quaternary => 4,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            2 => Some(MerkleArity::Binary),
            4 => Some(MerkleArity::Quaternary),
            _ => None,
        }
    }
}

/// Endianness for byte encodings.
///
/// | Variant | Description |
/// |---------|-------------|
/// | `Little` | Little-endian byte order. |
/// | `Big` | Big-endian byte order. |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    /// Little-endian representation.
    Little,
    /// Big-endian representation.
    Big,
}

impl Endianness {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Endianness::Little => 1,
            Endianness::Big => 2,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Endianness::Little),
            2 => Some(Endianness::Big),
            _ => None,
        }
    }
}

/// Merkle commitment parameters.
///
/// | Field | Type | Endianness |
/// |-------|------|------------|
/// | `leaf_encoding` | [`Endianness`] | `u8` discriminant |
/// | `leaf_width` | `u8` | Little-endian |
/// | `arity` | [`MerkleArity`] | Branching encoded as `u8` |
/// | `domain_sep` | `u64` | Little-endian |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleParams {
    /// Byte order for leaf encoding.
    pub leaf_encoding: Endianness,
    /// Number of field elements per leaf.
    pub leaf_width: u8,
    /// Tree branching factor.
    pub arity: MerkleArity,
    /// Domain separation tag for commitments.
    pub domain_sep: u64,
}

/// Bounds for transcript challenge sampling.
///
/// | Field | Type | Endianness |
/// |-------|------|------------|
/// | `minimum` | `u8` | Little-endian |
/// | `maximum` | `u8` | Little-endian |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeBounds {
    /// Minimum number of transcript challenges required.
    pub minimum: u8,
    /// Maximum number of transcript challenges allowed.
    pub maximum: u8,
}

/// Transcript configuration for Fiat–Shamir.
///
/// | Field | Type | Endianness |
/// |-------|------|------------|
/// | `protocol_tag` | `u64` | Little-endian |
/// | `seed` | `[u8; 32]` | Native order |
/// | `challenge_bounds` | [`ChallengeBounds`] | LE scalars |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptParams {
    /// Non-zero domain separation tag.
    pub protocol_tag: u64,
    /// Seed for deterministic transcript initialisation.
    pub seed: [u8; 32],
    /// Challenge sampling bounds.
    pub challenge_bounds: ChallengeBounds,
}

/// Proof envelope configuration.
///
/// | Field | Type | Endianness |
/// |-------|------|------------|
/// | `version` | `u16` | Little-endian |
/// | `max_size_kb` | `u32` | Little-endian |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofParams {
    /// Proof envelope version.
    pub version: u16,
    /// Maximum proof size in kilobytes.
    pub max_size_kb: u32,
}

/// Security budget controlling soundness slack.
///
/// | Field | Type | Endianness |
/// |-------|------|------------|
/// | `target_bits` | `u16` | Little-endian |
/// | `soundness_slack_bits` | `u8` | Little-endian |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityBudget {
    /// Target bits of soundness.
    pub target_bits: u16,
    /// Slack bits allocated for batching or composition.
    pub soundness_slack_bits: u8,
}
