use serde::{Deserialize, Serialize};

use super::hash::params_hash;
use super::types::{
    FieldKind, FriParams, HashKind, LdeParams, MerkleParams, ProofParams, SecurityBudget,
    TranscriptParams,
};
use super::validate::ParamsError;

/// Canonical STARK parameter set shared by prover and verifier.
///
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `params_version` | `u16` | Version of the parameter schema. |
/// | `field` | [`FieldKind`] | Prime field used for polynomial arithmetic. |
/// | `hash` | [`HashKind`] | Hash function selection including parameter identifier. |
/// | `lde` | [`LdeParams`] | Low Degree Extension configuration. |
/// | `fri` | [`FriParams`] | Fast Reed–Solomon IOP configuration. |
/// | `merkle` | [`MerkleParams`] | Merkle commitment encoding options. |
/// | `transcript` | [`TranscriptParams`] | Fiat–Shamir transcript framing. |
/// | `proof` | [`ProofParams`] | Proof envelope layout. |
/// | `security` | [`SecurityBudget`] | Global soundness budget. |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarkParams {
    pub(crate) params_version: u16,
    pub(crate) field: FieldKind,
    pub(crate) hash: HashKind,
    pub(crate) lde: LdeParams,
    pub(crate) fri: FriParams,
    pub(crate) merkle: MerkleParams,
    pub(crate) transcript: TranscriptParams,
    pub(crate) proof: ProofParams,
    pub(crate) security: SecurityBudget,
}

impl StarkParams {
    /// Returns the parameter schema version.
    pub const fn params_version(&self) -> u16 {
        self.params_version
    }

    /// Returns the selected prime field.
    pub const fn field(&self) -> FieldKind {
        self.field
    }

    /// Returns the configured hash function.
    pub const fn hash(&self) -> HashKind {
        self.hash
    }

    /// Returns the Low Degree Extension configuration.
    pub const fn lde(&self) -> &LdeParams {
        &self.lde
    }

    /// Returns the FRI configuration.
    pub const fn fri(&self) -> &FriParams {
        &self.fri
    }

    /// Returns the Merkle configuration.
    pub const fn merkle(&self) -> &MerkleParams {
        &self.merkle
    }

    /// Returns the transcript configuration.
    pub const fn transcript(&self) -> &TranscriptParams {
        &self.transcript
    }

    /// Returns the proof envelope configuration.
    pub const fn proof(&self) -> &ProofParams {
        &self.proof
    }

    /// Returns the security budget configuration.
    pub const fn security(&self) -> &SecurityBudget {
        &self.security
    }

    /// Computes the canonical parameter hash.
    ///
    /// The digest is computed over the canonical byte layout defined in
    /// [`crate::params::serialize_params`].
    pub fn params_hash(&self) -> [u8; 32] {
        params_hash(self)
    }

    /// Produces a human-readable profile identifier.
    ///
    /// The identifier is deterministic and contains only ASCII alphanumeric
    /// characters and underscores.  It does not leak any secret material.
    pub fn profile_id(&self) -> String {
        format!(
            "{}_F{}_H{}{}_B{}_Q{}_A{}_V{}",
            match self.security.target_bits {
                bits if bits >= 128 => "PROFILE_HISEC",
                _ => "PROFILE",
            },
            self.field.code(),
            self.hash.family().code(),
            self.hash.parameter_id(),
            self.lde.blowup,
            self.fri.queries,
            self.merkle.arity.code(),
            self.proof.version
        )
    }

    /// Checks whether two parameter sets are compatible on security-critical fields.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.field == other.field
            && self.hash == other.hash
            && self.merkle.arity == other.merkle.arity
            && self.merkle.leaf_encoding == other.merkle.leaf_encoding
            && self.merkle.leaf_width == other.merkle.leaf_width
            && self.transcript.protocol_tag == other.transcript.protocol_tag
            && self.proof.version == other.proof.version
    }

    pub(crate) fn try_from_builder(
        builder: &super::builder::StarkParamsBuilder,
    ) -> Result<Self, ParamsError> {
        let params = Self {
            params_version: builder.params_version,
            field: builder.field,
            hash: builder.hash,
            lde: builder.lde,
            fri: builder.fri,
            merkle: builder.merkle,
            transcript: builder.transcript,
            proof: builder.proof,
            security: builder.security,
        };
        let _ = super::validate::validate(&params)?;
        Ok(params)
    }
}
