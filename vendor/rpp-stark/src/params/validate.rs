use super::hash::params_hash;
use super::types::{
    ChallengeBounds, FieldKind, HashFamily, HashKind, LdeOrder, MerkleArity, SecurityBudget,
};
use super::StarkParams;

/// Result of a successful validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    /// Canonical parameter hash derived during validation.
    pub params_hash: [u8; 32],
}

/// Error enumeration for parameter validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamsError {
    /// LDE blowup factor was below the allowed threshold.
    InvalidBlowup { min: u32, got: u32 },
    /// Number of FRI queries was below the allowed threshold.
    InvalidQueries { min: u16, got: u16 },
    /// FRI folding parameter `r` was below the minimum.
    InvalidFriR { min: u8, got: u8 },
    /// FRI layer count was below the minimum.
    InvalidFriLayers { min: u8, got: u8 },
    /// Evaluation domain exponent was too small.
    DomainTooSmall { min: u16, got: u16 },
    /// Transcript protocol tag must be non-zero.
    InvalidProtocolTag,
    /// Challenge bounds were invalid (`minimum` must be non-zero and ≤ `maximum`).
    InvalidChallengeBounds { minimum: u8, maximum: u8 },
    /// Merkle leaves must contain at least one field element.
    LeafWidthZero,
    /// Maximum proof size must be at least the specified threshold.
    MaxProofTooSmall { min: u32, got: u32 },
    /// Proof version must match the parameter schema version.
    VersionMismatch { params: u16, proof: u16 },
    /// Field and hash combination is not supported by the implementation.
    IncompatibleFieldHash { field: FieldKind, hash: HashKind },
    /// Security target bits were below the minimum threshold.
    SecurityBudgetTooLow { min: u16, got: u16 },
    /// Slack bits exceeded the allowed ratio of the target bits.
    SecuritySlackTooLarge { slack: u8, max_allowed: u8 },
    /// Serialisation failure when processing the parameter set.
    SerializationError { kind: crate::ser::SerKind },
}

/// Validates all Stark parameter invariants and returns a [`ValidationReport`].
pub fn validate(params: &StarkParams) -> Result<ValidationReport, ParamsError> {
    validate_lde(params.lde.blowup, params.lde.order)?;
    validate_fri(
        params.fri.r,
        params.fri.queries,
        params.fri.domain_log2,
        params.fri.num_layers,
    )?;
    validate_merkle(params.merkle.arity, params.merkle.leaf_width)?;
    validate_transcript(
        params.transcript.protocol_tag,
        &params.transcript.challenge_bounds,
    )?;
    validate_proof(
        params.params_version,
        params.proof.version,
        params.proof.max_size_kb,
    )?;
    validate_security(&params.security)?;
    validate_field_hash(params.field, params.hash)?;
    Ok(ValidationReport {
        params_hash: params_hash(params),
    })
}

fn validate_lde(blowup: u32, order: LdeOrder) -> Result<(), ParamsError> {
    let _ = order;
    if blowup < 2 {
        return Err(ParamsError::InvalidBlowup {
            min: 2,
            got: blowup,
        });
    }
    Ok(())
}

fn validate_fri(r: u8, queries: u16, domain_log2: u16, num_layers: u8) -> Result<(), ParamsError> {
    if r < 1 {
        return Err(ParamsError::InvalidFriR { min: 1, got: r });
    }
    if queries < 1 {
        return Err(ParamsError::InvalidQueries {
            min: 1,
            got: queries,
        });
    }
    if domain_log2 < 8 {
        return Err(ParamsError::DomainTooSmall {
            min: 8,
            got: domain_log2,
        });
    }
    if num_layers < 1 {
        return Err(ParamsError::InvalidFriLayers {
            min: 1,
            got: num_layers,
        });
    }
    Ok(())
}

fn validate_merkle(arity: MerkleArity, leaf_width: u8) -> Result<(), ParamsError> {
    if leaf_width == 0 {
        return Err(ParamsError::LeafWidthZero);
    }
    let _ = arity;
    Ok(())
}

fn validate_transcript(protocol_tag: u64, bounds: &ChallengeBounds) -> Result<(), ParamsError> {
    if protocol_tag == 0 {
        return Err(ParamsError::InvalidProtocolTag);
    }
    if bounds.minimum == 0 || bounds.minimum > bounds.maximum {
        return Err(ParamsError::InvalidChallengeBounds {
            minimum: bounds.minimum,
            maximum: bounds.maximum,
        });
    }
    Ok(())
}

fn validate_proof(
    params_version: u16,
    proof_version: u16,
    max_size_kb: u32,
) -> Result<(), ParamsError> {
    if params_version != proof_version {
        return Err(ParamsError::VersionMismatch {
            params: params_version,
            proof: proof_version,
        });
    }
    if max_size_kb < 8 {
        return Err(ParamsError::MaxProofTooSmall {
            min: 8,
            got: max_size_kb,
        });
    }
    Ok(())
}

fn validate_security(security: &SecurityBudget) -> Result<(), ParamsError> {
    if security.target_bits < 64 {
        return Err(ParamsError::SecurityBudgetTooLow {
            min: 64,
            got: security.target_bits,
        });
    }
    let max_allowed = (security.target_bits / 2) as u8;
    if security.soundness_slack_bits > max_allowed {
        return Err(ParamsError::SecuritySlackTooLarge {
            slack: security.soundness_slack_bits,
            max_allowed,
        });
    }
    Ok(())
}

fn validate_field_hash(field: FieldKind, hash: HashKind) -> Result<(), ParamsError> {
    let family = hash.family();
    let supported = match field {
        FieldKind::Goldilocks => matches!(family, HashFamily::Poseidon2 | HashFamily::Blake2s),
        FieldKind::Bn254 => matches!(family, HashFamily::Rescue | HashFamily::Blake2s),
    };
    if !supported {
        return Err(ParamsError::IncompatibleFieldHash { field, hash });
    }
    Ok(())
}
