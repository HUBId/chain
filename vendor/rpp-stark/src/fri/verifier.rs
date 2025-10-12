use super::folding::{coset_shift_schedule, next_domain_size, parent_index};
use super::layer::verify_query_opening;
use super::proof::{derive_query_positions, hash_final_layer, FriProof};
use super::types::{FriError, FriSecurityLevel};
use super::{fe_mul, fe_sub, hash_leaf, BINARY_FOLD_ARITY};
use crate::field::prime_field::FieldElementOps;
use crate::field::FieldElement;
use crate::hash::merkle::EMPTY_DIGEST;
use crate::params::StarkParams;
use crate::transcript::{Transcript, TranscriptError, TranscriptLabel};
use crate::utils::serialization::DigestBytes;

fn map_transcript_error(err: TranscriptError) -> FriError {
    match err {
        TranscriptError::InvalidLabel => FriError::InvalidStructure("transcript-label"),
        TranscriptError::RangeZero => FriError::InvalidStructure("transcript-range"),
        TranscriptError::Overflow => FriError::InvalidStructure("transcript-overflow"),
        TranscriptError::Serialization(_) => FriError::InvalidStructure("transcript-ser"),
        TranscriptError::BoundsViolation => FriError::InvalidStructure("transcript-bounds"),
        TranscriptError::Unsupported => FriError::InvalidStructure("transcript-unsupported"),
        TranscriptError::DeterministicHash(err) => FriError::DeterministicHash(err),
    }
}

fn security_level_from_query_count(count: usize) -> Result<FriSecurityLevel, FriError> {
    if count == FriSecurityLevel::Standard.query_budget() {
        Ok(FriSecurityLevel::Standard)
    } else if count == FriSecurityLevel::HiSec.query_budget() {
        Ok(FriSecurityLevel::HiSec)
    } else if count == FriSecurityLevel::Throughput.query_budget() {
        Ok(FriSecurityLevel::Throughput)
    } else {
        Err(FriError::InvalidStructure("unsupported-query-count"))
    }
}

pub fn fri_verify(
    proof: &FriProof,
    params: &StarkParams,
    transcript: &mut Transcript,
) -> Result<(), FriError> {
    if proof.initial_domain_size == 0 {
        return Err(FriError::EmptyCodeword);
    }

    let expected_domain_size = 1usize << (params.fri().domain_log2 as usize);
    if proof.initial_domain_size != expected_domain_size {
        return Err(FriError::InvalidStructure("initial-domain-size"));
    }

    let query_count = params.fri().queries as usize;
    let security_level = security_level_from_query_count(query_count)?;
    if proof.security_level != security_level {
        return Err(FriError::SecurityLevelMismatch);
    }

    if proof.queries.len() != query_count {
        return Err(FriError::QueryBudgetMismatch {
            expected: query_count,
            actual: proof.queries.len(),
        });
    }

    let num_layers = params.fri().num_layers as usize;
    if proof.layer_roots.len() != num_layers {
        return Err(FriError::InvalidStructure("layer-count"));
    }
    if proof.fold_challenges.len() != num_layers {
        return Err(FriError::InvalidStructure("fold challenge length"));
    }

    let residual_bound = params.fri().r as usize;
    if proof.final_polynomial.len() > residual_bound {
        return Err(FriError::InvalidStructure("final-polynomial-length"));
    }

    let recomputed_digest = hash_final_layer(&proof.final_polynomial)?;
    if recomputed_digest != proof.final_polynomial_digest {
        return Err(FriError::LayerRootMismatch { layer: num_layers });
    }

    let coset_shifts = coset_shift_schedule(params, num_layers);

    for (layer_index, root) in proof.layer_roots.iter().enumerate() {
        if layer_index > u8::MAX as usize {
            return Err(FriError::InvalidStructure("layer-index-overflow"));
        }
        transcript
            .absorb_digest(
                TranscriptLabel::FriRoot(layer_index as u8),
                &DigestBytes { bytes: *root },
            )
            .map_err(map_transcript_error)?;
        let eta = transcript
            .challenge_field(TranscriptLabel::FriFoldChallenge(layer_index as u8))
            .map_err(map_transcript_error)?;
        let expected = proof
            .fold_challenges
            .get(layer_index)
            .copied()
            .ok_or(FriError::InvalidStructure("missing-fold-challenge"))?;
        if eta != expected {
            return Err(FriError::InvalidStructure("fold challenge mismatch"));
        }
    }

    let count_bytes = (query_count as u32).to_le_bytes();
    transcript
        .absorb_bytes(TranscriptLabel::QueryCount, &count_bytes)
        .map_err(map_transcript_error)?;
    let query_seed_bytes = transcript
        .challenge_bytes(TranscriptLabel::QueryIndexStream, 32)
        .map_err(map_transcript_error)?;
    let mut query_seed = [0u8; 32];
    query_seed.copy_from_slice(&query_seed_bytes);

    let positions = derive_query_positions(query_seed, query_count, proof.initial_domain_size)?;
    if positions.len() != proof.queries.len() {
        return Err(FriError::InvalidStructure("query count mismatch"));
    }

    for (expected_position, query) in positions.iter().zip(proof.queries.iter()) {
        if query.position != *expected_position {
            return Err(FriError::InvalidStructure("query position mismatch"));
        }
        if query.layers.len() != num_layers {
            return Err(FriError::InvalidStructure("layer count mismatch"));
        }

        let mut index = *expected_position;
        let mut domain_size = proof.initial_domain_size;
        for (layer_index, coset_shift) in coset_shifts.iter().take(num_layers).enumerate() {
            let opening = &query.layers[layer_index];
            let root = &proof.layer_roots[layer_index];
            verify_query_opening(layer_index, opening, root, index, domain_size)?;

            let first = opening
                .path
                .first()
                .ok_or(FriError::InvalidStructure("merkle-path-empty"))?;
            let child_position = first.index.0 as usize;
            if child_position >= BINARY_FOLD_ARITY {
                return Err(FriError::InvalidStructure("merkle-index"));
            }
            if index % BINARY_FOLD_ARITY != child_position {
                return Err(FriError::InvalidStructure("pair-index-mismatch"));
            }

            let beta = proof.fold_challenges[layer_index];
            let parent_value = if layer_index + 1 < num_layers {
                query.layers[layer_index + 1].value
            } else {
                query.final_value
            };

            let sibling_digest = first.siblings[0];
            match child_position {
                0 => {
                    let diff = fe_sub(parent_value, opening.value);
                    let beta_shift = fe_mul(beta, *coset_shift);
                    if beta_shift == FieldElement::ZERO {
                        if diff != FieldElement::ZERO {
                            return Err(FriError::FoldingConstraintViolated { layer: layer_index });
                        }
                    } else {
                        let inv = beta_shift
                            .inv()
                            .ok_or(FriError::FoldingConstraintViolated { layer: layer_index })?;
                        let sibling_value = fe_mul(diff, inv);
                        if sibling_digest == EMPTY_DIGEST {
                            if sibling_value != FieldElement::ZERO {
                                return Err(FriError::FoldingConstraintViolated {
                                    layer: layer_index,
                                });
                            }
                        } else if hash_leaf(&sibling_value)? != sibling_digest {
                            return Err(FriError::FoldingConstraintViolated { layer: layer_index });
                        }
                    }
                }
                1 => {
                    let beta_shift = fe_mul(beta, *coset_shift);
                    let scaled = fe_mul(beta_shift, opening.value);
                    let left_value = fe_sub(parent_value, scaled);
                    if sibling_digest == EMPTY_DIGEST {
                        if left_value != FieldElement::ZERO {
                            return Err(FriError::FoldingConstraintViolated { layer: layer_index });
                        }
                    } else if hash_leaf(&left_value)? != sibling_digest {
                        return Err(FriError::FoldingConstraintViolated { layer: layer_index });
                    }
                }
                _ => unreachable!(),
            }

            index = parent_index(index);
            domain_size = next_domain_size(domain_size);
        }

        if index >= proof.final_polynomial.len() {
            return Err(FriError::QueryOutOfRange {
                position: *expected_position,
            });
        }

        if proof.final_polynomial[index] != query.final_value {
            return Err(FriError::LayerRootMismatch { layer: num_layers });
        }
    }

    Ok(())
}
