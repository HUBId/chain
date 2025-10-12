use super::folding::{binary_fold, coset_shift_schedule, parent_index};
use super::layer::FriLayer;
use super::proof::{derive_query_positions, hash_final_layer, FriProof, FriQueryProof};
use super::types::{FriError, FriParamsView, FriSecurityLevel};
use crate::field::FieldElement;
use crate::params::StarkParams;
use crate::transcript::{Felt, Transcript, TranscriptError, TranscriptLabel};
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

/// Executes the canonical binary FRI prover against the supplied transcript.
pub fn fri_prove(
    evaluations: &[Felt],
    params: &StarkParams,
    transcript: &mut Transcript,
) -> Result<FriProof, FriError> {
    if evaluations.is_empty() {
        return Err(FriError::EmptyCodeword);
    }

    let query_count = params.fri().queries as usize;
    let security_level = security_level_from_query_count(query_count)?;
    let query_plan = super::derive_query_plan_id(security_level, params);
    let view = FriParamsView::from_params(params, security_level, query_plan);

    let coset_shifts = coset_shift_schedule(params, view.num_layers());
    let mut layers = Vec::with_capacity(view.num_layers());
    let mut layer_roots = Vec::with_capacity(view.num_layers());
    let mut fold_challenges = Vec::with_capacity(view.num_layers());

    let mut current: Vec<FieldElement> = evaluations.to_vec();

    for (layer_index, coset_shift) in coset_shifts.iter().copied().enumerate() {
        if layer_index > u8::MAX as usize {
            return Err(FriError::InvalidStructure("layer-index-overflow"));
        }

        let layer = FriLayer::new(layer_index, coset_shift, current)?;
        let root = layer.root();
        transcript
            .absorb_digest(
                TranscriptLabel::FriRoot(layer_index as u8),
                &DigestBytes { bytes: root },
            )
            .map_err(map_transcript_error)?;
        let eta = transcript
            .challenge_field(TranscriptLabel::FriFoldChallenge(layer_index as u8))
            .map_err(map_transcript_error)?;
        fold_challenges.push(eta);
        layer_roots.push(root);

        current = binary_fold(layer.evaluations(), eta, layer.coset_shift());
        layers.push(layer);
    }

    let final_polynomial = current;
    let final_polynomial_digest = hash_final_layer(&final_polynomial)?;

    let count_bytes = (view.query_count() as u32).to_le_bytes();
    transcript
        .absorb_bytes(TranscriptLabel::QueryCount, &count_bytes)
        .map_err(map_transcript_error)?;
    let query_seed_bytes = transcript
        .challenge_bytes(TranscriptLabel::QueryIndexStream, 32)
        .map_err(map_transcript_error)?;
    let mut query_seed = [0u8; 32];
    query_seed.copy_from_slice(&query_seed_bytes);

    let positions = derive_query_positions(query_seed, view.query_count(), evaluations.len())?;
    let mut queries = Vec::with_capacity(positions.len());

    for &position in &positions {
        let mut index = position;
        let mut layers_openings = Vec::with_capacity(layers.len());
        for layer in layers.iter() {
            let opening = layer.open(index)?;
            layers_openings.push(opening);
            index = parent_index(index);
        }

        if index >= final_polynomial.len() {
            return Err(FriError::QueryOutOfRange { position });
        }

        let final_value = final_polynomial[index];
        queries.push(FriQueryProof {
            position,
            layers: layers_openings,
            final_value,
        });
    }

    FriProof::new(
        security_level,
        evaluations.len(),
        layer_roots,
        fold_challenges,
        final_polynomial,
        final_polynomial_digest,
        queries,
    )
}
