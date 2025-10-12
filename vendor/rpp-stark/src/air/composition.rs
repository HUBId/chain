//! Constraint composition and evaluation helpers.
//!
//! The actual constraint polynomial logic will be connected as the prover and
//! verifier pipelines mature.

use core::fmt;

use crate::air::traits::Air;
use crate::air::types::{AirError, DegreeBounds, SerKind, TraceRole};
use crate::field::prime_field::{CanonicalSerialize, FieldElementOps};
use crate::field::FieldElement as Felt;
use crate::merkle::{self, DeterministicMerkleHasher, Leaf, MerkleCommit, MerkleTree};
use crate::params::StarkParams;
use crate::transcript::{Transcript, TranscriptContext, TranscriptLabel};

/// Metadata describing how constraint evaluations are grouped together.
#[derive(Clone, Debug, PartialEq)]
pub struct ConstraintGroup {
    /// Human readable group label used for diagnostics.
    pub label: String,
    /// Trace role associated with the constraint evaluations.
    pub role: TraceRole,
    /// Observed algebraic degree of the group prior to normalisation.
    pub degree: usize,
    /// Optional scaling factor applied after folding the group evaluations.
    pub normaliser: Felt,
    /// Individual constraint evaluation vectors recorded in deterministic order.
    pub evaluations: Vec<Vec<Felt>>,
}

impl ConstraintGroup {
    /// Creates a new constraint group with unit normaliser.
    pub fn new(
        label: impl Into<String>,
        role: TraceRole,
        degree: usize,
        evaluations: Vec<Vec<Felt>>,
    ) -> Self {
        Self {
            label: label.into(),
            role,
            degree,
            normaliser: Felt::ONE,
            evaluations,
        }
    }

    fn ensure_non_empty(&self) -> Result<(), AirError> {
        if self.evaluations.is_empty() {
            return Err(AirError::LayoutViolation(
                "constraint group must contain at least one evaluation",
            ));
        }
        Ok(())
    }
}

/// Parameters driving composition evaluation.
pub struct CompositionParams<'a> {
    /// Global STARK parameter set.
    pub stark: &'a StarkParams,
    /// Fiat–Shamir transcript already bound to the composition root.
    pub transcript: &'a mut Transcript,
    /// Degree bounds enforced for main and auxiliary columns.
    pub degree_bounds: DegreeBounds,
    /// Constraint groups combined into the composition polynomial.
    pub groups: &'a [ConstraintGroup],
}

/// Merkle commitment artefacts for composition polynomials.
#[derive(Clone, Debug, PartialEq)]
pub struct CompositionCommitment {
    /// Merkle root digest of the committed evaluations.
    pub root: merkle::Digest,
    /// Auxiliary Merkle data required to answer queries.
    pub aux: merkle::CommitAux,
    /// α challenges assigned to each constraint group in order.
    pub alphas: Vec<Felt>,
    /// Raw byte challenge stream derived for auditability.
    pub challenge_bytes: Vec<u8>,
}

impl fmt::Display for CompositionCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CompositionCommitment(root: {:?}, groups: {})",
            self.root,
            self.alphas.len()
        )
    }
}

/// Composes constraint groups into a single evaluation vector and commits using Merkle trees.
pub fn compose<A: Air>(
    _air: &A,
    params: CompositionParams<'_>,
) -> Result<(Vec<Felt>, CompositionCommitment), AirError> {
    if params.groups.is_empty() {
        return Err(AirError::LayoutViolation(
            "composition requires at least one constraint group",
        ));
    }

    for group in params.groups.iter() {
        group.ensure_non_empty()?;
        params.degree_bounds.ensure(group.role, group.degree)?;
    }

    let domain_size = params
        .groups
        .iter()
        .flat_map(|group| group.evaluations.first())
        .map(|eval| eval.len())
        .next()
        .ok_or(AirError::LayoutViolation(
            "composition requires at least one evaluation vector",
        ))?;
    if domain_size == 0 {
        return Err(AirError::LayoutViolation(
            "evaluation vectors must have positive length",
        ));
    }
    for group in params.groups.iter() {
        for eval in &group.evaluations {
            if eval.len() != domain_size {
                return Err(AirError::LayoutViolation(
                    "evaluation length must match FRI domain size",
                ));
            }
        }
    }

    let mut fork = params.transcript.fork(TranscriptContext::Air);
    let extra_bytes = if params.groups.len() > 1 {
        fork.challenge_bytes(
            TranscriptLabel::CompChallengeA,
            (params.groups.len() - 1) * 32,
        )
        .map_err(|_| AirError::Serialization {
            kind: SerKind::Transcript,
            detail: "failed to sample transcript bytes",
        })?
    } else {
        Vec::new()
    };

    let alpha_seed = params
        .transcript
        .challenge_field(TranscriptLabel::CompChallengeA)
        .map_err(|_| AirError::Serialization {
            kind: SerKind::Transcript,
            detail: "failed to sample transcript field challenge",
        })?;

    let mut alphas = Vec::with_capacity(params.groups.len());
    alphas.push(alpha_seed);
    for chunk in extra_bytes.chunks(32) {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(chunk);
        alphas.push(Felt::from_transcript_bytes(&buf));
    }
    alphas.truncate(params.groups.len());

    let mut composition = vec![Felt::ZERO; domain_size];
    for (group, alpha) in params.groups.iter().zip(alphas.iter()) {
        let mut group_contribution = vec![Felt::ZERO; domain_size];
        let mut alpha_power = Felt::ONE;
        for evaluation in &group.evaluations {
            for (acc, value) in group_contribution.iter_mut().zip(evaluation.iter()) {
                let term = value.mul(&alpha_power);
                *acc = acc.add(&term);
            }
            alpha_power = alpha_power.mul(alpha);
        }
        if group.normaliser != Felt::ONE {
            let normaliser = group.normaliser;
            let inv = normaliser.inv().ok_or(AirError::LayoutViolation(
                "constraint group normaliser must be invertible",
            ))?;
            for value in group_contribution.iter_mut() {
                *value = value.mul(&inv);
            }
        }
        for (acc, value) in composition.iter_mut().zip(group_contribution.into_iter()) {
            *acc = acc.add(&value);
        }
    }

    let leaves = evaluations_to_leaves(&composition, params.stark.merkle().leaf_width as usize)?;
    let (root, aux) = <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::commit(
        params.stark,
        leaves.into_iter(),
    )
    .map_err(|_| AirError::LayoutViolation("merkle commitment failed"))?;

    Ok((
        composition,
        CompositionCommitment {
            root,
            aux,
            alphas,
            challenge_bytes: extra_bytes,
        },
    ))
}

fn evaluations_to_leaves(evaluations: &[Felt], leaf_width: usize) -> Result<Vec<Leaf>, AirError> {
    if leaf_width == 0 {
        return Err(AirError::LayoutViolation(
            "merkle leaf width must be positive",
        ));
    }
    if evaluations.len() % leaf_width != 0 {
        return Err(AirError::LayoutViolation(
            "evaluation length must be divisible by leaf width",
        ));
    }

    let mut leaves = Vec::with_capacity(evaluations.len() / leaf_width);
    for chunk in evaluations.chunks(leaf_width) {
        let mut bytes = Vec::with_capacity(leaf_width * Felt::BYTE_LENGTH);
        for felt in chunk {
            let encoded = felt.to_bytes().map_err(|_| AirError::Serialization {
                kind: SerKind::Trace,
                detail: "non-canonical constraint evaluation",
            })?;
            bytes.extend_from_slice(&encoded);
        }
        leaves.push(Leaf::new(bytes));
    }
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::air::traits::{BoundaryBuilder, Evaluator, PublicInputsCodec, TraceBuilder};
    use crate::air::types::{ColIx, DegreeBounds, TraceData};
    use crate::params::{HashKind, StarkParamsBuilder};
    use crate::utils::serialization::{DigestBytes, FieldElementBytes};

    fn prepare_transcript(params: &StarkParams) -> Transcript {
        let mut transcript = Transcript::new(params, TranscriptContext::StarkMain);
        transcript
            .absorb_field_elements(TranscriptLabel::PublicInputsDigest, &[Felt::ZERO])
            .unwrap();
        transcript
            .absorb_digest(
                TranscriptLabel::TraceRoot,
                &DigestBytes { bytes: [0u8; 32] },
            )
            .unwrap();
        let _ = transcript
            .challenge_field(TranscriptLabel::TraceChallengeA)
            .unwrap();
        transcript
            .absorb_digest(TranscriptLabel::CompRoot, &DigestBytes { bytes: [1u8; 32] })
            .unwrap();
        transcript
    }

    fn sample_groups(size: usize, domain: usize) -> Vec<ConstraintGroup> {
        (0..size)
            .map(|i| {
                let values: Vec<Felt> = (0..domain)
                    .map(|j| Felt::from(((i as u64) << 8) + j as u64))
                    .collect();
                ConstraintGroup::new(format!("group-{i}"), TraceRole::Main, 1, vec![values])
            })
            .collect()
    }

    #[test]
    fn alpha_sampling_respects_group_order() {
        let mut builder = StarkParamsBuilder::new();
        builder.hash = HashKind::Blake2s { digest_size: 32 };
        let params = builder.build().unwrap();

        let domain = params.merkle().leaf_width as usize * 2;
        let groups = sample_groups(3, domain);

        let mut transcript_expected = prepare_transcript(&params);
        let mut fork = transcript_expected.fork(TranscriptContext::Air);
        let expected_bytes = fork
            .challenge_bytes(TranscriptLabel::CompChallengeA, (groups.len() - 1) * 32)
            .unwrap();
        let alpha_seed = transcript_expected
            .challenge_field(TranscriptLabel::CompChallengeA)
            .unwrap();
        let mut expected_alphas = Vec::new();
        expected_alphas.push(alpha_seed);
        for chunk in expected_bytes.chunks(32) {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(chunk);
            expected_alphas.push(Felt::from_transcript_bytes(&buf));
        }
        expected_alphas.truncate(groups.len());

        let mut transcript = prepare_transcript(&params);
        let degree_bounds = DegreeBounds::new(4, 4).unwrap();
        let (_evals, commitment) = compose(
            &MockAir,
            CompositionParams {
                stark: &params,
                transcript: &mut transcript,
                degree_bounds,
                groups: &groups,
            },
        )
        .unwrap();

        assert_eq!(commitment.alphas, expected_alphas);
        assert_eq!(commitment.challenge_bytes, expected_bytes);
    }

    #[test]
    fn degree_bounds_are_enforced() {
        let mut builder = StarkParamsBuilder::new();
        builder.hash = HashKind::Blake2s { digest_size: 32 };
        let params = builder.build().unwrap();
        let mut transcript = prepare_transcript(&params);
        let mut groups = sample_groups(1, params.merkle().leaf_width as usize * 2);
        groups[0].degree = 10;
        let degree_bounds = DegreeBounds::new(2, 4).unwrap();
        let err = compose(
            &MockAir,
            CompositionParams {
                stark: &params,
                transcript: &mut transcript,
                degree_bounds,
                groups: &groups,
            },
        )
        .unwrap_err();
        assert!(matches!(err, AirError::DegreeOverflow { .. }));
    }

    #[test]
    fn commitment_is_deterministic() {
        let mut builder = StarkParamsBuilder::new();
        builder.hash = HashKind::Blake2s { digest_size: 32 };
        let params = builder.build().unwrap();
        let mut transcript1 = prepare_transcript(&params);
        let mut transcript2 = prepare_transcript(&params);
        let groups = sample_groups(2, params.merkle().leaf_width as usize * 2);
        let degree_bounds = DegreeBounds::new(4, 4).unwrap();

        let (evals1, commitment1) = compose(
            &MockAir,
            CompositionParams {
                stark: &params,
                transcript: &mut transcript1,
                degree_bounds,
                groups: &groups,
            },
        )
        .unwrap();

        let (evals2, commitment2) = compose(
            &MockAir,
            CompositionParams {
                stark: &params,
                transcript: &mut transcript2,
                degree_bounds,
                groups: &groups,
            },
        )
        .unwrap();

        assert_eq!(evals1, evals2);
        assert_eq!(commitment1.root, commitment2.root);
        assert_eq!(commitment1.alphas, commitment2.alphas);
        assert_eq!(commitment1.challenge_bytes, commitment2.challenge_bytes);
    }

    struct MockAir;

    struct DummyTraceBuilder;
    impl TraceBuilder for DummyTraceBuilder {
        fn add_column(&mut self, _role: TraceRole, _values: Vec<Felt>) -> Result<ColIx, AirError> {
            unimplemented!()
        }

        fn build(self, _degree_bounds: DegreeBounds) -> Result<TraceData, AirError> {
            unimplemented!()
        }
    }

    struct DummyBoundaryBuilder;
    impl BoundaryBuilder for DummyBoundaryBuilder {
        fn set(
            &mut self,
            _column: ColIx,
            _at: crate::air::types::BoundaryAt,
            _value: Felt,
        ) -> Result<(), AirError> {
            unimplemented!()
        }

        fn build(self) -> Result<Vec<crate::air::traits::BoundaryConstraint>, AirError> {
            unimplemented!()
        }
    }

    struct DummyEvaluator;
    impl Evaluator for DummyEvaluator {
        fn enforce_zero(&mut self, _expr: crate::air::traits::PolyExpr) -> Result<(), AirError> {
            unimplemented!()
        }

        fn constraints(&self) -> Result<Vec<crate::air::traits::Constraint>, AirError> {
            unimplemented!()
        }
    }

    struct DummyCodec;
    impl PublicInputsCodec for DummyCodec {
        type Value = ();

        fn encode(&self, _value: &Self::Value) -> Result<Vec<FieldElementBytes>, AirError> {
            unimplemented!()
        }

        fn decode(&self, _bytes: &[FieldElementBytes]) -> Result<Self::Value, AirError> {
            unimplemented!()
        }
    }

    impl Air for MockAir {
        type TraceBuilder = DummyTraceBuilder;
        type BoundaryBuilder = DummyBoundaryBuilder;
        type Evaluator = DummyEvaluator;
        type PublicInputsCodec = DummyCodec;

        fn trace_schema(&self) -> Result<crate::air::types::TraceSchema, AirError> {
            unimplemented!()
        }

        fn public_spec(&self) -> Result<crate::air::types::PublicSpec, AirError> {
            unimplemented!()
        }

        fn new_trace_builder(&self) -> Result<Self::TraceBuilder, AirError> {
            unimplemented!()
        }

        fn new_boundary_builder(&self) -> Result<Self::BoundaryBuilder, AirError> {
            unimplemented!()
        }

        fn new_evaluator(&self) -> Result<Self::Evaluator, AirError> {
            unimplemented!()
        }

        fn public_inputs_codec(&self) -> Result<Self::PublicInputsCodec, AirError> {
            unimplemented!()
        }
    }
}
