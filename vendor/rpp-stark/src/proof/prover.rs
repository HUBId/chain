//! Deterministic prover pipeline implementation.
//!
//! The prover builds a proof envelope by executing the following steps:
//!
//! 1. Parse the witness into a list of LDE evaluations.
//! 2. Compute the initial commitment roots and bind them to the transcript.
//! 3. Derive Fiat–Shamir challenges (α-vector, OOD points, FRI seed).
//! 4. Produce a binary FRI proof using the deterministic seed.
//! 5. Assemble the envelope header/body, compute digests and enforce size limits.

use crate::air::composition::{compose, CompositionParams, ConstraintGroup};
use crate::air::example::{LfsrAir, LfsrPublicInputs};
use crate::air::trace::{NextRowView, Trace};
use crate::air::traits::{
    Air as AirContract, BoundaryBuilder as AirBoundaryBuilder, Evaluator as AirEvaluator, PolyExpr,
    TraceBuilder as AirTraceBuilder,
};
use crate::air::types::{AirError as AirLayerError, ColIx, TraceRole, TraceSchema};
use crate::config::{
    AirSpecId, ProfileConfig, ProofKind as ConfigProofKind, ProofKindLayout, ProofSystemConfig,
    ProverContext,
};
use crate::fft::lde::{LowDegreeExtensionParameters, PROFILE_HISEC_X16, PROFILE_X8};
use crate::field::FieldElement;
use crate::fri::{FriError, FriProof, FriSecurityLevel};
use crate::merkle::{
    CommitAux, DeterministicMerkleHasher, Leaf, MerkleArityExt, MerkleCommit, MerkleError,
    MerkleProof, MerkleTree, ProofNode,
};
use crate::params::{ProofParams, StarkParams};
use crate::proof::envelope::ProofBuilder;
use crate::proof::params::canonical_stark_params;
use crate::proof::public_inputs::PublicInputs;
use crate::proof::ser::{
    compute_public_digest, map_public_to_config_kind, serialize_public_inputs,
};
use crate::proof::transcript::{
    Transcript as ProofTranscript, TranscriptBlockContext, TranscriptHeader,
};
use crate::proof::types::{
    CompositionOpenings, FriHandle, FriParametersMirror, MerkleAuthenticationPath, MerklePathNode,
    MerkleProofBundle, Openings, OpeningsDescriptor, OutOfDomainOpening, Proof, Telemetry,
    TelemetryOption, TraceOpenings, PROOF_ALPHA_VECTOR_LEN, PROOF_MIN_OOD_POINTS, PROOF_VERSION,
};
use crate::ser::{SerError, SerKind};
use crate::transcript::{Transcript as AirTranscript, TranscriptContext, TranscriptLabel};
use crate::utils::serialization::{DigestBytes, WitnessBlob};
use core::cmp::{max, min};
use core::convert::TryInto;

use crate::field::prime_field::{
    CanonicalSerialize, FieldConstraintError, FieldDeserializeError, FieldElementOps,
};

use super::types::{FriVerifyIssue, MerkleSection, VerifyError};

/// Errors surfaced while building a proof envelope.
#[derive(Debug)]
pub enum ProverError {
    /// The proof system configuration declared an unsupported version.
    UnsupportedProofVersion(u16),
    /// Parameter digest mismatch between configuration and prover context.
    ParamDigestMismatch,
    /// Witness blob failed to parse into field elements.
    MalformedWitness(&'static str),
    /// Failed to derive Fiat–Shamir challenges.
    Transcript(crate::proof::transcript::TranscriptError),
    /// Binary FRI prover returned an error.
    Fri(FriError),
    /// AIR layer surface error.
    Air(AirLayerError),
    /// Merkle tree construction failed.
    Merkle(MerkleError),
    /// The resulting proof exceeded the configured size limit.
    ProofTooLarge { actual: usize, limit: u32 },
    /// Serialization failure while assembling the proof envelope.
    Serialization(SerKind),
    /// Canonical field constraint violated during proof generation.
    FieldConstraint(&'static str, FieldConstraintError),
}

impl From<crate::proof::transcript::TranscriptError> for ProverError {
    fn from(err: crate::proof::transcript::TranscriptError) -> Self {
        ProverError::Transcript(err)
    }
}

impl From<FriError> for ProverError {
    fn from(err: FriError) -> Self {
        ProverError::Fri(err)
    }
}

impl From<AirLayerError> for ProverError {
    fn from(err: AirLayerError) -> Self {
        ProverError::Air(err)
    }
}

impl From<MerkleError> for ProverError {
    fn from(err: MerkleError) -> Self {
        ProverError::Merkle(err)
    }
}

impl From<SerError> for ProverError {
    fn from(err: SerError) -> Self {
        ProverError::Serialization(err.kind())
    }
}

/// Builds a [`Proof`] from public inputs and witness data.
pub fn build_envelope(
    public_inputs: &PublicInputs<'_>,
    witness: WitnessBlob<'_>,
    config: &ProofSystemConfig,
    context: &ProverContext,
) -> Result<Proof, ProverError> {
    let declared_version = config.proof_version.0 as u16;
    if declared_version != PROOF_VERSION {
        return Err(ProverError::UnsupportedProofVersion(declared_version));
    }

    if config.param_digest != context.param_digest {
        return Err(ProverError::ParamDigestMismatch);
    }

    let proof_kind = map_public_to_config_kind(public_inputs.kind());
    let air_spec_id = resolve_air_spec_id(&context.profile.air_spec_ids, proof_kind);
    let security_level = map_security_level(&context.profile);

    let public_inputs_bytes = serialize_public_inputs(public_inputs).map_err(ProverError::from)?;
    let public_digest = compute_public_digest(&public_inputs_bytes);

    let lfsr_inputs = map_lfsr_public_inputs(public_inputs)?;
    let air = LfsrAir::new(lfsr_inputs.clone());
    let trace_schema = air.trace_schema()?;

    let witness_columns = parse_witness(witness)?;
    let columns = map_witness_to_schema(&witness_columns, &trace_schema, lfsr_inputs.length)?;

    let mut trace_builder = air.new_trace_builder()?;
    for (meta, column) in trace_schema.columns.iter().zip(columns.iter()) {
        trace_builder.add_column(meta.role, column.clone())?;
    }
    let trace_data = trace_builder.build(trace_schema.degree_bounds)?;
    let mut trace_columns = Vec::with_capacity(trace_schema.columns.len());
    for (index, _) in trace_schema.columns.iter().enumerate() {
        trace_columns.push(trace_data.column(ColIx::new(index))?.to_vec());
    }
    let trace = Trace::from_columns(trace_schema.clone(), trace_columns.clone())?;

    let mut boundary_builder = air.new_boundary_builder()?;
    for (index, meta) in trace_schema.columns.iter().enumerate() {
        for boundary in &meta.boundaries {
            let value = trace_data.boundary_value(ColIx::new(index), *boundary)?;
            boundary_builder.set(ColIx::new(index), *boundary, value)?;
        }
    }
    let _boundary_constraints = boundary_builder.build()?;

    let lde_params = map_lde_profile(context.profile.lde_factor as usize);
    let lde_values = trace.lde_evaluations(lde_params)?;

    let stark_params = canonical_stark_params(&context.profile);
    let (core_root, core_aux, trace_leaves) = commit_evaluations(&stark_params, &lde_values)?;

    let mut air_transcript = prepare_air_transcript(&stark_params, &public_digest, &core_root)?;
    let degree_bounds = trace_schema.degree_bounds;
    let constraint_groups = build_constraint_groups(&air, &trace, lde_params)?;
    let (composition_values, composition_commitment) = compose(
        &air,
        CompositionParams {
            stark: &stark_params,
            transcript: &mut air_transcript,
            degree_bounds,
            groups: &constraint_groups,
        },
    )?;
    let aux_root = digest_to_array(composition_commitment.root.as_bytes());
    let composition_aux = composition_commitment.aux;
    let composition_leaves = evaluations_to_leaves(&composition_values)?;

    let mut transcript = ProofTranscript::new(TranscriptHeader {
        version: context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: context.profile.poseidon_param_id.clone(),
        air_spec_id: air_spec_id.clone(),
        proof_kind,
        params_hash: context.param_digest.clone(),
    })?;
    transcript.absorb_public_inputs(&public_inputs_bytes)?;
    transcript.absorb_commitment_roots(core_root, Some(aux_root))?;
    transcript.absorb_air_spec_id(air_spec_id.clone())?;
    transcript.absorb_block_context(None::<TranscriptBlockContext>)?;

    let mut challenges = transcript.finalize()?;
    let alpha_vector = challenges.draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)?;
    let ood_points = challenges.draw_ood_points(PROOF_MIN_OOD_POINTS)?;
    let _ood_seed = challenges.draw_ood_seed()?;

    let fri_seed = challenges.draw_fri_seed()?;
    let fri_proof =
        FriProof::prove_with_params(security_level, fri_seed, &composition_values, &stark_params)?;

    // Consume the η challenges to keep transcript counters aligned with the proof.
    for (layer_index, _) in fri_proof.layer_roots.iter().enumerate() {
        let _ = challenges.draw_fri_eta(layer_index)?;
    }
    let _ = challenges.draw_query_seed()?;

    let trace_indices: Vec<u32> = fri_proof
        .queries
        .iter()
        .map(|query| query.position.try_into().unwrap_or(u32::MAX))
        .collect();

    let sampled_trace_values: Vec<FieldElement> = trace_indices
        .iter()
        .map(|&index| {
            let pos = index as usize;
            lde_values.get(pos).copied().unwrap_or(FieldElement::ZERO)
        })
        .collect();
    let sampled_composition_values: Vec<FieldElement> = trace_indices
        .iter()
        .map(|&index| {
            let pos = index as usize;
            composition_values
                .get(pos)
                .copied()
                .unwrap_or(FieldElement::ZERO)
        })
        .collect();
    let composition_openings = build_composition_openings(
        &stark_params,
        &composition_aux,
        &composition_leaves,
        &trace_indices,
    )?;
    let trace_openings =
        build_trace_openings(&stark_params, &core_aux, &trace_leaves, &trace_indices)?;
    let ood_openings = derive_ood_openings(
        &ood_points,
        &alpha_vector,
        &sampled_trace_values,
        &sampled_composition_values,
    )?;
    let fri_layer_roots = fri_proof.layer_roots.clone();

    let fri_parameters = FriParametersMirror {
        fold: 2,
        cap_degree: context.profile.fri_depth_range.max as u16,
        cap_size: min(
            fri_proof.final_polynomial.len() as u32,
            crate::proof::types::PROOF_TELEMETRY_MAX_CAP_SIZE,
        ),
        query_budget: security_level.query_budget() as u16,
    };

    let merkle = MerkleProofBundle::new(core_root, aux_root, fri_layer_roots);

    let telemetry = Telemetry {
        header_length: 0,
        body_length: 0,
        fri_parameters,
        integrity_digest: DigestBytes::default(),
    };

    let openings = Openings {
        trace: trace_openings,
        composition: Some(composition_openings),
        out_of_domain: ood_openings,
    };

    let openings_descriptor = OpeningsDescriptor::new(merkle, openings);
    let fri_handle = FriHandle::new(fri_proof);
    let telemetry_option = TelemetryOption::new(true, telemetry);
    let proof_params = ProofParams {
        version: PROOF_VERSION,
        max_size_kb: bytes_to_kib(context.limits.max_proof_size_bytes),
    };

    let built = ProofBuilder::new(proof_params)
        .with_header(PROOF_VERSION, context.param_digest.clone())
        .with_binding(proof_kind, air_spec_id, public_inputs_bytes)
        .with_openings_descriptor(openings_descriptor)
        .with_fri_handle(fri_handle)
        .with_telemetry_option(telemetry_option)
        .build()
        .map_err(|err| map_builder_error(err, context.limits.max_proof_size_bytes))?;

    debug_assert_eq!(built.public_digest, public_digest);
    if built.public_digest != public_digest {
        return Err(ProverError::Serialization(SerKind::PublicInputs));
    }

    Ok(built.into_proof())
}

fn bytes_to_kib(bytes: u32) -> u32 {
    if bytes == 0 {
        0
    } else {
        ((bytes - 1) / 1024) + 1
    }
}

fn map_builder_error(err: VerifyError, limit_bytes: u32) -> ProverError {
    match err {
        VerifyError::ProofTooLarge { got_kb, .. } => {
            let actual = (got_kb as usize).saturating_mul(1024);
            ProverError::ProofTooLarge {
                actual,
                limit: limit_bytes,
            }
        }
        VerifyError::Serialization(kind) => ProverError::Serialization(kind),
        VerifyError::EmptyOpenings => ProverError::Serialization(SerKind::Openings),
        VerifyError::IndicesNotSorted
        | VerifyError::IndicesMismatch
        | VerifyError::IndicesDuplicate { .. } => ProverError::Serialization(SerKind::Openings),
        VerifyError::CompositionInconsistent { .. } => {
            ProverError::Serialization(SerKind::CompositionCommitment)
        }
        VerifyError::MerkleVerifyFailed { .. } | VerifyError::RootMismatch { .. } => {
            ProverError::Serialization(SerKind::TraceCommitment)
        }
        VerifyError::VersionMismatch { actual, .. } => ProverError::UnsupportedProofVersion(actual),
        VerifyError::ParamsHashMismatch => ProverError::ParamDigestMismatch,
        VerifyError::PublicInputMismatch | VerifyError::PublicDigestMismatch => {
            ProverError::Serialization(SerKind::PublicInputs)
        }
        _ => ProverError::Serialization(SerKind::Proof),
    }
}

#[derive(Debug, Clone, Default)]
struct WitnessColumns {
    rows: usize,
    main: Vec<Vec<FieldElement>>,
    auxiliary: Vec<Vec<FieldElement>>,
    permutation: Vec<Vec<FieldElement>>,
    lookup: Vec<Vec<FieldElement>>,
}

fn parse_witness(witness: WitnessBlob<'_>) -> Result<WitnessColumns, ProverError> {
    const HEADER_FIELDS: usize = 5;
    const FIELD_BYTES: usize = 8;
    if witness.bytes.len() < HEADER_FIELDS * 4 {
        return Err(ProverError::MalformedWitness("witness_header"));
    }

    let mut cursor = 0usize;
    let take_u32 = |bytes: &[u8], offset: &mut usize| -> Result<u32, ProverError> {
        let end = offset
            .checked_add(4)
            .ok_or(ProverError::MalformedWitness("witness_overflow"))?;
        let slice = bytes
            .get(*offset..end)
            .ok_or(ProverError::MalformedWitness("witness_header"))?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(slice);
        *offset = end;
        Ok(u32::from_le_bytes(buf))
    };

    let rows = take_u32(witness.bytes, &mut cursor)? as usize;
    if rows == 0 {
        return Err(ProverError::MalformedWitness("trace_rows"));
    }
    let main_cols = take_u32(witness.bytes, &mut cursor)? as usize;
    let aux_cols = take_u32(witness.bytes, &mut cursor)? as usize;
    let perm_cols = take_u32(witness.bytes, &mut cursor)? as usize;
    let lookup_cols = take_u32(witness.bytes, &mut cursor)? as usize;

    let total_columns = main_cols
        .checked_add(aux_cols)
        .and_then(|v| v.checked_add(perm_cols))
        .and_then(|v| v.checked_add(lookup_cols))
        .ok_or(ProverError::MalformedWitness("column_overflow"))?;
    let expected = HEADER_FIELDS * 4 + total_columns * rows * FIELD_BYTES;
    if witness.bytes.len() != expected {
        return Err(ProverError::MalformedWitness("witness_size"));
    }

    let parse_segment = |count: usize,
                         data: &[u8],
                         offset: &mut usize,
                         label: &'static str|
     -> Result<Vec<Vec<FieldElement>>, ProverError> {
        let mut segment = Vec::with_capacity(count);
        for _ in 0..count {
            let mut column = Vec::with_capacity(rows);
            for _ in 0..rows {
                let end = offset
                    .checked_add(FIELD_BYTES)
                    .ok_or(ProverError::MalformedWitness("witness_overflow"))?;
                let slice = data
                    .get(*offset..end)
                    .ok_or(ProverError::MalformedWitness(label))?;
                let mut buf = [0u8; FIELD_BYTES];
                buf.copy_from_slice(slice);
                let value = FieldElement::from_bytes(&buf).map_err(|err| match err {
                    FieldDeserializeError::FieldDeserializeNonCanonical => {
                        ProverError::MalformedWitness("non_canonical_field")
                    }
                })?;
                column.push(value);
                *offset = end;
            }
            segment.push(column);
        }
        Ok(segment)
    };

    let main = parse_segment(main_cols, witness.bytes, &mut cursor, "main_columns")?;
    let auxiliary = parse_segment(aux_cols, witness.bytes, &mut cursor, "aux_columns")?;
    let permutation = parse_segment(perm_cols, witness.bytes, &mut cursor, "perm_columns")?;
    let lookup = parse_segment(lookup_cols, witness.bytes, &mut cursor, "lookup_columns")?;

    Ok(WitnessColumns {
        rows,
        main,
        auxiliary,
        permutation,
        lookup,
    })
}

fn map_witness_to_schema(
    witness: &WitnessColumns,
    schema: &TraceSchema,
    expected_rows: usize,
) -> Result<Vec<Vec<FieldElement>>, ProverError> {
    if witness.rows != expected_rows {
        return Err(ProverError::MalformedWitness("trace_length"));
    }

    let mut main_ix = 0usize;
    let mut aux_ix = 0usize;
    let mut perm_ix = 0usize;
    let mut lookup_ix = 0usize;
    let mut columns = Vec::with_capacity(schema.columns.len());
    for meta in &schema.columns {
        let source = match meta.role {
            TraceRole::Main => {
                let column = witness
                    .main
                    .get(main_ix)
                    .ok_or(ProverError::MalformedWitness("main_columns"))?;
                main_ix += 1;
                column
            }
            TraceRole::Auxiliary => {
                let column = witness
                    .auxiliary
                    .get(aux_ix)
                    .ok_or(ProverError::MalformedWitness("aux_columns"))?;
                aux_ix += 1;
                column
            }
            TraceRole::Permutation => {
                let column = witness
                    .permutation
                    .get(perm_ix)
                    .ok_or(ProverError::MalformedWitness("perm_columns"))?;
                perm_ix += 1;
                column
            }
            TraceRole::Lookup => {
                let column = witness
                    .lookup
                    .get(lookup_ix)
                    .ok_or(ProverError::MalformedWitness("lookup_columns"))?;
                lookup_ix += 1;
                column
            }
        };
        if source.len() != witness.rows {
            return Err(ProverError::MalformedWitness("column_length"));
        }
        columns.push(source.clone());
    }

    if main_ix != witness.main.len()
        || aux_ix != witness.auxiliary.len()
        || perm_ix != witness.permutation.len()
        || lookup_ix != witness.lookup.len()
    {
        return Err(ProverError::MalformedWitness("column_count_mismatch"));
    }

    Ok(columns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::types::{DegreeBounds, LdeOrder, TraceColMeta};
    use crate::utils::serialization::WitnessBlob;

    fn witness_fixture() -> WitnessColumns {
        let rows = 2u32;
        let main = [[1u64, 2u64]];
        let auxiliary = [[3u64, 4u64]];
        let permutation = [[5u64, 6u64]];
        let lookup = [[7u64, 8u64]];

        let mut bytes = Vec::new();
        for value in [rows, 1, 1, 1, 1] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for column in main
            .iter()
            .chain(auxiliary.iter())
            .chain(permutation.iter())
            .chain(lookup.iter())
        {
            for value in column {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }

        parse_witness(WitnessBlob { bytes: &bytes }).expect("fixture witness must parse")
    }

    fn schema_with_all_roles() -> TraceSchema {
        let columns = vec![
            TraceColMeta::new("main", TraceRole::Main),
            TraceColMeta::new("aux", TraceRole::Auxiliary),
            TraceColMeta::new("perm", TraceRole::Permutation),
            TraceColMeta::new("lookup", TraceRole::Lookup),
        ];
        let lde = LdeOrder::new(2).expect("valid lde order");
        let degree = DegreeBounds::new(1, 1).expect("valid degree bounds");
        TraceSchema::new(columns, lde, degree).expect("valid trace schema")
    }

    #[test]
    fn map_witness_handles_all_trace_roles() {
        let witness = witness_fixture();
        let schema = schema_with_all_roles();
        let mapped = map_witness_to_schema(&witness, &schema, 2).expect("witness should map");
        assert_eq!(mapped.len(), 4);
        assert_eq!(
            mapped[0],
            vec![FieldElement::from(1u64), FieldElement::from(2u64)]
        );
        assert_eq!(
            mapped[1],
            vec![FieldElement::from(3u64), FieldElement::from(4u64)]
        );
        assert_eq!(
            mapped[2],
            vec![FieldElement::from(5u64), FieldElement::from(6u64)]
        );
        assert_eq!(
            mapped[3],
            vec![FieldElement::from(7u64), FieldElement::from(8u64)]
        );
    }

    #[test]
    fn map_witness_detects_unused_segments() {
        let witness = witness_fixture();
        let columns = vec![
            TraceColMeta::new("main", TraceRole::Main),
            TraceColMeta::new("aux", TraceRole::Auxiliary),
        ];
        let lde = LdeOrder::new(2).expect("valid lde order");
        let degree = DegreeBounds::new(1, 1).expect("valid degree bounds");
        let schema = TraceSchema::new(columns, lde, degree).expect("valid schema");
        let err =
            map_witness_to_schema(&witness, &schema, 2).expect_err("should reject extra segments");
        assert!(matches!(
            err,
            ProverError::MalformedWitness("column_count_mismatch")
        ));
    }
}

fn map_lfsr_public_inputs(
    public_inputs: &PublicInputs<'_>,
) -> Result<LfsrPublicInputs, ProverError> {
    match public_inputs {
        PublicInputs::Execution { header, body } => {
            if body.len() != 8 {
                return Err(ProverError::MalformedWitness("lfsr_seed_length"));
            }
            let mut seed_bytes = [0u8; 8];
            seed_bytes.copy_from_slice(body);
            let seed = FieldElement::from_bytes(&seed_bytes).map_err(|err| match err {
                FieldDeserializeError::FieldDeserializeNonCanonical => {
                    ProverError::MalformedWitness("lfsr_seed")
                }
            })?;
            if header.trace_width != 1 {
                return Err(ProverError::MalformedWitness("trace_width"));
            }
            LfsrPublicInputs::new(seed, header.trace_length as usize).map_err(ProverError::Air)
        }
        _ => Err(ProverError::MalformedWitness("unsupported_public_inputs")),
    }
}

fn build_constraint_groups<A: AirContract>(
    air: &A,
    trace: &Trace,
    lde_params: &'static LowDegreeExtensionParameters,
) -> Result<Vec<ConstraintGroup>, ProverError> {
    let evaluator = air.new_evaluator()?;
    let constraints = evaluator.constraints()?;
    let domain_size = trace
        .length()
        .checked_mul(lde_params.blowup_factor)
        .ok_or(ProverError::MalformedWitness("domain_size"))?;

    if constraints.is_empty() {
        let zeros = vec![FieldElement::ZERO; domain_size];
        return Ok(vec![ConstraintGroup::new(
            "transition",
            TraceRole::Main,
            1,
            vec![zeros],
        )]);
    }

    let mut evaluations = Vec::with_capacity(constraints.len());
    let mut max_degree = 0usize;
    let trace_length = trace.length();
    for constraint in constraints {
        max_degree = max(max_degree, constraint.degree);
        let mut column = vec![FieldElement::ZERO; domain_size];
        for (step, value) in column.iter_mut().take(trace_length).enumerate() {
            let view = trace.row_pair(step)?;
            *value = evaluate_poly_expr(&constraint.expr, view)?;
        }
        evaluations.push(column);
    }

    Ok(vec![ConstraintGroup::new(
        "transition",
        TraceRole::Main,
        max_degree.max(1),
        evaluations,
    )])
}

fn evaluate_poly_expr(expr: &PolyExpr, row: NextRowView<'_>) -> Result<FieldElement, ProverError> {
    match expr {
        PolyExpr::Const(value) => Ok(*value),
        PolyExpr::Column { column } => {
            let (current, _) = row.get(*column)?;
            Ok(current)
        }
        PolyExpr::Next { column } => {
            let (_, next) = row.get(*column)?;
            Ok(next)
        }
        PolyExpr::Neg(inner) => Ok(evaluate_poly_expr(inner, row)?.neg()),
        PolyExpr::Add(lhs, rhs) => {
            let left = evaluate_poly_expr(lhs, row)?;
            let right = evaluate_poly_expr(rhs, row)?;
            Ok(left.add(&right))
        }
        PolyExpr::Sub(lhs, rhs) => {
            let left = evaluate_poly_expr(lhs, row)?;
            let right = evaluate_poly_expr(rhs, row)?;
            Ok(left.sub(&right))
        }
        PolyExpr::Mul(lhs, rhs) => {
            let left = evaluate_poly_expr(lhs, row)?;
            let right = evaluate_poly_expr(rhs, row)?;
            Ok(left.mul(&right))
        }
    }
}

fn resolve_air_spec_id(layout: &ProofKindLayout<AirSpecId>, kind: ConfigProofKind) -> AirSpecId {
    match kind {
        ConfigProofKind::Tx => layout.tx.clone(),
        ConfigProofKind::State => layout.state.clone(),
        ConfigProofKind::Pruning => layout.pruning.clone(),
        ConfigProofKind::Uptime => layout.uptime.clone(),
        ConfigProofKind::Consensus => layout.consensus.clone(),
        ConfigProofKind::Identity => layout.identity.clone(),
        ConfigProofKind::Aggregation => layout.aggregation.clone(),
        ConfigProofKind::VRF => layout.vrf.clone(),
    }
}

fn map_security_level(profile: &ProfileConfig) -> FriSecurityLevel {
    match profile.fri_queries {
        64 => FriSecurityLevel::Standard,
        96 => FriSecurityLevel::HiSec,
        48 => FriSecurityLevel::Throughput,
        other => {
            let _ = other; // fall back to standard for unknown profiles
            FriSecurityLevel::Standard
        }
    }
}

fn map_lde_profile(factor: usize) -> &'static LowDegreeExtensionParameters {
    match factor {
        16 => &PROFILE_HISEC_X16,
        _ => &PROFILE_X8,
    }
}

fn commit_evaluations(
    params: &StarkParams,
    evaluations: &[FieldElement],
) -> Result<([u8; 32], CommitAux, Vec<Leaf>), ProverError> {
    let leaves = evaluations_to_leaves(evaluations)?;
    let (root, aux) = <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::commit(
        params,
        leaves.clone().into_iter(),
    )?;
    Ok((digest_to_array(root.as_bytes()), aux, leaves))
}

fn prepare_air_transcript(
    params: &StarkParams,
    public_digest: &[u8; 32],
    trace_root: &[u8; 32],
) -> Result<AirTranscript, ProverError> {
    let mut transcript = AirTranscript::new(params, TranscriptContext::StarkMain);
    let mut digest_bytes = [0u8; 8];
    digest_bytes.copy_from_slice(&public_digest[..8]);
    let digest_felt = FieldElement::from_bytes(&digest_bytes)
        .map_err(|_| ProverError::MalformedWitness("transcript_public_digest"))?;
    transcript
        .absorb_field_elements(TranscriptLabel::PublicInputsDigest, &[digest_felt])
        .map_err(|_| ProverError::MalformedWitness("transcript_public"))?;
    transcript
        .absorb_digest(
            TranscriptLabel::TraceRoot,
            &DigestBytes { bytes: *trace_root },
        )
        .map_err(|_| ProverError::MalformedWitness("transcript_trace_root"))?;
    let _ = transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .map_err(|_| ProverError::MalformedWitness("transcript_trace_challenge"))?;
    transcript
        .absorb_digest(TranscriptLabel::CompRoot, &DigestBytes { bytes: [0u8; 32] })
        .map_err(|_| ProverError::MalformedWitness("transcript_comp_root_placeholder"))?;
    Ok(transcript)
}

fn evaluations_to_leaves(values: &[FieldElement]) -> Result<Vec<Leaf>, ProverError> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let mut leaves = Vec::with_capacity(values.len());
    for value in values {
        let mut bytes = Vec::with_capacity(FieldElement::BYTE_LENGTH);
        let encoded = value
            .to_bytes()
            .map_err(|err| ProverError::FieldConstraint("evaluations_to_leaves", err))?;
        bytes.extend_from_slice(&encoded);
        leaves.push(Leaf::new(bytes));
    }
    Ok(leaves)
}

fn build_trace_openings(
    params: &StarkParams,
    aux: &CommitAux,
    leaves: &[Leaf],
    indices: &[u32],
) -> Result<TraceOpenings, ProverError> {
    let (leaf_bytes, paths) = build_opening_artifacts(params, aux, leaves, indices)?;
    Ok(TraceOpenings {
        indices: indices.to_vec(),
        leaves: leaf_bytes,
        paths,
    })
}

fn build_composition_openings(
    params: &StarkParams,
    aux: &CommitAux,
    leaves: &[Leaf],
    indices: &[u32],
) -> Result<CompositionOpenings, ProverError> {
    let (leaf_bytes, paths) = build_opening_artifacts(params, aux, leaves, indices)?;
    Ok(CompositionOpenings {
        indices: indices.to_vec(),
        leaves: leaf_bytes,
        paths,
    })
}

fn build_opening_artifacts(
    params: &StarkParams,
    aux: &CommitAux,
    leaves: &[Leaf],
    indices: &[u32],
) -> Result<(Vec<Vec<u8>>, Vec<MerkleAuthenticationPath>), ProverError> {
    let mut leaf_bytes = Vec::with_capacity(indices.len());
    let mut paths = Vec::with_capacity(indices.len());
    for &index in indices {
        let proof =
            <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::open(params, aux, &[index])?;
        let bytes = leaves
            .get(index as usize)
            .map(|leaf| leaf.as_bytes().to_vec())
            .unwrap_or_default();
        leaf_bytes.push(bytes);
        paths.push(convert_tree_proof(&proof, index));
    }
    Ok((leaf_bytes, paths))
}

fn convert_tree_proof(proof: &MerkleProof, index: u32) -> MerkleAuthenticationPath {
    let mut nodes = Vec::new();
    let mut current = index;
    let arity = proof.arity.as_usize() as u32;
    for node in proof.path() {
        match node {
            ProofNode::Arity2([digest]) => {
                let position = (current % arity) as u8;
                nodes.push(MerklePathNode {
                    index: position,
                    sibling: digest_to_array(digest.as_bytes()),
                });
            }
            ProofNode::Arity4(digests) => {
                let position = (current % arity) as u8;
                let branching = proof.arity.as_usize() as u8;
                let missing_positions: Vec<u8> =
                    (0..branching).filter(|pos| *pos != position).collect();
                let mut digest_iter = digests.iter();

                if let Some(first_digest) = digest_iter.next() {
                    nodes.push(MerklePathNode {
                        index: position,
                        sibling: digest_to_array(first_digest.as_bytes()),
                    });
                } else {
                    nodes.push(MerklePathNode {
                        index: position,
                        sibling: [0u8; 32],
                    });
                }

                for (pos, digest) in missing_positions.iter().skip(1).zip(digest_iter) {
                    nodes.push(MerklePathNode {
                        index: *pos,
                        sibling: digest_to_array(digest.as_bytes()),
                    });
                }
            }
        }
        if arity > 0 {
            current /= arity;
        }
    }
    MerkleAuthenticationPath { nodes }
}

fn derive_ood_openings(
    points: &[[u8; 32]],
    alpha_vector: &[[u8; 32]],
    trace_values: &[FieldElement],
    composition_values: &[FieldElement],
) -> Result<Vec<OutOfDomainOpening>, ProverError> {
    if composition_values.is_empty() || trace_values.is_empty() || points.is_empty() {
        return Ok(Vec::new());
    }

    let alphas: Vec<FieldElement> = alpha_vector
        .iter()
        .map(FieldElement::from_transcript_bytes)
        .collect();

    points
        .iter()
        .map(|point_bytes| {
            let point = FieldElement::from_transcript_bytes(point_bytes);
            let core_evaluation = evaluate_ood_samples(trace_values, &alphas, point);
            let composition_evaluation = evaluate_ood_samples(composition_values, &alphas, point);

            let core_bytes = field_to_fixed_bytes(core_evaluation)
                .map_err(|err| ProverError::FieldConstraint("ood_core", err))?;
            let composition_bytes = field_to_fixed_bytes(composition_evaluation)
                .map_err(|err| ProverError::FieldConstraint("ood_composition", err))?;

            Ok(OutOfDomainOpening {
                point: *point_bytes,
                core_values: vec![core_bytes],
                aux_values: Vec::new(),
                composition_value: composition_bytes,
            })
        })
        .collect()
}

fn evaluate_ood_samples(
    samples: &[FieldElement],
    alphas: &[FieldElement],
    point: FieldElement,
) -> FieldElement {
    if samples.is_empty() || alphas.is_empty() {
        return FieldElement::ZERO;
    }

    let mut acc = FieldElement::ZERO;
    let mut power = FieldElement::ONE;
    for (sample, alpha) in samples.iter().zip(alphas.iter().cycle()) {
        let weighted = sample.mul(alpha);
        let term = weighted.mul(&power);
        acc = acc.add(&term);
        power = power.mul(&point);
    }
    acc
}

fn field_to_fixed_bytes(value: FieldElement) -> Result<[u8; 32], FieldConstraintError> {
    let mut bytes = [0u8; 32];
    let le = value.to_bytes()?;
    bytes[..le.len()].copy_from_slice(&le);
    Ok(bytes)
}

fn digest_to_array(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Helper converting prover errors into verification failures when the prover
/// surface is reused by integration tests.
impl From<ProverError> for VerifyError {
    fn from(error: ProverError) -> Self {
        match error {
            ProverError::UnsupportedProofVersion(version) => VerifyError::VersionMismatch {
                expected: PROOF_VERSION,
                actual: version,
            },
            ProverError::ParamDigestMismatch => VerifyError::ParamsHashMismatch,
            ProverError::MalformedWitness(_) => {
                VerifyError::UnexpectedEndOfBuffer("malformed_witness".to_string())
            }
            ProverError::Transcript(_) => VerifyError::TranscriptOrder,
            ProverError::Fri(FriError::LayerRootMismatch { .. }) => VerifyError::FriVerifyFailed {
                issue: FriVerifyIssue::LayerMismatch,
            },
            ProverError::Fri(FriError::PathInvalid { .. }) => VerifyError::MerkleVerifyFailed {
                section: MerkleSection::FriPath,
            },
            ProverError::Fri(FriError::QueryOutOfRange { .. }) => VerifyError::FriVerifyFailed {
                issue: FriVerifyIssue::QueryOutOfRange,
            },
            ProverError::Fri(_) => VerifyError::FriVerifyFailed {
                issue: FriVerifyIssue::Generic,
            },
            ProverError::Air(_) => VerifyError::UnexpectedEndOfBuffer("air_error".to_string()),
            ProverError::Merkle(_) => VerifyError::MerkleVerifyFailed {
                section: MerkleSection::FriPath,
            },
            ProverError::ProofTooLarge { actual, limit } => {
                let got_kb = actual.div_ceil(1024).min(u32::MAX as usize) as u32;
                let max_kb = (limit as usize).div_ceil(1024) as u32;
                VerifyError::ProofTooLarge { max_kb, got_kb }
            }
            ProverError::Serialization(kind) => VerifyError::Serialization(kind),
            ProverError::FieldConstraint(context, _) => {
                VerifyError::UnexpectedEndOfBuffer(context.to_string())
            }
        }
    }
}
