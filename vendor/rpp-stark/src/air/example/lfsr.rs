//! Linear-feedback shift register example AIR.
//!
//! This module provides a compact worked example that exercises the public
//! input codec, deterministic trace construction and constraint recording APIs
//! exposed by the AIR layer.  The example models a single-register LFSR defined
//! over the prime field used by the library.  The recurrence is intentionally
//! simple: every successive step is derived as `next = ALPHA * current + BETA`.
//! This keeps the symbolic transition polynomial linear while still covering the
//! complete pipeline (codec, trace generation, boundary checks and constraint
//! recording).

use crate::air::trace::Trace;
use crate::air::traits::{
    Air as AirTrait, BoundaryBuilder as BoundaryBuilderTrait, BoundaryConstraint, Constraint,
    Evaluator as EvaluatorTrait, PolyExpr, PublicInputsCodec as PublicInputsCodecTrait,
    TraceBuilder as TraceBuilderTrait,
};
use crate::air::types::{
    AirError, BoundaryAt, ColIx, DegreeBounds, LdeOrder, PublicFieldMeta, PublicFieldType,
    PublicSpec, SerKind, TraceColMeta, TraceData, TraceRole, TraceSchema,
};
use crate::field::prime_field::{CanonicalSerialize, FieldDeserializeError, FieldElementOps};
use crate::field::FieldElement as Felt;
use crate::utils::serialization::FieldElementBytes;

/// Column index used throughout the example.
const STATE_COL: ColIx = ColIx::new(0);
/// Multiplicative factor applied during the transition.
const ALPHA: Felt = Felt(5);
/// Additive tweak applied during the transition.
const BETA: Felt = Felt(7);
/// Blowup factor enforced by the schema.
const LDE_BLOWUP: usize = 8;

/// Public inputs for the LFSR example.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputs {
    /// Seed used as the first trace value.
    pub seed: Felt,
    /// Number of rows in the execution trace.
    pub length: usize,
}

impl PublicInputs {
    /// Creates a new public input descriptor, validating the supplied length.
    pub fn new(seed: Felt, length: usize) -> Result<Self, AirError> {
        if length < 2 {
            return Err(AirError::LayoutViolation(
                "lfsr trace length must contain at least two rows",
            ));
        }
        if length % LDE_BLOWUP != 0 {
            return Err(AirError::LayoutViolation(
                "lfsr trace length must be a multiple of the lde blowup factor",
            ));
        }
        Ok(Self { seed, length })
    }

    /// Returns the canonical 32-byte digest derived from the public inputs.
    pub fn digest(&self) -> Result<[u8; 32], AirError> {
        let mut digest = [0u8; 32];
        let seed_bytes = self.seed.to_bytes().map_err(|_| AirError::Serialization {
            kind: SerKind::PublicInput,
            detail: "seed non-canonical",
        })?;
        digest[..seed_bytes.len()].copy_from_slice(&seed_bytes);
        let length_fe = Felt::from(self.length as u64);
        let length_bytes = length_fe.to_bytes().map_err(|_| AirError::Serialization {
            kind: SerKind::PublicInput,
            detail: "length non-canonical",
        })?;
        let offset = seed_bytes.len();
        digest[offset..offset + length_bytes.len()].copy_from_slice(&length_bytes);
        Ok(digest)
    }
}

/// Codec implementing canonical serialization for [`PublicInputs`].
#[derive(Debug, Default, Clone, Copy)]
pub struct PublicInputsCodec;

impl PublicInputsCodec {
    fn decode_field(bytes: &FieldElementBytes) -> Result<Felt, AirError> {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes.bytes[..8]);
        if bytes.bytes[8..].iter().any(|b| *b != 0) {
            return Err(AirError::Serialization {
                kind: SerKind::PublicInput,
                detail: "non-canonical field encoding",
            });
        }
        match Felt::from_bytes(&buf) {
            Ok(value) => Ok(value),
            Err(FieldDeserializeError::FieldDeserializeNonCanonical) => {
                Err(AirError::Serialization {
                    kind: SerKind::PublicInput,
                    detail: "field element not canonical",
                })
            }
        }
    }
}

impl PublicInputsCodecTrait for PublicInputsCodec {
    type Value = PublicInputs;

    fn encode(&self, value: &Self::Value) -> Result<Vec<FieldElementBytes>, AirError> {
        let mut seed_bytes = [0u8; 32];
        let seed_le = value.seed.to_bytes().map_err(|_| AirError::Serialization {
            kind: SerKind::PublicInput,
            detail: "seed non-canonical",
        })?;
        seed_bytes[..seed_le.len()].copy_from_slice(&seed_le);

        let mut length_bytes = [0u8; 32];
        let length_fe = Felt::from(value.length as u64);
        let length_le = length_fe.to_bytes().map_err(|_| AirError::Serialization {
            kind: SerKind::PublicInput,
            detail: "length non-canonical",
        })?;
        length_bytes[..length_le.len()].copy_from_slice(&length_le);

        Ok(vec![
            FieldElementBytes { bytes: seed_bytes },
            FieldElementBytes {
                bytes: length_bytes,
            },
        ])
    }

    fn decode(&self, bytes: &[FieldElementBytes]) -> Result<Self::Value, AirError> {
        if bytes.len() != 2 {
            return Err(AirError::Serialization {
                kind: SerKind::PublicInput,
                detail: "lfsr codec expects two field elements",
            });
        }
        let seed = Self::decode_field(&bytes[0])?;
        let length = Self::decode_field(&bytes[1])?;
        let length = u64::try_from(length).map_err(|_| AirError::Serialization {
            kind: SerKind::PublicInput,
            detail: "length non-canonical",
        })? as usize;
        PublicInputs::new(seed, length)
    }
}

/// Deterministic execution trace builder for the LFSR example.
#[derive(Debug, Clone)]
pub struct TraceBuilder {
    schema: TraceSchema,
    expected_column: Vec<Felt>,
    recorded_column: Option<Vec<Felt>>,
}

impl TraceBuilder {
    fn new(schema: TraceSchema, expected_column: Vec<Felt>) -> Self {
        Self {
            schema,
            expected_column,
            recorded_column: None,
        }
    }
}

impl TraceBuilderTrait for TraceBuilder {
    fn add_column(&mut self, role: TraceRole, values: Vec<Felt>) -> Result<ColIx, AirError> {
        if role != TraceRole::Main {
            return Err(AirError::LayoutViolation(
                "lfsr example only exposes a main trace column",
            ));
        }
        if values.len() != self.expected_column.len() {
            return Err(AirError::SchemaMismatch {
                what: "trace row count",
                expected: self.expected_column.len(),
                actual: values.len(),
            });
        }
        for (step, (expected, observed)) in self.expected_column.iter().zip(&values).enumerate() {
            if expected != observed {
                return Err(AirError::NonDeterministicWitness {
                    column: STATE_COL,
                    step,
                });
            }
        }
        if let Some(existing) = &self.recorded_column {
            for (step, (lhs, rhs)) in existing.iter().zip(&values).enumerate() {
                if lhs != rhs {
                    return Err(AirError::NonDeterministicWitness {
                        column: STATE_COL,
                        step,
                    });
                }
            }
        } else {
            self.recorded_column = Some(values.clone());
        }
        Ok(STATE_COL)
    }

    fn build(self, degree_bounds: DegreeBounds) -> Result<TraceData, AirError> {
        let column = self.recorded_column.ok_or(AirError::SchemaMismatch {
            what: "trace column count",
            expected: 1,
            actual: 0,
        })?;
        degree_bounds.ensure(TraceRole::Main, column.len().saturating_sub(1))?;
        let trace_data = TraceData::new(vec![column.clone()])?;
        self.schema.validate_trace(&trace_data)?;
        let trace = Trace::from_columns(self.schema.clone(), vec![column])?;
        check_transitions(&trace, &transition_expr(STATE_COL), STATE_COL)?;
        Ok(trace_data)
    }
}

/// Boundary builder that enforces determinism via the expected trace.
#[derive(Debug, Clone)]
pub struct BoundaryBuilder {
    expected_trace: Trace,
    assignments: Vec<BoundaryConstraint>,
    seen: Vec<((ColIx, BoundaryAt), Felt)>,
}

impl BoundaryBuilder {
    fn new(expected_trace: Trace) -> Self {
        Self {
            expected_trace,
            assignments: Vec::new(),
            seen: Vec::new(),
        }
    }
}

impl BoundaryBuilderTrait for BoundaryBuilder {
    fn set(&mut self, column: ColIx, at: BoundaryAt, value: Felt) -> Result<(), AirError> {
        let expected_value = match at {
            BoundaryAt::First => self.expected_trace.row(0)?.get(column)?,
            BoundaryAt::Last => self
                .expected_trace
                .row(self.expected_trace.length().saturating_sub(1))?
                .get(column)?,
            BoundaryAt::Row(ix) => self.expected_trace.row(ix)?.get(column)?,
        };
        if value != expected_value {
            let step = match at {
                BoundaryAt::First => 0,
                BoundaryAt::Last => self.expected_trace.length().saturating_sub(1),
                BoundaryAt::Row(ix) => ix,
            };
            return Err(AirError::NonDeterministicWitness { column, step });
        }
        if let Some((_, existing)) = self
            .seen
            .iter()
            .find(|((col, boundary), _)| *col == column && *boundary == at)
        {
            if existing != &value {
                let step = match at {
                    BoundaryAt::First => 0,
                    BoundaryAt::Last => self.expected_trace.length().saturating_sub(1),
                    BoundaryAt::Row(ix) => ix,
                };
                return Err(AirError::NonDeterministicWitness { column, step });
            }
        }
        self.seen.push(((column, at), value));
        self.assignments
            .push(BoundaryConstraint { column, at, value });
        Ok(())
    }

    fn build(self) -> Result<Vec<BoundaryConstraint>, AirError> {
        Ok(self.assignments)
    }
}

/// Constraint evaluator storing transition polynomials.
#[derive(Debug, Default, Clone)]
pub struct Evaluator {
    constraints: Vec<Constraint>,
}

impl EvaluatorTrait for Evaluator {
    fn enforce_zero(&mut self, expr: PolyExpr) -> Result<(), AirError> {
        self.constraints.push(Constraint::new(expr));
        Ok(())
    }

    fn constraints(&self) -> Result<Vec<Constraint>, AirError> {
        Ok(self.constraints.clone())
    }
}

/// AIR implementation for the worked LFSR example.
#[derive(Debug, Clone)]
pub struct Air {
    public_inputs: PublicInputs,
}

impl Air {
    /// Creates a new AIR instance for the provided public inputs.
    pub fn new(public_inputs: PublicInputs) -> Self {
        Self { public_inputs }
    }

    /// Stable identifier used in transcripts and documentation.
    pub const fn id() -> &'static str {
        "LFSR_Example_v1"
    }

    fn trace_columns(&self) -> Vec<TraceColMeta> {
        vec![TraceColMeta::new("state", TraceRole::Main)
            .with_boundary(BoundaryAt::First)
            .with_boundary(BoundaryAt::Last)]
    }

    fn expected_column(&self) -> Vec<Felt> {
        generate_column(&self.public_inputs)
    }

    fn expected_trace(&self, schema: &TraceSchema) -> Result<Trace, AirError> {
        Trace::from_columns(schema.clone(), vec![self.expected_column()])
    }
}

impl AirTrait for Air {
    type TraceBuilder = TraceBuilder;
    type BoundaryBuilder = BoundaryBuilder;
    type Evaluator = Evaluator;
    type PublicInputsCodec = PublicInputsCodec;

    fn trace_schema(&self) -> Result<TraceSchema, AirError> {
        let degree = self.public_inputs.length.saturating_sub(1);
        let columns = self.trace_columns();
        let lde_order = LdeOrder::new(LDE_BLOWUP)?;
        let degree_bounds = DegreeBounds::new(degree, degree)?;
        TraceSchema::new(columns, lde_order, degree_bounds)
    }

    fn public_spec(&self) -> Result<PublicSpec, AirError> {
        let schema = self.trace_schema()?;
        let spec = PublicSpec {
            fields: vec![
                PublicFieldMeta {
                    label: "seed".to_string(),
                    field_type: PublicFieldType::TraceValue {
                        column: STATE_COL,
                        boundary: BoundaryAt::First,
                    },
                },
                PublicFieldMeta {
                    label: "final_state".to_string(),
                    field_type: PublicFieldType::TraceValue {
                        column: STATE_COL,
                        boundary: BoundaryAt::Last,
                    },
                },
            ],
        };
        spec.validate(&schema)?;
        Ok(spec)
    }

    fn new_trace_builder(&self) -> Result<Self::TraceBuilder, AirError> {
        let schema = self.trace_schema()?;
        let expected_column = self.expected_column();
        Ok(TraceBuilder::new(schema, expected_column))
    }

    fn new_boundary_builder(&self) -> Result<Self::BoundaryBuilder, AirError> {
        let schema = self.trace_schema()?;
        let expected_trace = self.expected_trace(&schema)?;
        Ok(BoundaryBuilder::new(expected_trace))
    }

    fn new_evaluator(&self) -> Result<Self::Evaluator, AirError> {
        let mut evaluator = Evaluator::default();
        evaluator.enforce_zero(transition_expr(STATE_COL))?;
        Ok(evaluator)
    }

    fn public_inputs_codec(&self) -> Result<Self::PublicInputsCodec, AirError> {
        Ok(PublicInputsCodec)
    }
}

fn generate_column(inputs: &PublicInputs) -> Vec<Felt> {
    let mut column = Vec::with_capacity(inputs.length);
    let mut state = inputs.seed;
    column.push(state);
    for _ in 1..inputs.length {
        state = next_state(state);
        column.push(state);
    }
    column
}

fn next_state(current: Felt) -> Felt {
    current.mul(&ALPHA).add(&BETA)
}

fn transition_expr(column: ColIx) -> PolyExpr {
    let linear = PolyExpr::mul_const(PolyExpr::col(column), ALPHA);
    let affine = PolyExpr::add_const(linear, BETA);
    PolyExpr::sub(PolyExpr::next(column), affine)
}

fn evaluate_poly(expr: &PolyExpr, current: Felt, next: Felt) -> Felt {
    match expr {
        PolyExpr::Const(value) => *value,
        PolyExpr::Column { .. } => current,
        PolyExpr::Next { .. } => next,
        PolyExpr::Neg(inner) => evaluate_poly(inner, current, next).neg(),
        PolyExpr::Add(lhs, rhs) => {
            evaluate_poly(lhs, current, next).add(&evaluate_poly(rhs, current, next))
        }
        PolyExpr::Sub(lhs, rhs) => {
            evaluate_poly(lhs, current, next).sub(&evaluate_poly(rhs, current, next))
        }
        PolyExpr::Mul(lhs, rhs) => {
            evaluate_poly(lhs, current, next).mul(&evaluate_poly(rhs, current, next))
        }
    }
}

fn check_transitions(trace: &Trace, expr: &PolyExpr, column: ColIx) -> Result<(), AirError> {
    if trace.length() < 2 {
        return Err(AirError::LayoutViolation(
            "lfsr trace must contain at least two rows",
        ));
    }
    for step in 0..(trace.length() - 1) {
        let pair = trace.row_pair(step)?;
        let (current, next) = pair.get(column)?;
        let value = evaluate_poly(expr, current, next);
        if !value.is_zero() {
            return Err(AirError::InvalidTransition {
                column,
                step,
                current,
                next,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use insta::assert_json_snapshot;
    use proptest::prelude::*;

    #[test]
    fn codec_roundtrip() {
        let inputs = PublicInputs::new(Felt(9), 8).unwrap();
        let codec = PublicInputsCodec;
        let encoded = codec.encode(&inputs).unwrap();
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded, inputs);
    }

    #[test]
    fn codec_rejects_non_canonical_encoding() {
        let codec = PublicInputsCodec;
        let mut non_canonical = FieldElementBytes { bytes: [0u8; 32] };
        non_canonical.bytes[8] = 1;
        let err = codec
            .decode(&[non_canonical.clone(), non_canonical])
            .unwrap_err();
        assert!(matches!(
            err,
            AirError::Serialization {
                kind: SerKind::PublicInput,
                detail
            } if detail.contains("non-canonical")
        ));
    }

    #[test]
    fn trace_generation_is_deterministic() {
        let inputs = PublicInputs::new(Felt(11), 8).unwrap();
        let air = Air::new(inputs.clone());
        let schema = air.trace_schema().unwrap();
        let degree_bounds = schema.degree_bounds;
        let expected_column = generate_column(&inputs);

        let mut builder = air.new_trace_builder().unwrap();
        builder
            .add_column(TraceRole::Main, expected_column.clone())
            .unwrap();
        let trace_data = builder.build(degree_bounds).unwrap();
        assert_eq!(trace_data.num_columns(), 1);

        let mut second_builder = air.new_trace_builder().unwrap();
        second_builder
            .add_column(TraceRole::Main, expected_column.clone())
            .unwrap();
        let second_trace_data = second_builder.build(schema.degree_bounds).unwrap();
        assert_eq!(
            trace_data.column(STATE_COL).unwrap(),
            second_trace_data.column(STATE_COL).unwrap()
        );

        let mut mismatched = expected_column.clone();
        mismatched[3] = mismatched[3].add(&Felt::ONE);
        let mut failing_builder = air.new_trace_builder().unwrap();
        let err = failing_builder
            .add_column(TraceRole::Main, mismatched)
            .unwrap_err();
        assert!(matches!(err, AirError::NonDeterministicWitness { .. }));
    }

    #[test]
    fn public_input_digest_snapshot() {
        let inputs = PublicInputs::new(Felt(3), 8).unwrap();
        assert_json_snapshot!(
            "public_input_digest_seed3_len8",
            inputs.digest().expect("example inputs must be canonical")
        );
    }

    #[test]
    fn transition_violation_is_detected() {
        let inputs = PublicInputs::new(Felt(13), 8).unwrap();
        let air = Air::new(inputs.clone());
        let schema = air.trace_schema().unwrap();
        let mut column = generate_column(&inputs);
        column[4] = column[4].add(&Felt::ONE);
        let trace = Trace::from_columns(schema, vec![column]).unwrap();
        let err = check_transitions(&trace, &transition_expr(STATE_COL), STATE_COL).unwrap_err();
        assert!(matches!(err, AirError::InvalidTransition { .. }));
    }

    #[test]
    fn boundary_tampering_is_detected() {
        let inputs = PublicInputs::new(Felt(5), 8).unwrap();
        let air = Air::new(inputs.clone());
        let mut builder = air.new_boundary_builder().unwrap();
        builder
            .set(STATE_COL, BoundaryAt::First, inputs.seed)
            .unwrap();
        builder
            .set(
                STATE_COL,
                BoundaryAt::Last,
                generate_column(&inputs).last().copied().unwrap(),
            )
            .unwrap();
        builder.build().unwrap();

        let mut tampered = air.new_boundary_builder().unwrap();
        let err = tampered
            .set(STATE_COL, BoundaryAt::First, inputs.seed.add(&Felt::ONE))
            .unwrap_err();
        assert!(matches!(err, AirError::NonDeterministicWitness { .. }));
    }

    #[test]
    fn trace_data_boundary_checks_enforced() {
        let inputs = PublicInputs::new(Felt(17), 8).unwrap();
        let air = Air::new(inputs.clone());
        let schema = air.trace_schema().unwrap();
        let expected = generate_column(&inputs);
        let mut builder = air.new_trace_builder().unwrap();
        builder
            .add_column(TraceRole::Main, expected.clone())
            .unwrap();
        let trace_data = builder.build(schema.degree_bounds).unwrap();

        let last = expected.last().copied().unwrap();
        assert_eq!(
            trace_data
                .boundary_value(STATE_COL, BoundaryAt::First)
                .unwrap(),
            inputs.seed
        );
        assert_eq!(
            trace_data
                .boundary_value(STATE_COL, BoundaryAt::Last)
                .unwrap(),
            last
        );

        let err = trace_data
            .boundary_value(STATE_COL, BoundaryAt::Row(expected.len() + 1))
            .unwrap_err();
        assert!(matches!(err, AirError::BoundaryViolation { .. }));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn proptest_trace_is_deterministic(seed in 0u64..32, length_factor in 1usize..4) {
            let length = (length_factor + 1) * LDE_BLOWUP;
            let inputs = PublicInputs::new(Felt(seed), length).unwrap();
            let air = Air::new(inputs.clone());
            let schema = air.trace_schema().unwrap();
            let expected_column = generate_column(&inputs);

            let mut builder_a = air.new_trace_builder().unwrap();
            builder_a.add_column(TraceRole::Main, expected_column.clone()).unwrap();
            let trace_a = builder_a.build(schema.degree_bounds).unwrap();

            let mut builder_b = air.new_trace_builder().unwrap();
            builder_b.add_column(TraceRole::Main, expected_column.clone()).unwrap();
            let trace_b = builder_b.build(schema.degree_bounds).unwrap();

            prop_assert_eq!(trace_a.column(STATE_COL).unwrap(), trace_b.column(STATE_COL).unwrap());

            if length > 1 {
                let mut tampered = expected_column.clone();
                let ix = (seed as usize) % length;
                tampered[ix] = tampered[ix].add(&Felt::ONE);
                let mut tampered_builder = air.new_trace_builder().unwrap();
                let err = tampered_builder.add_column(TraceRole::Main, tampered).unwrap_err();
                let witness_violation = matches!(err, AirError::NonDeterministicWitness { .. });
                prop_assert!(witness_violation);
            }

            let mut boundary_builder = air.new_boundary_builder().unwrap();
            boundary_builder.set(STATE_COL, BoundaryAt::First, inputs.seed).unwrap();
            let last = expected_column.last().copied().unwrap();
            boundary_builder.set(STATE_COL, BoundaryAt::Last, last).unwrap();
            boundary_builder.build().unwrap();
        }
    }
}
