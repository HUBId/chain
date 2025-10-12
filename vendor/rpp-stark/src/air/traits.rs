//! Traits describing behaviour expected from AIR implementations.
//!
//! Implementors should provide the canonical semantics for transition and
//! boundary constraints as they become available.
#![allow(clippy::should_implement_trait)]

use crate::air::types::{
    AirError, BoundaryAt, ColIx, DegreeBounds, PublicSpec, TraceData, TraceRole, TraceSchema,
};
use crate::field::FieldElement as Felt;
use crate::utils::serialization::FieldElementBytes;

/// Top-level behaviour contract for Algebraic Intermediate Representations.
pub trait Air {
    /// Trace builder returned by [`Air::new_trace_builder`].
    type TraceBuilder: TraceBuilder;
    /// Boundary builder returned by [`Air::new_boundary_builder`].
    type BoundaryBuilder: BoundaryBuilder;
    /// Constraint evaluator returned by [`Air::new_evaluator`].
    type Evaluator: Evaluator;
    /// Codec returned by [`Air::public_inputs_codec`].
    type PublicInputsCodec: PublicInputsCodec;

    /// Returns the deterministic execution trace schema for this AIR.
    fn trace_schema(&self) -> Result<TraceSchema, AirError>;

    /// Returns the public input specification used by this AIR.
    fn public_spec(&self) -> Result<PublicSpec, AirError>;

    /// Creates a new trace builder adhering to [`TraceSchema`].
    fn new_trace_builder(&self) -> Result<Self::TraceBuilder, AirError>;

    /// Creates a new boundary builder adhering to [`TraceSchema`].
    fn new_boundary_builder(&self) -> Result<Self::BoundaryBuilder, AirError>;

    /// Creates a new constraint evaluator for this AIR.
    fn new_evaluator(&self) -> Result<Self::Evaluator, AirError>;

    /// Returns the codec used to serialise public inputs.
    fn public_inputs_codec(&self) -> Result<Self::PublicInputsCodec, AirError>;
}

/// Trait describing deterministic construction of execution traces.
///
/// Implementations **must not** rely on hidden randomness and are expected to
/// emit columns in a stable, repeatable order across invocations.
pub trait TraceBuilder {
    /// Adds a column with the provided role to the execution trace.
    fn add_column(&mut self, role: TraceRole, values: Vec<Felt>) -> Result<ColIx, AirError>;

    /// Finishes construction and validates the resulting [`TraceData`].
    fn build(self, degree_bounds: DegreeBounds) -> Result<TraceData, AirError>;
}

/// Trait describing deterministic assignment of boundary constraints.
///
/// Implementations **must not** employ hidden randomness and should emit
/// boundary entries in a consistent order.
pub trait BoundaryBuilder {
    /// Assigns a boundary value for the requested column and location.
    fn set(&mut self, column: ColIx, at: BoundaryAt, value: Felt) -> Result<(), AirError>;

    /// Finalises the boundary descriptions.
    fn build(self) -> Result<Vec<BoundaryConstraint>, AirError>;
}

/// Constraint polynomial recorded by an [`Evaluator`].
#[derive(Debug, Clone, PartialEq)]
pub struct Constraint {
    /// Symbolic representation of the polynomial expression.
    pub expr: PolyExpr,
    /// Degree of the polynomial at the time of recording.
    pub degree: usize,
}

impl Constraint {
    /// Creates a new constraint object capturing the expression degree.
    pub fn new(expr: PolyExpr) -> Self {
        let degree = expr.degree();
        Self { expr, degree }
    }
}

/// Trait used to record constraint polynomials.
///
/// Implementations **must not** rely on hidden randomness and should produce
/// constraint sequences in a deterministic order.
pub trait Evaluator {
    /// Records a polynomial expression that must evaluate to zero.
    fn enforce_zero(&mut self, expr: PolyExpr) -> Result<(), AirError>;

    /// Returns the deterministically ordered constraints recorded so far.
    fn constraints(&self) -> Result<Vec<Constraint>, AirError>;
}

/// Codec responsible for serialising public inputs.
///
/// Implementations **must not** leverage hidden randomness and must encode
/// fields in a deterministic order.
pub trait PublicInputsCodec {
    /// Type representing the public input structure.
    type Value;

    /// Serialises the public input value into field element bytes.
    fn encode(&self, value: &Self::Value) -> Result<Vec<FieldElementBytes>, AirError>;

    /// Deserialises field element bytes into the public input value.
    fn decode(&self, bytes: &[FieldElementBytes]) -> Result<Self::Value, AirError>;
}

/// Boundary constraint descriptor constructed by [`BoundaryBuilder`].
#[derive(Debug, Clone, PartialEq)]
pub struct BoundaryConstraint {
    /// Column participating in the constraint.
    pub column: ColIx,
    /// Boundary location on the column.
    pub at: BoundaryAt,
    /// Value enforced at the boundary.
    pub value: Felt,
}

/// Symbolic polynomial expression used when recording constraints.
#[derive(Debug, Clone, PartialEq)]
pub enum PolyExpr {
    /// Constant polynomial.
    Const(Felt),
    /// Column value at the current step.
    Column { column: ColIx },
    /// Column value at the next step.
    Next { column: ColIx },
    /// Negation of a polynomial.
    Neg(Box<PolyExpr>),
    /// Sum of two polynomials.
    Add(Box<PolyExpr>, Box<PolyExpr>),
    /// Difference of two polynomials.
    Sub(Box<PolyExpr>, Box<PolyExpr>),
    /// Product of two polynomials.
    Mul(Box<PolyExpr>, Box<PolyExpr>),
}

impl PolyExpr {
    /// Returns the algebraic degree of the polynomial expression.
    pub fn degree(&self) -> usize {
        match self {
            PolyExpr::Const(_) => 0,
            PolyExpr::Column { .. } | PolyExpr::Next { .. } => 1,
            PolyExpr::Neg(expr) => expr.degree(),
            PolyExpr::Add(lhs, rhs) | PolyExpr::Sub(lhs, rhs) => lhs.degree().max(rhs.degree()),
            PolyExpr::Mul(lhs, rhs) => lhs.degree() + rhs.degree(),
        }
    }

    /// Creates a constant polynomial expression.
    pub fn const_(value: Felt) -> Self {
        PolyExpr::Const(value)
    }

    /// Creates a polynomial referring to the current trace column value.
    pub fn col(column: ColIx) -> Self {
        PolyExpr::Column { column }
    }

    /// Creates a polynomial referring to the next trace column value.
    pub fn next(column: ColIx) -> Self {
        PolyExpr::Next { column }
    }

    /// Computes the negation of a polynomial expression.
    pub fn neg(expr: PolyExpr) -> Self {
        PolyExpr::Neg(Box::new(expr))
    }

    /// Adds two polynomial expressions together.
    pub fn add(lhs: PolyExpr, rhs: PolyExpr) -> Self {
        PolyExpr::Add(Box::new(lhs), Box::new(rhs))
    }

    /// Subtracts the right expression from the left expression.
    pub fn sub(lhs: PolyExpr, rhs: PolyExpr) -> Self {
        PolyExpr::Sub(Box::new(lhs), Box::new(rhs))
    }

    /// Multiplies two polynomial expressions.
    pub fn mul(lhs: PolyExpr, rhs: PolyExpr) -> Self {
        PolyExpr::Mul(Box::new(lhs), Box::new(rhs))
    }

    /// Multiplies a polynomial by a constant value.
    pub fn mul_const(expr: PolyExpr, value: Felt) -> Self {
        PolyExpr::mul(expr, PolyExpr::const_(value))
    }

    /// Adds a constant value to the polynomial.
    pub fn add_const(expr: PolyExpr, value: Felt) -> Self {
        PolyExpr::add(expr, PolyExpr::const_(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::field::prime_field::CanonicalSerialize;

    #[derive(Default)]
    struct MockEvaluator {
        constraints: Vec<Constraint>,
    }

    impl Evaluator for MockEvaluator {
        fn enforce_zero(&mut self, expr: PolyExpr) -> Result<(), AirError> {
            self.constraints.push(Constraint::new(expr));
            Ok(())
        }

        fn constraints(&self) -> Result<Vec<Constraint>, AirError> {
            Ok(self.constraints.clone())
        }
    }

    struct MockCodec;

    impl PublicInputsCodec for MockCodec {
        type Value = Felt;

        fn encode(&self, value: &Self::Value) -> Result<Vec<FieldElementBytes>, AirError> {
            let mut buf = [0u8; 32];
            let le = value
                .to_bytes()
                .expect("mock codec should receive canonical values");
            buf[..le.len()].copy_from_slice(&le);
            Ok(vec![FieldElementBytes { bytes: buf }])
        }

        fn decode(&self, bytes: &[FieldElementBytes]) -> Result<Self::Value, AirError> {
            if bytes.len() != 1 {
                return Err(AirError::Serialization {
                    kind: crate::air::types::SerKind::PublicInput,
                    detail: "unexpected input length",
                });
            }
            let mut limb = [0u8; 8];
            limb.copy_from_slice(&bytes[0].bytes[..8]);
            Ok(Felt::from(u64::from_le_bytes(limb)))
        }
    }

    #[test]
    fn poly_expr_degree_composition() {
        let col_a = PolyExpr::col(ColIx::new(0));
        let col_b = PolyExpr::next(ColIx::new(1));
        let additive = PolyExpr::add(col_a.clone(), col_b.clone());
        assert_eq!(additive.degree(), 1);

        let product = PolyExpr::mul(additive.clone(), col_a.clone());
        assert_eq!(product.degree(), 2);

        let negated = PolyExpr::neg(PolyExpr::mul_const(product.clone(), Felt::from(3u64)));
        assert_eq!(negated.degree(), 2);

        let shifted = PolyExpr::add_const(negated.clone(), Felt::from(5u64));
        assert_eq!(shifted.degree(), 2);
    }

    #[test]
    fn evaluator_records_degree_information() -> Result<(), AirError> {
        let mut evaluator = MockEvaluator::default();
        evaluator.enforce_zero(PolyExpr::mul(
            PolyExpr::col(ColIx::new(0)),
            PolyExpr::add(PolyExpr::col(ColIx::new(1)), PolyExpr::next(ColIx::new(1))),
        ))?;

        let constraints = evaluator.constraints()?;
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].degree, 2);
        Ok(())
    }

    #[test]
    fn codec_roundtrip_is_deterministic() -> Result<(), AirError> {
        let codec = MockCodec;
        let value = Felt::from(7u64);
        let bytes_first = codec.encode(&value)?;
        let bytes_second = codec.encode(&value)?;
        assert_eq!(bytes_first, bytes_second);
        let decoded = codec.decode(&bytes_first)?;
        assert_eq!(decoded, value);
        Ok(())
    }
}
