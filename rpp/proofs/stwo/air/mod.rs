//! Algebraic Intermediate Representation (AIR) definitions and utilities
//! supporting the STWO blueprint. The scaffolding below allows circuits to
//! register constraint expressions over execution traces and deterministically
//! compress their evaluations so that provers and verifiers can agree on the
//! enforced algebra without implementing a full STARK backend yet.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::stwo::circuit::ExecutionTrace;
use crate::stwo::params::{FieldElement, FieldError, StarkParameters};

/// Errors that can be raised while manipulating AIR artifacts.
#[derive(Debug, thiserror::Error)]
pub enum AirError {
    #[error("trace segment '{0}' not found")]
    MissingSegment(String),

    #[error("column '{column}' not found in segment '{segment}'")]
    MissingColumn { segment: String, column: String },

    #[error(
        "row {row} with offset {offset} out of bounds for column '{column}' in segment '{segment}'"
    )]
    RowOutOfBounds {
        segment: String,
        column: String,
        row: usize,
        offset: isize,
    },

    #[error("mask for column '{column}' in segment '{segment}' missing offset {offset}")]
    MissingMaskOffset {
        segment: String,
        column: String,
        offset: isize,
    },

    #[error("field arithmetic error: {0}")]
    Field(#[from] FieldError),

    #[error("constraint evaluation count mismatch: expected {expected}, found {actual}")]
    EvaluationCount { expected: usize, actual: usize },
}

/// Identifier referencing a column inside a named trace segment.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AirColumn {
    segment: String,
    column: String,
}

impl AirColumn {
    pub fn new(segment: impl Into<String>, column: impl Into<String>) -> Self {
        Self {
            segment: segment.into(),
            column: column.into(),
        }
    }

    /// Returns the name of the trace segment backing the column.
    pub fn segment(&self) -> &str {
        &self.segment
    }

    /// Returns the column label within the trace segment.
    pub fn column(&self) -> &str {
        &self.column
    }

    /// Build an AIR expression referencing the column at the current row.
    pub fn expr(&self) -> AirExpression {
        AirExpression::Column(ColumnReference {
            column: self.clone(),
            offset: 0,
        })
    }

    /// Build an AIR expression referencing the column shifted by `offset`
    /// relative to the current row.
    pub fn shifted(&self, offset: isize) -> AirExpression {
        AirExpression::Column(ColumnReference {
            column: self.clone(),
            offset,
        })
    }
}

/// Reference to a column plus the relative row offset to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnReference {
    column: AirColumn,
    offset: isize,
}

impl ColumnReference {
    /// Returns the column referenced by the expression.
    pub fn column(&self) -> &AirColumn {
        &self.column
    }

    /// Returns the relative row offset associated with the reference.
    pub fn offset(&self) -> isize {
        self.offset
    }
}

/// Trait abstracting sources that can provide column values with row offsets.
pub trait TraceEvaluator {
    fn value(
        &self,
        column: &AirColumn,
        row: usize,
        offset: isize,
    ) -> Result<FieldElement, AirError>;
}

/// Expression tree describing algebraic constraints over the execution trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AirExpression {
    Constant(FieldElement),
    Column(ColumnReference),
    Add(Vec<AirExpression>),
    Sub(Box<AirExpression>, Box<AirExpression>),
    Mul(Vec<AirExpression>),
}

impl AirExpression {
    /// Create a constant expression from a field element.
    pub fn constant(value: FieldElement) -> Self {
        Self::Constant(value)
    }

    /// Build the sum of multiple expressions.
    pub fn sum(terms: Vec<AirExpression>) -> Self {
        Self::Add(terms)
    }

    /// Build the product of multiple expressions.
    pub fn product(terms: Vec<AirExpression>) -> Self {
        Self::Mul(terms)
    }

    /// Build the difference of two expressions.
    pub fn difference(lhs: AirExpression, rhs: AirExpression) -> Self {
        Self::Sub(Box::new(lhs), Box::new(rhs))
    }

    pub(crate) fn evaluate<E: TraceEvaluator>(
        &self,
        view: &E,
        row: usize,
        parameters: &StarkParameters,
    ) -> Result<FieldElement, AirError> {
        match self {
            AirExpression::Constant(value) => Ok(value.clone()),
            AirExpression::Column(reference) => {
                view.value(&reference.column, row, reference.offset)
            }
            AirExpression::Add(terms) => {
                let mut acc = FieldElement::zero(parameters.modulus());
                for term in terms {
                    let value = term.evaluate(view, row, parameters)?;
                    acc = acc.add(&value)?;
                }
                Ok(acc)
            }
            AirExpression::Sub(lhs, rhs) => {
                let left = lhs.evaluate(view, row, parameters)?;
                let right = rhs.evaluate(view, row, parameters)?;
                Ok(left.sub(&right)?)
            }
            AirExpression::Mul(terms) => {
                if terms.is_empty() {
                    return Ok(FieldElement::one(parameters.modulus()));
                }
                let mut acc = FieldElement::one(parameters.modulus());
                for term in terms {
                    let value = term.evaluate(view, row, parameters)?;
                    acc = acc.mul(&value)?;
                }
                Ok(acc)
            }
        }
    }
}

impl From<AirColumn> for AirExpression {
    fn from(column: AirColumn) -> Self {
        column.expr()
    }
}

/// Domain selector describing which rows of a trace segment a constraint
/// should be evaluated on.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConstraintDomain {
    AllRows,
    FirstRow,
    LastRow,
    Range { start: usize, end: Option<usize> },
}

impl ConstraintDomain {
    pub(crate) fn rows(&self, length: usize) -> Vec<usize> {
        match self {
            ConstraintDomain::AllRows => (0..length).collect(),
            ConstraintDomain::FirstRow => {
                if length > 0 {
                    vec![0]
                } else {
                    Vec::new()
                }
            }
            ConstraintDomain::LastRow => {
                if length > 0 {
                    vec![length - 1]
                } else {
                    Vec::new()
                }
            }
            ConstraintDomain::Range { start, end } => {
                if *start >= length {
                    Vec::new()
                } else {
                    let end_index = end.map(|idx| idx.min(length)).unwrap_or(length);
                    (*start..end_index).collect()
                }
            }
        }
    }
}

/// Algebraic constraint evaluated over a subset of rows inside a segment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AirConstraint {
    pub name: String,
    pub segment: String,
    pub domain: ConstraintDomain,
    pub expression: AirExpression,
}

impl AirConstraint {
    pub fn new(
        name: impl Into<String>,
        segment: impl Into<String>,
        domain: ConstraintDomain,
        expression: AirExpression,
    ) -> Self {
        Self {
            name: name.into(),
            segment: segment.into(),
            domain,
            expression,
        }
    }
}

/// Bundle of constraints describing the AIR for a circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AirDefinition {
    constraints: Vec<AirConstraint>,
}

impl AirDefinition {
    pub fn new(constraints: Vec<AirConstraint>) -> Self {
        Self { constraints }
    }

    pub fn constraints(&self) -> &[AirConstraint] {
        &self.constraints
    }

    /// Evaluate all constraints over the provided execution trace.
    pub fn evaluate(
        &self,
        trace: &ExecutionTrace,
        parameters: &StarkParameters,
    ) -> Result<Vec<ConstraintEvaluation>, AirError> {
        let view = TraceView::new(trace);
        let mut evaluations = Vec::with_capacity(self.constraints.len());
        for constraint in &self.constraints {
            let segment = view
                .segment(constraint.segment.as_str())
                .ok_or_else(|| AirError::MissingSegment(constraint.segment.clone()))?;
            let rows = constraint.domain.rows(segment.row_count());
            let mut results = Vec::new();
            for row in rows {
                let value = constraint.expression.evaluate(&view, row, parameters)?;
                if !value.is_zero() {
                    results.push((row, value));
                }
            }
            evaluations.push(ConstraintEvaluation {
                name: constraint.name.clone(),
                rows: results,
            });
        }
        Ok(evaluations)
    }
}

/// Evaluation results for a single AIR constraint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintEvaluation {
    pub name: String,
    pub rows: Vec<(usize, FieldElement)>,
}

impl ConstraintEvaluation {
    pub fn is_satisfied(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn first_violation(&self) -> Option<(usize, FieldElement)> {
        self.rows.first().cloned()
    }
}

/// Result of compressing multiple constraint evaluations into a linear
/// combination using random-looking challenges.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintCompressionResult {
    pub aggregated: Vec<(usize, FieldElement)>,
}

impl ConstraintCompressionResult {
    pub fn is_zero(&self) -> bool {
        self.aggregated.iter().all(|(_, value)| value.is_zero())
    }

    pub fn first_violation(&self) -> Option<(usize, FieldElement)> {
        self.aggregated
            .iter()
            .find(|(_, value)| !value.is_zero())
            .cloned()
    }
}

/// Deterministically derived randomizers used to combine constraint
/// evaluations. In a production prover these would be sampled via a Fiat–
/// Shamir transcript.
#[derive(Debug)]
pub struct ConstraintCompressor {
    challenges: Vec<FieldElement>,
}

impl ConstraintCompressor {
    pub fn new(parameters: &StarkParameters, air: &AirDefinition) -> Self {
        let hasher = parameters.poseidon_hasher();
        let challenges = air
            .constraints()
            .iter()
            .enumerate()
            .map(|(index, constraint)| {
                hasher.hash_bytes(&vec![
                    constraint.name.as_bytes().to_vec(),
                    (index as u64).to_be_bytes().to_vec(),
                ])
            })
            .collect();
        Self { challenges }
    }

    pub fn compress(
        &self,
        evaluations: &[ConstraintEvaluation],
    ) -> Result<ConstraintCompressionResult, AirError> {
        if evaluations.len() != self.challenges.len() {
            return Err(AirError::EvaluationCount {
                expected: self.challenges.len(),
                actual: evaluations.len(),
            });
        }
        let mut aggregated: BTreeMap<usize, FieldElement> = BTreeMap::new();
        for (evaluation, challenge) in evaluations.iter().zip(self.challenges.iter()) {
            for (row, value) in &evaluation.rows {
                let scaled = value.mul(challenge)?;
                if let Some(existing) = aggregated.get_mut(row) {
                    *existing = existing.add(&scaled)?;
                } else {
                    aggregated.insert(*row, scaled.clone());
                }
            }
        }
        Ok(ConstraintCompressionResult {
            aggregated: aggregated.into_iter().collect(),
        })
    }
}

struct SegmentView<'a> {
    name: &'a str,
    column_index: HashMap<&'a str, usize>,
    rows: &'a [Vec<FieldElement>],
}

impl<'a> SegmentView<'a> {
    fn new(segment: &'a crate::stwo::circuit::TraceSegment) -> Self {
        let mut column_index = HashMap::new();
        for (idx, column) in segment.columns.iter().enumerate() {
            column_index.insert(column.as_str(), idx);
        }
        Self {
            name: segment.name.as_str(),
            column_index,
            rows: &segment.rows,
        }
    }

    fn row_count(&self) -> usize {
        self.rows.len()
    }

    fn value(&self, column: &str, row: usize, offset: isize) -> Result<FieldElement, AirError> {
        let index = self
            .column_index
            .get(column)
            .ok_or_else(|| AirError::MissingColumn {
                segment: self.name.to_string(),
                column: column.to_string(),
            })?;
        let target = row as isize + offset;
        if target < 0 || target as usize >= self.rows.len() {
            return Err(AirError::RowOutOfBounds {
                segment: self.name.to_string(),
                column: column.to_string(),
                row,
                offset,
            });
        }
        Ok(self.rows[target as usize][*index].clone())
    }
}

struct TraceView<'a> {
    segments: HashMap<&'a str, SegmentView<'a>>,
}

impl<'a> TraceView<'a> {
    fn new(trace: &'a ExecutionTrace) -> Self {
        let segments = trace
            .segments
            .iter()
            .map(|segment| (segment.name.as_str(), SegmentView::new(segment)))
            .collect();
        Self { segments }
    }

    fn segment(&self, name: &str) -> Option<&SegmentView<'a>> {
        self.segments.get(name)
    }

    fn value(
        &self,
        column: &AirColumn,
        row: usize,
        offset: isize,
    ) -> Result<FieldElement, AirError> {
        let segment = self
            .segment(column.segment.as_str())
            .ok_or_else(|| AirError::MissingSegment(column.segment.clone()))?;
        segment.value(column.column.as_str(), row, offset)
    }
}

impl<'a> TraceEvaluator for TraceView<'a> {
    fn value(
        &self,
        column: &AirColumn,
        row: usize,
        offset: isize,
    ) -> Result<FieldElement, AirError> {
        TraceView::value(self, column, row, offset)
    }
}
