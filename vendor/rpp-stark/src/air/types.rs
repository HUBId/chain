//! Core type definitions for the AIR layer.
//!
//! The final API surface is still under construction; concrete data
//! structures will be introduced as the proof system stabilises.

use core::fmt;

use crate::field::prime_field::CanonicalSerialize;
use crate::field::FieldElement as Felt;
use crate::utils::serialization::FieldElementBytes;

/// Column identifier newtype used when reporting errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ColIx(usize);

impl ColIx {
    /// Creates a new column index wrapper.
    pub const fn new(ix: usize) -> Self {
        Self(ix)
    }

    /// Returns the underlying index as `usize`.
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

impl fmt::Display for ColIx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Describes the role a trace column plays in the execution trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceRole {
    /// Main trace columns feed directly into constraint evaluation.
    Main,
    /// Auxiliary columns are derived from witness relations.
    Auxiliary,
    /// Permutation columns encode lookup and permutation arguments.
    Permutation,
    /// Lookup columns capture table values used in lookup arguments.
    Lookup,
}

impl fmt::Display for TraceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceRole::Main => f.write_str("main"),
            TraceRole::Auxiliary => f.write_str("auxiliary"),
            TraceRole::Permutation => f.write_str("permutation"),
            TraceRole::Lookup => f.write_str("lookup"),
        }
    }
}

impl TraceRole {
    /// Returns all role variants in declaration order.
    pub const fn all() -> [TraceRole; 4] {
        [
            TraceRole::Main,
            TraceRole::Auxiliary,
            TraceRole::Permutation,
            TraceRole::Lookup,
        ]
    }
}

/// Little-endian domain extension order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdeOrder {
    blowup: usize,
}

impl LdeOrder {
    /// Creates a new LDE order descriptor.
    pub fn new(blowup: usize) -> Result<Self, AirError> {
        if blowup == 0 {
            return Err(AirError::LayoutViolation(
                "lde blowup factor must be strictly positive",
            ));
        }
        if !blowup.is_power_of_two() {
            return Err(AirError::LayoutViolation(
                "lde blowup factor must be a power of two",
            ));
        }
        Ok(Self { blowup })
    }

    /// Returns the configured blowup factor.
    pub const fn blowup(&self) -> usize {
        self.blowup
    }

    fn validate_rows(&self, rows: usize) -> Result<(), AirError> {
        if rows == 0 {
            return Err(AirError::LayoutViolation(
                "execution trace must contain at least one row",
            ));
        }
        if rows % self.blowup != 0 {
            return Err(AirError::LayoutViolation(
                "lde blowup factor must divide the execution trace length",
            ));
        }
        Ok(())
    }
}

/// Degree bounds for trace and auxiliary polynomials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DegreeBounds {
    main: usize,
    auxiliary: usize,
}

impl DegreeBounds {
    /// Constructs new degree bounds, enforcing consistency between roles.
    pub fn new(main: usize, auxiliary: usize) -> Result<Self, AirError> {
        if main == 0 {
            return Err(AirError::LayoutViolation(
                "main trace degree bound must be positive",
            ));
        }
        if auxiliary < main {
            return Err(AirError::LayoutViolation(
                "auxiliary degree bound must be at least the main bound",
            ));
        }
        Ok(Self { main, auxiliary })
    }

    fn check_role(&self, role: TraceRole, observed_degree: usize) -> Result<(), AirError> {
        let bound = match role {
            TraceRole::Main => self.main,
            TraceRole::Auxiliary | TraceRole::Permutation | TraceRole::Lookup => self.auxiliary,
        };
        if observed_degree > bound {
            Err(AirError::DegreeOverflow {
                role,
                observed: observed_degree,
                allowed: bound,
            })
        } else {
            Ok(())
        }
    }

    /// Ensures the observed degree stays within the configured bounds for `role`.
    pub fn ensure(&self, role: TraceRole, observed_degree: usize) -> Result<(), AirError> {
        self.check_role(role, observed_degree)
    }
}

/// Boundary position within the execution trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryAt {
    /// First row of the trace.
    First,
    /// Last row of the trace.
    Last,
    /// Arbitrary row index.
    Row(usize),
}

impl fmt::Display for BoundaryAt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundaryAt::First => f.write_str("first"),
            BoundaryAt::Last => f.write_str("last"),
            BoundaryAt::Row(ix) => write!(f, "row {ix}"),
        }
    }
}

/// Metadata describing a single trace column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceColMeta {
    /// Human readable column label.
    pub label: String,
    /// The role played by this column.
    pub role: TraceRole,
    /// Boundary values that are exposed publicly or enforced statically.
    pub boundaries: Vec<BoundaryAt>,
}

impl TraceColMeta {
    /// Creates a new trace column metadata descriptor.
    pub fn new(label: impl Into<String>, role: TraceRole) -> Self {
        Self {
            label: label.into(),
            role,
            boundaries: Vec::new(),
        }
    }

    /// Registers an additional boundary location.
    pub fn with_boundary(mut self, boundary: BoundaryAt) -> Self {
        if !self.boundaries.contains(&boundary) {
            self.boundaries.push(boundary);
        }
        self
    }

    fn allows(&self, boundary: &BoundaryAt) -> bool {
        self.boundaries.contains(boundary)
    }
}

/// Public input specification derived from the trace schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSpec {
    /// Fields exposed to the verifier.
    pub fields: Vec<PublicFieldMeta>,
}

impl PublicSpec {
    /// Validates the specification against a trace schema.
    pub fn validate(&self, schema: &TraceSchema) -> Result<(), AirError> {
        for field in &self.fields {
            if let PublicFieldType::TraceValue { column, boundary } = &field.field_type {
                let meta = schema
                    .column_meta(*column)
                    .ok_or_else(|| AirError::SchemaMismatch {
                        what: "trace column count",
                        expected: schema.columns.len(),
                        actual: column.as_usize() + 1,
                    })?;
                if !meta.allows(boundary) {
                    return Err(AirError::BoundaryViolation {
                        column: *column,
                        boundary: *boundary,
                        detail: "boundary not declared in schema",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Metadata for a single public field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicFieldMeta {
    /// Identifier used in documentation and transcripts.
    pub label: String,
    /// Typing information for the exposed field.
    pub field_type: PublicFieldType,
}

/// Public field typing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicFieldType {
    /// Constant value published independently of the trace.
    Constant(Felt),
    /// Value sourced from the execution trace.
    TraceValue { column: ColIx, boundary: BoundaryAt },
}

/// AIR level execution trace schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSchema {
    /// Metadata for each execution trace column.
    pub columns: Vec<TraceColMeta>,
    /// Domain extension order.
    pub lde_order: LdeOrder,
    /// Degree bounds for trace polynomials.
    pub degree_bounds: DegreeBounds,
}

impl TraceSchema {
    /// Creates a new trace schema descriptor.
    pub fn new(
        columns: Vec<TraceColMeta>,
        lde_order: LdeOrder,
        degree_bounds: DegreeBounds,
    ) -> Result<Self, AirError> {
        if columns.is_empty() {
            return Err(AirError::SchemaMismatch {
                what: "trace column count",
                expected: 1,
                actual: 0,
            });
        }
        Ok(Self {
            columns,
            lde_order,
            degree_bounds,
        })
    }

    /// Returns metadata for the requested column index.
    pub fn column_meta(&self, ix: ColIx) -> Option<&TraceColMeta> {
        self.columns.get(ix.as_usize())
    }

    /// Returns an iterator over the columns belonging to the supplied role.
    pub fn columns_by_role(&self, role: TraceRole) -> impl Iterator<Item = &TraceColMeta> {
        self.columns.iter().filter(move |meta| meta.role == role)
    }

    /// Returns the number of columns declared for each role.
    pub fn role_counts(&self) -> TraceRoleCounts {
        let mut counts = TraceRoleCounts::default();
        for meta in &self.columns {
            counts.increment(meta.role);
        }
        counts
    }

    /// Validates an execution trace against the schema.
    pub fn validate_trace(&self, trace: &TraceData) -> Result<(), AirError> {
        if self.columns.len() != trace.num_columns() {
            return Err(AirError::SchemaMismatch {
                what: "trace column count",
                expected: self.columns.len(),
                actual: trace.num_columns(),
            });
        }
        self.lde_order.validate_rows(trace.num_rows())?;
        let observed_degree = trace.num_rows().saturating_sub(1);
        for (ix, meta) in self.columns.iter().enumerate() {
            self.degree_bounds.check_role(meta.role, observed_degree)?;
            for boundary in &meta.boundaries {
                trace.boundary_value(ColIx::new(ix), *boundary)?;
            }
        }
        Ok(())
    }
}

/// Execution trace container used for schema validation and serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceData {
    columns: Vec<Vec<Felt>>,
    rows: usize,
}

/// Cardinality descriptor for trace segments grouped by [`TraceRole`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TraceRoleCounts {
    /// Number of main trace columns.
    pub main: usize,
    /// Number of auxiliary trace columns.
    pub auxiliary: usize,
    /// Number of permutation trace columns.
    pub permutation: usize,
    /// Number of lookup trace columns.
    pub lookup: usize,
}

impl TraceRoleCounts {
    /// Increments the counter associated with `role`.
    pub fn increment(&mut self, role: TraceRole) {
        match role {
            TraceRole::Main => self.main += 1,
            TraceRole::Auxiliary => self.auxiliary += 1,
            TraceRole::Permutation => self.permutation += 1,
            TraceRole::Lookup => self.lookup += 1,
        }
    }

    /// Returns the column count registered for `role`.
    pub fn get(&self, role: TraceRole) -> usize {
        match role {
            TraceRole::Main => self.main,
            TraceRole::Auxiliary => self.auxiliary,
            TraceRole::Permutation => self.permutation,
            TraceRole::Lookup => self.lookup,
        }
    }
}

impl TraceData {
    /// Creates a new trace data container.
    pub fn new(columns: Vec<Vec<Felt>>) -> Result<Self, AirError> {
        if columns.is_empty() {
            return Err(AirError::SchemaMismatch {
                what: "trace column count",
                expected: 1,
                actual: 0,
            });
        }
        let rows = columns[0].len();
        if rows == 0 {
            return Err(AirError::LayoutViolation(
                "execution trace must contain at least one row",
            ));
        }
        for column in &columns {
            if column.len() != rows {
                return Err(AirError::SchemaMismatch {
                    what: "trace row count",
                    expected: rows,
                    actual: column.len(),
                });
            }
        }
        Ok(Self { columns, rows })
    }

    /// Returns the number of columns.
    pub fn num_columns(&self) -> usize {
        self.columns.len()
    }

    /// Returns the number of rows.
    pub fn num_rows(&self) -> usize {
        self.rows
    }

    /// Returns a reference to a trace column.
    pub fn column(&self, ix: ColIx) -> Result<&[Felt], AirError> {
        self.columns
            .get(ix.as_usize())
            .map(|col| col.as_slice())
            .ok_or_else(|| AirError::SchemaMismatch {
                what: "trace column count",
                expected: self.columns.len(),
                actual: ix.as_usize() + 1,
            })
    }

    /// Returns the trace value at the specified boundary.
    pub fn boundary_value(&self, ix: ColIx, boundary: BoundaryAt) -> Result<Felt, AirError> {
        let column = self.column(ix)?;
        let row = match boundary {
            BoundaryAt::First => 0,
            BoundaryAt::Last => column.len().saturating_sub(1),
            BoundaryAt::Row(r) => r,
        };
        column.get(row).copied().ok_or(AirError::BoundaryViolation {
            column: ix,
            boundary,
            detail: "boundary outside trace length",
        })
    }

    /// Serialises a column into canonical little-endian field element bytes.
    pub fn column_bytes(&self, ix: ColIx) -> Result<Vec<FieldElementBytes>, AirError> {
        let column = self.column(ix)?;
        let mut bytes = Vec::with_capacity(column.len());
        for value in column {
            let mut buf = [0u8; 32];
            let le = value.to_bytes().map_err(|_| AirError::Serialization {
                kind: SerKind::Trace,
                detail: "non-canonical trace value",
            })?;
            buf[..le.len()].copy_from_slice(&le);
            bytes.push(FieldElementBytes { bytes: buf });
        }
        Ok(bytes)
    }
}

/// Serialization context kinds surfaced in [`AirError::Serialization`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerKind {
    /// Execution trace serialisation.
    Trace,
    /// Public input serialisation.
    PublicInput,
    /// Transcript serialisation.
    Transcript,
}

impl fmt::Display for SerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerKind::Trace => f.write_str("trace data"),
            SerKind::PublicInput => f.write_str("public input"),
            SerKind::Transcript => f.write_str("transcript"),
        }
    }
}

/// Error enumeration covering deterministic AIR failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AirError {
    /// Schema layout mismatch (column count, row count, etc.).
    SchemaMismatch {
        /// Description of the component that failed validation.
        what: &'static str,
        /// Expected cardinality.
        expected: usize,
        /// Actual cardinality encountered.
        actual: usize,
    },
    /// Schema declared a boundary outside the trace layout.
    InvalidBoundary {
        /// Column where the invalid boundary was declared.
        column: ColIx,
        /// Boundary location that failed validation.
        boundary: BoundaryAt,
        /// Additional diagnostic context.
        detail: &'static str,
    },
    /// Boundary constraint violation.
    BoundaryViolation {
        /// Column where the violation occurred.
        column: ColIx,
        /// Boundary location.
        boundary: BoundaryAt,
        /// Additional diagnostic context.
        detail: &'static str,
    },
    /// Transition relation failed for the provided witness values.
    InvalidTransition {
        /// Column identifier.
        column: ColIx,
        /// Step index.
        step: usize,
        /// Value at `step`.
        current: Felt,
        /// Value at `step + 1`.
        next: Felt,
    },
    /// Degree bound exceeded for the specified role.
    DegreeOverflow {
        /// Role for which the overflow was detected.
        role: TraceRole,
        /// Observed degree.
        observed: usize,
        /// Allowed maximum degree.
        allowed: usize,
    },
    /// Serialization failure for one of the helper contexts.
    Serialization {
        /// Serialization context.
        kind: SerKind,
        /// Description of the failure.
        detail: &'static str,
    },
    /// Witness column admitted non-determinism.
    NonDeterministicWitness {
        /// Column identifier.
        column: ColIx,
        /// Step index where mismatch was detected.
        step: usize,
    },
    /// General layout violation (e.g. invalid parameters).
    LayoutViolation(&'static str),
}

impl fmt::Display for AirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AirError::SchemaMismatch {
                what,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "schema mismatch for {what}: expected {expected}, got {actual}"
                )
            }
            AirError::InvalidBoundary {
                column,
                boundary,
                detail,
            } => write!(
                f,
                "invalid boundary at column {column} ({boundary}): {detail}"
            ),
            AirError::BoundaryViolation {
                column,
                boundary,
                detail,
            } => write!(
                f,
                "boundary violation at column {column} ({boundary}): {detail}"
            ),
            AirError::InvalidTransition {
                column,
                step,
                current,
                next,
            } => write!(
                f,
                "invalid transition at column {column} step {step}: {} -> {}",
                current.0, next.0
            ),
            AirError::DegreeOverflow {
                role,
                observed,
                allowed,
            } => write!(
                f,
                "degree overflow for {role} columns: observed {observed}, allowed {allowed}"
            ),
            AirError::Serialization { kind, detail } => {
                write!(f, "serialization error for {kind}: {detail}")
            }
            AirError::NonDeterministicWitness { column, step } => write!(
                f,
                "non-deterministic witness detected at column {column} step {step}"
            ),
            AirError::LayoutViolation(detail) => write!(f, "layout violation: {detail}"),
        }
    }
}

impl std::error::Error for AirError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_schema() -> Result<TraceSchema, AirError> {
        let columns = vec![
            TraceColMeta::new("main", TraceRole::Main)
                .with_boundary(BoundaryAt::First)
                .with_boundary(BoundaryAt::Last),
            TraceColMeta::new("aux", TraceRole::Auxiliary).with_boundary(BoundaryAt::Row(1)),
            TraceColMeta::new("perm", TraceRole::Permutation),
            TraceColMeta::new("lookup", TraceRole::Lookup),
        ];
        let lde = LdeOrder::new(4)?;
        let degree = DegreeBounds::new(3, 4)?;
        TraceSchema::new(columns, lde, degree)
    }

    fn sample_trace() -> Result<TraceData, AirError> {
        TraceData::new(vec![
            vec![
                Felt::from(1u64),
                Felt::from(2u64),
                Felt::from(3u64),
                Felt::from(4u64),
            ],
            vec![
                Felt::from(5u64),
                Felt::from(6u64),
                Felt::from(7u64),
                Felt::from(8u64),
            ],
            vec![
                Felt::from(9u64),
                Felt::from(10u64),
                Felt::from(11u64),
                Felt::from(12u64),
            ],
            vec![
                Felt::from(13u64),
                Felt::from(14u64),
                Felt::from(15u64),
                Felt::from(16u64),
            ],
        ])
    }

    #[test]
    fn schema_validation_accepts_matching_trace() -> Result<(), AirError> {
        let schema = sample_schema()?;
        let trace = sample_trace()?;
        schema.validate_trace(&trace)?;
        Ok(())
    }

    #[test]
    fn schema_validation_detects_mismatched_columns() -> Result<(), AirError> {
        let schema = sample_schema()?;
        let trace = TraceData::new(vec![vec![
            Felt::from(1u64),
            Felt::from(2u64),
            Felt::from(3u64),
            Felt::from(4u64),
        ]])?;
        let result = schema.validate_trace(&trace);
        match result {
            Err(AirError::SchemaMismatch {
                what,
                expected,
                actual,
            }) => {
                if what != "trace column count" {
                    return Err(AirError::LayoutViolation("unexpected mismatch kind"));
                }
                if expected != 4 || actual != 1 {
                    return Err(AirError::LayoutViolation("unexpected mismatch values"));
                }
                Ok(())
            }
            Err(err) => Err(err),
            Ok(_) => Err(AirError::LayoutViolation("schema should reject trace")),
        }
    }

    #[test]
    fn role_counts_report_segment_widths() -> Result<(), AirError> {
        let schema = sample_schema()?;
        let counts = schema.role_counts();
        assert_eq!(counts.get(TraceRole::Main), 1);
        assert_eq!(counts.get(TraceRole::Auxiliary), 1);
        assert_eq!(counts.get(TraceRole::Permutation), 1);
        assert_eq!(counts.get(TraceRole::Lookup), 1);
        Ok(())
    }

    #[test]
    fn trace_serialization_uses_little_endian_helpers() -> Result<(), AirError> {
        let trace = TraceData::new(vec![
            vec![Felt::from(1u64), Felt::from(0x0102_0304_0506_0708u64)],
            vec![Felt::from(9u64), Felt::from(10u64)],
        ])?;
        let column_bytes = trace.column_bytes(ColIx::new(0))?;
        if column_bytes.len() != 2 {
            return Err(AirError::LayoutViolation(
                "unexpected column serialization length",
            ));
        }
        if column_bytes[0].bytes[..8] != 1u64.to_le_bytes() {
            return Err(AirError::LayoutViolation("first element not little-endian"));
        }
        if column_bytes[0].bytes[8..].iter().any(|b| *b != 0) {
            return Err(AirError::LayoutViolation("first element padding not zero"));
        }
        if column_bytes[1].bytes[..8] != 0x0102_0304_0506_0708u64.to_le_bytes() {
            return Err(AirError::LayoutViolation(
                "second element not little-endian",
            ));
        }
        Ok(())
    }

    #[test]
    fn air_error_formatting_is_human_readable() -> Result<(), AirError> {
        let transition = AirError::InvalidTransition {
            column: ColIx::new(1),
            step: 3,
            current: Felt::from(5u64),
            next: Felt::from(7u64),
        };
        if format!("{transition}") != "invalid transition at column #1 step 3: 5 -> 7" {
            return Err(AirError::LayoutViolation(
                "unexpected transition formatting",
            ));
        }

        let serialization = AirError::Serialization {
            kind: SerKind::Trace,
            detail: "io failure",
        };
        if format!("{serialization}") != "serialization error for trace data: io failure" {
            return Err(AirError::LayoutViolation(
                "unexpected serialization formatting",
            ));
        }
        Ok(())
    }
}
