//! Trace handling utilities used during witness generation.
//!
//! The trace container implemented here keeps execution witnesses in a
//! canonical row-major layout and exposes ergonomic accessors tailored for
//! transition constraint evaluation.  Construction validates the supplied data
//! against [`TraceSchema`], ensuring width/length consistency and boundary
//! declarations that remain within the table height.  Additional helpers bridge
//! the trace storage with the deterministic low-degree extension (LDE)
//! primitives so callers can reliably derive evaluation-domain values.

use core::fmt;
use std::sync::Arc;

use crate::air::types::{AirError, BoundaryAt, ColIx, TraceSchema};
use crate::fft::lde::{LowDegreeExtender, LowDegreeExtensionParameters};
use crate::field::FieldElement as Felt;

/// Execution trace container backed by a canonical row-major buffer.
#[derive(Debug, Clone)]
pub struct Trace {
    schema: Arc<TraceSchema>,
    width: usize,
    length: usize,
    values: Vec<Felt>,
}

impl Trace {
    /// Creates a new trace from a row-major matrix.
    pub fn from_rows(schema: TraceSchema, rows: Vec<Vec<Felt>>) -> Result<Self, AirError> {
        Self::from_rows_with_schema(Arc::new(schema), rows)
    }

    /// Creates a new trace from a row-major matrix and a shared schema handle.
    pub fn from_rows_with_schema(
        schema: Arc<TraceSchema>,
        rows: Vec<Vec<Felt>>,
    ) -> Result<Self, AirError> {
        let width = schema.columns.len();
        if width == 0 {
            return Err(AirError::SchemaMismatch {
                what: "trace column count",
                expected: 1,
                actual: 0,
            });
        }
        if rows.is_empty() {
            return Err(AirError::SchemaMismatch {
                what: "trace row count",
                expected: 1,
                actual: 0,
            });
        }

        let mut values = Vec::with_capacity(width * rows.len());
        for row in rows {
            if row.len() != width {
                return Err(AirError::SchemaMismatch {
                    what: "trace column count",
                    expected: width,
                    actual: row.len(),
                });
            }
            values.extend_from_slice(&row);
        }
        Self::build(schema, width, values)
    }

    /// Creates a new trace from a column-major matrix.
    pub fn from_columns(schema: TraceSchema, columns: Vec<Vec<Felt>>) -> Result<Self, AirError> {
        Self::from_columns_with_schema(Arc::new(schema), columns)
    }

    /// Creates a new trace from a column-major matrix and a shared schema handle.
    pub fn from_columns_with_schema(
        schema: Arc<TraceSchema>,
        columns: Vec<Vec<Felt>>,
    ) -> Result<Self, AirError> {
        let width = schema.columns.len();
        if width == 0 {
            return Err(AirError::SchemaMismatch {
                what: "trace column count",
                expected: 1,
                actual: 0,
            });
        }
        if columns.len() != width {
            return Err(AirError::SchemaMismatch {
                what: "trace column count",
                expected: width,
                actual: columns.len(),
            });
        }
        let length = columns[0].len();
        if length == 0 {
            return Err(AirError::SchemaMismatch {
                what: "trace row count",
                expected: 1,
                actual: 0,
            });
        }
        let mut values = vec![Felt::default(); width * length];
        for (col_ix, column) in columns.iter().enumerate() {
            if column.len() != length {
                return Err(AirError::SchemaMismatch {
                    what: "trace row count",
                    expected: length,
                    actual: column.len(),
                });
            }
            for (row_ix, value) in column.iter().enumerate() {
                let slot = row_ix * width + col_ix;
                values[slot] = *value;
            }
        }
        Self::finalise(schema, width, length, values)
    }

    /// Returns the trace width (number of columns).
    pub fn width(&self) -> usize {
        self.width
    }

    /// Returns the trace length (number of rows).
    pub fn length(&self) -> usize {
        self.length
    }

    /// Returns the underlying schema descriptor.
    pub fn schema(&self) -> &TraceSchema {
        &self.schema
    }

    /// Returns the canonical row-major view of the trace.
    pub fn as_slice(&self) -> &[Felt] {
        &self.values
    }

    /// Returns a view of the requested row.
    pub fn row(&self, row: usize) -> Result<RowView<'_>, AirError> {
        let slice = self.row_slice(row)?;
        Ok(RowView { values: slice })
    }

    /// Returns a view over `row` and its successor (wrapping at the end).
    pub fn row_pair(&self, row: usize) -> Result<NextRowView<'_>, AirError> {
        let current = self.row_slice(row)?;
        let next = self.row_slice((row + 1) % self.length)?;
        Ok(NextRowView { current, next })
    }

    /// Builds a deterministic low-degree extender for the trace.
    pub fn to_lde(
        &self,
        params: &'static LowDegreeExtensionParameters,
    ) -> Result<LowDegreeExtender, AirError> {
        self.validate_lde_profile(params)?;
        Ok(LowDegreeExtender::new(self.length, self.width, params))
    }

    /// Computes LDE evaluations using the provided profile.
    pub fn lde_evaluations(
        &self,
        params: &'static LowDegreeExtensionParameters,
    ) -> Result<Vec<Felt>, AirError> {
        let extender = self.to_lde(params)?;
        Ok(extender.extend_trace(&self.values))
    }

    fn build(schema: Arc<TraceSchema>, width: usize, values: Vec<Felt>) -> Result<Self, AirError> {
        let length = values.len() / width;
        if length * width != values.len() {
            return Err(AirError::LayoutViolation("trace layout not rectangular"));
        }
        Self::finalise(schema, width, length, values)
    }

    fn finalise(
        schema: Arc<TraceSchema>,
        width: usize,
        length: usize,
        values: Vec<Felt>,
    ) -> Result<Self, AirError> {
        if length == 0 {
            return Err(AirError::SchemaMismatch {
                what: "trace row count",
                expected: 1,
                actual: 0,
            });
        }
        if values.len() != width * length {
            return Err(AirError::LayoutViolation("trace layout not rectangular"));
        }
        let blowup = schema.lde_order.blowup();
        if blowup == 0 || length % blowup != 0 {
            return Err(AirError::LayoutViolation(
                "lde blowup factor must divide the execution trace length",
            ));
        }
        Self::validate_boundaries(&schema, length)?;
        Ok(Self {
            schema,
            width,
            length,
            values,
        })
    }

    fn validate_boundaries(schema: &TraceSchema, length: usize) -> Result<(), AirError> {
        for (ix, column) in schema.columns.iter().enumerate() {
            let column_ix = ColIx::new(ix);
            for boundary in &column.boundaries {
                if let BoundaryAt::Row(row) = boundary {
                    if *row >= length {
                        return Err(AirError::InvalidBoundary {
                            column: column_ix,
                            boundary: *boundary,
                            detail: "boundary exceeds trace length",
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn row_slice(&self, row: usize) -> Result<&[Felt], AirError> {
        if row >= self.length {
            return Err(AirError::LayoutViolation("row index out of bounds"));
        }
        let start = row * self.width;
        let end = start + self.width;
        Ok(&self.values[start..end])
    }

    fn validate_lde_profile(
        &self,
        params: &'static LowDegreeExtensionParameters,
    ) -> Result<(), AirError> {
        if params.blowup_factor != self.schema.lde_order.blowup() {
            return Err(AirError::LayoutViolation(
                "lde profile blowup does not match schema",
            ));
        }
        if self.length == 0 {
            return Err(AirError::LayoutViolation(
                "execution trace must contain at least one row",
            ));
        }
        if !self.length.is_power_of_two() {
            return Err(AirError::LayoutViolation(
                "trace length must be a power of two for LDE",
            ));
        }
        if self.width == 0 {
            return Err(AirError::SchemaMismatch {
                what: "trace column count",
                expected: 1,
                actual: 0,
            });
        }
        Ok(())
    }
}

/// Immutable view over a trace row.
#[derive(Clone, Copy)]
pub struct RowView<'a> {
    values: &'a [Felt],
}

impl<'a> RowView<'a> {
    /// Returns the underlying slice of values.
    pub fn as_slice(&self) -> &'a [Felt] {
        self.values
    }

    /// Returns the value at the specified column.
    pub fn get(&self, column: ColIx) -> Result<Felt, AirError> {
        self.values
            .get(column.as_usize())
            .copied()
            .ok_or_else(|| AirError::SchemaMismatch {
                what: "trace column count",
                expected: self.values.len(),
                actual: column.as_usize() + 1,
            })
    }

    /// Returns the number of columns in the row.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` when the row is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl<'a> fmt::Debug for RowView<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RowView").field(&self.values).finish()
    }
}

/// Immutable view over a row and its successor.
#[derive(Clone, Copy)]
pub struct NextRowView<'a> {
    current: &'a [Felt],
    next: &'a [Felt],
}

impl<'a> NextRowView<'a> {
    /// Returns the view over the current row.
    pub fn current(&self) -> RowView<'a> {
        RowView {
            values: self.current,
        }
    }

    /// Returns the view over the successor row.
    pub fn next(&self) -> RowView<'a> {
        RowView { values: self.next }
    }

    /// Returns the pair `(current, next)` for the specified column.
    pub fn get(&self, column: ColIx) -> Result<(Felt, Felt), AirError> {
        let current = self
            .current
            .get(column.as_usize())
            .copied()
            .ok_or_else(|| AirError::SchemaMismatch {
                what: "trace column count",
                expected: self.current.len(),
                actual: column.as_usize() + 1,
            })?;
        let next =
            self.next
                .get(column.as_usize())
                .copied()
                .ok_or_else(|| AirError::SchemaMismatch {
                    what: "trace column count",
                    expected: self.next.len(),
                    actual: column.as_usize() + 1,
                })?;
        Ok((current, next))
    }
}

impl<'a> fmt::Debug for NextRowView<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NextRowView")
            .field("current", &self.current)
            .field("next", &self.next)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::types::{DegreeBounds, TraceColMeta, TraceRole};
    use crate::fft::lde::{
        ChunkingDeterminism, ChunkingStrategy, CoefficientEndianness, EvaluationOrder,
        TraceToLdeMapping,
    };
    use crate::field::prime_field::CanonicalSerialize;

    const TEST_PROFILE_ROW_MAJOR: LowDegreeExtensionParameters = LowDegreeExtensionParameters {
        blowup_factor: 1,
        evaluation_order: EvaluationOrder::Natural,
        coefficient_endianness: CoefficientEndianness::Little,
        trace_mapping: TraceToLdeMapping::RowMajorContiguous,
        chunking: ChunkingStrategy {
            chunk_size: 1,
            determinism: ChunkingDeterminism::DomainMajor,
            description: "Test profile row-major",
        },
    };

    const TEST_PROFILE_COLUMN_INTERLEAVED: LowDegreeExtensionParameters =
        LowDegreeExtensionParameters {
            blowup_factor: 1,
            evaluation_order: EvaluationOrder::Natural,
            coefficient_endianness: CoefficientEndianness::Little,
            trace_mapping: TraceToLdeMapping::ColumnInterleaved,
            chunking: ChunkingStrategy {
                chunk_size: 1,
                determinism: ChunkingDeterminism::DomainMajor,
                description: "Test profile column-interleaved",
            },
        };

    fn sample_schema(columns: usize) -> Result<TraceSchema, AirError> {
        let mut metas = Vec::new();
        for ix in 0..columns {
            let role = if ix == 0 {
                TraceRole::Main
            } else {
                TraceRole::Auxiliary
            };
            metas.push(TraceColMeta::new(format!("col{ix}"), role));
        }
        let lde = crate::air::types::LdeOrder::new(1)?;
        let degree = DegreeBounds::new(1, 1)?;
        TraceSchema::new(metas, lde, degree)
    }

    #[test]
    fn trace_from_rows_preserves_row_major_layout() -> Result<(), AirError> {
        let schema = sample_schema(3)?;
        let trace = Trace::from_rows(
            schema,
            vec![
                vec![Felt::from(1u64), Felt::from(2u64), Felt::from(3u64)],
                vec![Felt::from(4u64), Felt::from(5u64), Felt::from(6u64)],
            ],
        )?;
        let expected = vec![
            Felt::from(1u64),
            Felt::from(2u64),
            Felt::from(3u64),
            Felt::from(4u64),
            Felt::from(5u64),
            Felt::from(6u64),
        ];
        assert_eq!(trace.as_slice(), expected.as_slice());
        let serialized: Vec<[u8; 8]> = trace
            .as_slice()
            .iter()
            .map(|value| {
                value
                    .to_bytes()
                    .expect("trace fixture values must be canonical")
            })
            .collect();
        assert_eq!(serialized[0], 1u64.to_le_bytes());
        assert_eq!(serialized[3], 4u64.to_le_bytes());
        Ok(())
    }

    #[test]
    fn row_and_next_row_views_access_expected_values() -> Result<(), AirError> {
        let schema = sample_schema(2)?;
        let trace = Trace::from_rows(
            schema,
            vec![
                vec![Felt::from(10u64), Felt::from(11u64)],
                vec![Felt::from(20u64), Felt::from(21u64)],
                vec![Felt::from(30u64), Felt::from(31u64)],
                vec![Felt::from(40u64), Felt::from(41u64)],
            ],
        )?;

        let row = trace.row(2)?;
        assert_eq!(row.len(), 2);
        assert_eq!(row.get(ColIx::new(0))?, Felt::from(30u64));
        assert_eq!(row.get(ColIx::new(1))?, Felt::from(31u64));

        let pair = trace.row_pair(3)?;
        let (current, next) = pair.get(ColIx::new(0))?;
        assert_eq!(current, Felt::from(40u64));
        assert_eq!(next, Felt::from(10u64));
        let (current_aux, next_aux) = pair.get(ColIx::new(1))?;
        assert_eq!(current_aux, Felt::from(41u64));
        assert_eq!(next_aux, Felt::from(11u64));
        Ok(())
    }

    #[test]
    fn lde_evaluations_respect_row_major_mapping() -> Result<(), AirError> {
        let schema = sample_schema(2)?;
        let trace = Trace::from_rows(
            schema,
            vec![
                vec![Felt::from(1u64), Felt::from(2u64)],
                vec![Felt::from(3u64), Felt::from(4u64)],
                vec![Felt::from(5u64), Felt::from(6u64)],
                vec![Felt::from(7u64), Felt::from(8u64)],
            ],
        )?;
        let evaluations = trace.lde_evaluations(&TEST_PROFILE_ROW_MAJOR)?;
        assert_eq!(evaluations.as_slice(), trace.as_slice());
        Ok(())
    }

    #[test]
    fn lde_evaluations_respect_column_interleaved_mapping() -> Result<(), AirError> {
        let schema = sample_schema(2)?;
        let trace = Trace::from_rows(
            schema,
            vec![
                vec![Felt::from(1u64), Felt::from(2u64)],
                vec![Felt::from(3u64), Felt::from(4u64)],
                vec![Felt::from(5u64), Felt::from(6u64)],
                vec![Felt::from(7u64), Felt::from(8u64)],
            ],
        )?;
        let evaluations = trace.lde_evaluations(&TEST_PROFILE_COLUMN_INTERLEAVED)?;
        let expected = vec![
            Felt::from(1u64),
            Felt::from(3u64),
            Felt::from(5u64),
            Felt::from(7u64),
            Felt::from(2u64),
            Felt::from(4u64),
            Felt::from(6u64),
            Felt::from(8u64),
        ];
        assert_eq!(evaluations, expected);
        Ok(())
    }
}
