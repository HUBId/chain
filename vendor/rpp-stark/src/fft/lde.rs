//! Low-degree extension parameterisation.
//!
//! This module no longer exposes imperative extension helpers but instead
//! collects the metadata required by FFT back-ends and audit tooling.  The
//! parameters describe how a trace polynomial is transformed into an evaluation
//! domain, covering blowup factors, deterministic evaluation ordering, mapping
//! conventions and chunking constraints.

use crate::fft::{
    ifft::{Ifft, Radix2InverseFft},
    Fft, Radix2Fft, Radix2Ordering,
};
use crate::field::FieldElement;

/// Ordering in which evaluation points are produced by the LDE engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationOrder {
    /// Natural ordering, where the first evaluation corresponds to the first
    /// coset element and the sequence progresses monotonically.
    Natural,
    /// Bit-reversed ordering to match in-place radix-2 FFT algorithms.
    BitReversed,
}

/// Endianness used when serialising polynomial coefficients into Montgomery
/// limbs for the evaluation domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoefficientEndianness {
    /// Least significant limb first (little endian).
    Little,
    /// Most significant limb first (big endian).
    Big,
}

/// Mapping strategy that explains how trace rows and columns are placed within
/// the LDE evaluation domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceToLdeMapping {
    /// Each trace row is expanded contiguously before advancing to the next
    /// row.  The LDE therefore mirrors a row-major trace layout.
    RowMajorContiguous,
    /// Trace columns are interleaved so that each column occupies a distinct
    /// coset stride.  This is typically used for high-security profiles.
    ColumnInterleaved,
}

/// Deterministic chunking rules for distributing LDE work across workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkingDeterminism {
    /// Chunks are assigned by natural domain order; chunk `i` always contains
    /// the evaluations `i * chunk_size..(i + 1) * chunk_size`.
    DomainMajor,
    /// Chunks are allocated in a worker-major fashion where each worker is
    /// given contiguous rows before moving to the next worker id.
    WorkerMajor,
}

/// Strategy describing how the evaluation domain is partitioned deterministically.
#[derive(Debug, Clone, Copy)]
pub struct ChunkingStrategy {
    /// Number of evaluation points per deterministic chunk.
    pub chunk_size: usize,
    /// Deterministic ordering by which chunks are assigned.
    pub determinism: ChunkingDeterminism,
    /// Human readable explanation for audit logs.
    pub description: &'static str,
}

/// Parameters describing a low-degree extension profile.
#[derive(Debug, Clone, Copy)]
pub struct LowDegreeExtensionParameters {
    /// Multiplicative blowup factor applied to the trace domain.
    pub blowup_factor: usize,
    /// Ordering of the evaluation sequence.
    pub evaluation_order: EvaluationOrder,
    /// Endianness used for Montgomery representation.
    pub coefficient_endianness: CoefficientEndianness,
    /// Mapping from trace layout to the LDE domain.
    pub trace_mapping: TraceToLdeMapping,
    /// Deterministic chunking constraints.
    pub chunking: ChunkingStrategy,
}

/// Trait implemented by profiles capable of describing their parameters.
pub trait LowDegreeExtensionProfile {
    /// Returns the parameters describing this profile.
    fn parameters(&self) -> &'static LowDegreeExtensionParameters;
}

/// Standard ×8 blowup profile.
///
/// * **Evaluation order:** [`EvaluationOrder::BitReversed`] to optimise for
///   in-place radix-2 FFTs.  The first chunk therefore contains the bit-reverse
///   of indices `[0, chunk_size)`, matching historical prover expectations.
/// * **Endianness:** [`CoefficientEndianness::Little`], encoding least
///   significant limbs first as used by the trace commitment machinery.
/// * **Trace mapping:** [`TraceToLdeMapping::RowMajorContiguous`], i.e. rows are
///   extended one after another and each row contributes `blowup_factor`
///   evaluations.
/// * **Chunking:** Deterministic domain-major chunks of size equal to the
///   `blowup_factor`.  Chunk `i` therefore contains the bit-reversed indices for
///   row `i` and is stable across worker counts.
pub const PROFILE_X8: LowDegreeExtensionParameters = LowDegreeExtensionParameters {
    blowup_factor: 8,
    evaluation_order: EvaluationOrder::BitReversed,
    coefficient_endianness: CoefficientEndianness::Little,
    trace_mapping: TraceToLdeMapping::RowMajorContiguous,
    chunking: ChunkingStrategy {
        chunk_size: 8,
        determinism: ChunkingDeterminism::DomainMajor,
        description:
            "Domain-major deterministic chunks, each covering one row's bit-reversed evaluations",
    },
};

/// High-security ×16 profile used for audit-grade runs.
///
/// * **Evaluation order:** [`EvaluationOrder::Natural`] to simplify manual
///   inspection—chunk `i` begins at index `i * chunk_size` and increases
///   monotonically.
/// * **Endianness:** [`CoefficientEndianness::Little`]; even in audit mode the
///   prover persists Montgomery limbs in little-endian order to maintain
///   compatibility with transcript hashing.
/// * **Trace mapping:** [`TraceToLdeMapping::ColumnInterleaved`], ensuring that
///   each trace column occupies its own coset stride.  This minimises leakage in
///   high-security audits by separating witness columns.
/// * **Chunking:** Worker-major deterministic chunks of size `4 * blowup_factor`
///   to amortise cache penalties during audit replay.  Workers receive a
///   deterministic sequence of column-major stripes.
pub const PROFILE_HISEC_X16: LowDegreeExtensionParameters = LowDegreeExtensionParameters {
    blowup_factor: 16,
    evaluation_order: EvaluationOrder::Natural,
    coefficient_endianness: CoefficientEndianness::Little,
    trace_mapping: TraceToLdeMapping::ColumnInterleaved,
    chunking: ChunkingStrategy {
        chunk_size: 64,
        determinism: ChunkingDeterminism::WorkerMajor,
        description:
            "Worker-major deterministic stripes, four rows per worker in column-interleaved order",
    },
};

/// Collection of profiles compiled when audit instrumentation is enabled.
#[cfg(feature = "audit-lde")]
pub const AUDIT_PROFILES: &[LowDegreeExtensionParameters] = &[PROFILE_X8];

/// High-security profiles compiled only when the `audit-lde-hisec` feature is
/// enabled.  The feature depends on `audit-lde` to ensure shared reporting
/// infrastructure.
#[cfg(feature = "audit-lde-hisec")]
pub const AUDIT_PROFILE_HISEC: &[LowDegreeExtensionParameters] = &[PROFILE_HISEC_X16];

/// Canonical low-degree extender executing interpolation and evaluation according to a
/// [`LowDegreeExtensionParameters`] profile.
#[derive(Debug, Clone)]
pub struct LowDegreeExtender {
    params: &'static LowDegreeExtensionParameters,
    trace_rows: usize,
    trace_columns: usize,
    log2_extended_rows: usize,
    inverse_plan: Radix2InverseFft<FieldElement>,
    forward_plan: Radix2Fft,
}

impl LowDegreeExtender {
    /// Builds a new extender for the provided trace dimensions and profile.
    ///
    /// The trace slice consumed by `extend_trace` must contain
    /// `trace_rows * trace_columns` elements laid out in **row-major natural order**.
    pub fn new(
        trace_rows: usize,
        trace_columns: usize,
        params: &'static LowDegreeExtensionParameters,
    ) -> Self {
        assert!(
            trace_rows.is_power_of_two(),
            "trace height must be a power of two"
        );
        assert!(trace_rows > 0, "trace height must be non-zero");
        assert!(trace_columns > 0, "trace width must be non-zero");
        assert!(
            params.blowup_factor.is_power_of_two(),
            "only power-of-two blowup factors are supported",
        );

        assert_eq!(
            params.coefficient_endianness,
            CoefficientEndianness::Little,
            "coefficients are expected to be stored in little-endian order",
        );

        let log2_trace_rows = trace_rows.trailing_zeros() as usize;
        let log2_blowup = params.blowup_factor.trailing_zeros() as usize;
        let log2_extended_rows = log2_trace_rows + log2_blowup;

        let inverse_plan = Radix2InverseFft::natural_order(log2_trace_rows);
        let forward_ordering = match params.evaluation_order {
            EvaluationOrder::Natural => Radix2Ordering::Natural,
            EvaluationOrder::BitReversed => Radix2Ordering::BitReversed,
        };
        let forward_plan = Radix2Fft::new(log2_extended_rows, forward_ordering);

        Self {
            params,
            trace_rows,
            trace_columns,
            log2_extended_rows,
            inverse_plan,
            forward_plan,
        }
    }

    /// Returns the associated extension parameters.
    pub fn params(&self) -> &'static LowDegreeExtensionParameters {
        self.params
    }

    /// Returns the trace height.
    pub fn trace_rows(&self) -> usize {
        self.trace_rows
    }

    /// Returns the trace width.
    pub fn trace_columns(&self) -> usize {
        self.trace_columns
    }

    /// Returns the number of rows in the extended evaluation domain.
    pub fn extended_rows(&self) -> usize {
        self.trace_rows * self.params.blowup_factor
    }

    /// Returns the logarithm (base 2) of the extended evaluation domain size.
    pub fn log2_extended_rows(&self) -> usize {
        self.log2_extended_rows
    }

    /// Performs the low-degree extension for the provided trace slice.
    pub fn extend_trace(&self, trace: &[FieldElement]) -> Vec<FieldElement> {
        assert_eq!(
            trace.len(),
            self.trace_rows * self.trace_columns,
            "trace slice length does not match configured dimensions",
        );

        let mut lde = vec![FieldElement::ZERO; self.extended_rows() * self.trace_columns];
        let mut column_buffer = vec![FieldElement::ZERO; self.trace_rows];
        let mut extended_buffer = vec![FieldElement::ZERO; self.extended_rows()];

        for column in 0..self.trace_columns {
            Self::gather_column(trace, self.trace_columns, column, &mut column_buffer);

            let mut coefficients = column_buffer.clone();
            self.inverse_plan.inverse(&mut coefficients);

            extended_buffer[..self.trace_rows].copy_from_slice(&coefficients);
            for value in extended_buffer[self.trace_rows..].iter_mut() {
                *value = FieldElement::ZERO;
            }

            self.forward_plan.forward(&mut extended_buffer);
            self.scatter_column(column, &extended_buffer, &mut lde);
        }

        lde
    }

    /// Returns the deterministic chunk iterator for the provided worker.
    pub fn chunk_iter(&self, worker_id: usize, worker_count: usize) -> LdeChunkIter {
        assert!(worker_count > 0, "worker count must be non-zero");
        assert!(worker_id < worker_count, "worker id out of range");

        let chunk_size = self.params.chunking.chunk_size;
        assert!(chunk_size > 0, "chunk size must be non-zero");
        let total_rows = self.extended_rows();
        let total_chunks = total_rows.div_ceil(chunk_size);

        let mut assignments = Vec::new();

        match self.params.chunking.determinism {
            ChunkingDeterminism::DomainMajor => {
                for chunk_idx in (worker_id..total_chunks).step_by(worker_count) {
                    let start = chunk_idx * chunk_size;
                    let end = (start + chunk_size).min(total_rows);
                    assignments.push(LdeChunk {
                        start_row: start,
                        end_row: end,
                    });
                }
            }
            ChunkingDeterminism::WorkerMajor => {
                let chunks_per_worker = total_chunks.div_ceil(worker_count);
                let start_chunk = worker_id * chunks_per_worker;
                let end_chunk = ((worker_id + 1) * chunks_per_worker).min(total_chunks);
                for chunk_idx in start_chunk..end_chunk {
                    let start = chunk_idx * chunk_size;
                    let end = (start + chunk_size).min(total_rows);
                    assignments.push(LdeChunk {
                        start_row: start,
                        end_row: end,
                    });
                }
            }
        }

        LdeChunkIter {
            inner: assignments.into_iter(),
        }
    }

    /// Computes the canonical evaluation-index mapping for the provided natural row and column.
    ///
    /// Rows are specified in **natural** order (i.e. the order used by the original trace).
    /// The LDE storage index incorporates both the evaluation ordering dictated by the
    /// profile and the trace-to-LDE mapping strategy:
    ///
    /// * [`EvaluationOrder::Natural`] stores row `r` at index `r` before applying the layout.
    /// * [`EvaluationOrder::BitReversed`] stores row `r` at index `bit_reverse(r, log2_n)`.
    /// * [`TraceToLdeMapping::RowMajorContiguous`] multiplies the evaluation index by the trace
    ///   width before adding the column so that each extended row occupies a contiguous slice.
    /// * [`TraceToLdeMapping::ColumnInterleaved`] offsets by `column * extended_rows()` so that
    ///   each trace column occupies its own coset stride.
    pub fn lde_index(&self, natural_row: usize, column: usize) -> usize {
        assert!(natural_row < self.extended_rows(), "row out of bounds");
        assert!(column < self.trace_columns, "column out of bounds");
        let evaluation_index = self.evaluation_position(natural_row);
        match self.params.trace_mapping {
            TraceToLdeMapping::RowMajorContiguous => evaluation_index * self.trace_columns + column,
            TraceToLdeMapping::ColumnInterleaved => {
                column * self.extended_rows() + evaluation_index
            }
        }
    }

    fn evaluation_position(&self, natural_row: usize) -> usize {
        match self.params.evaluation_order {
            EvaluationOrder::Natural => natural_row,
            EvaluationOrder::BitReversed => reverse_bits(natural_row, self.log2_extended_rows),
        }
    }

    fn scatter_column(
        &self,
        column: usize,
        evaluations: &[FieldElement],
        output: &mut [FieldElement],
    ) {
        assert_eq!(evaluations.len(), self.extended_rows());
        assert_eq!(output.len(), self.extended_rows() * self.trace_columns);
        for natural_row in 0..self.extended_rows() {
            let evaluation_index = self.evaluation_position(natural_row);
            let destination = self.lde_index(natural_row, column);
            output[destination] = evaluations[evaluation_index];
        }
    }

    fn gather_column(
        trace: &[FieldElement],
        trace_columns: usize,
        column: usize,
        buffer: &mut [FieldElement],
    ) {
        for (row, slot) in buffer.iter_mut().enumerate() {
            *slot = trace[row * trace_columns + column];
        }
    }
}

/// Range of natural rows processed by a deterministic LDE chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdeChunk {
    /// Start row (inclusive) in natural order.
    pub start_row: usize,
    /// End row (exclusive) in natural order.
    pub end_row: usize,
}

/// Iterator over deterministic LDE chunks for a specific worker.
#[derive(Debug)]
pub struct LdeChunkIter {
    inner: std::vec::IntoIter<LdeChunk>,
}

impl Iterator for LdeChunkIter {
    type Item = LdeChunk;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

fn reverse_bits(value: usize, bits: usize) -> usize {
    if bits == 0 {
        value
    } else {
        value.reverse_bits() >> (usize::BITS as usize - bits)
    }
}

#[cfg(test)]
mod tests {
    use super::{reverse_bits, LdeChunk, LowDegreeExtender, PROFILE_HISEC_X16, PROFILE_X8};
    use crate::fft::ifft::Ifft;
    use crate::fft::{Fft, Radix2Fft};
    use crate::field::prime_field::MontgomeryConvertible;
    use crate::field::FieldElement;

    #[test]
    fn mandated_lde_blowup_lengths() {
        let trace_rows = 4;
        let row_major = LowDegreeExtender::new(trace_rows, 2, &PROFILE_X8);
        assert_eq!(
            row_major.extended_rows(),
            trace_rows * PROFILE_X8.blowup_factor,
            "×8 profile must extend the number of rows by its blowup factor"
        );

        let hisec_rows = 8;
        let hi_sec = LowDegreeExtender::new(hisec_rows, 3, &PROFILE_HISEC_X16);
        assert_eq!(
            hi_sec.extended_rows(),
            hisec_rows * PROFILE_HISEC_X16.blowup_factor,
            "×16 profile must extend the number of rows by its blowup factor"
        );
    }

    #[test]
    fn mandated_lde_deterministic_index_mapping() {
        let extender = LowDegreeExtender::new(8, 2, &PROFILE_X8);
        let total_slots = extender.extended_rows() * extender.trace_columns();
        let mut seen = vec![false; total_slots];
        for natural_row in 0..extender.extended_rows() {
            for column in 0..extender.trace_columns() {
                let index = extender.lde_index(natural_row, column);
                assert!(index < total_slots, "index out of bounds");
                assert!(
                    !seen[index],
                    "row-major mapping must not revisit indices (row {natural_row}, column {column})"
                );
                seen[index] = true;
            }
        }
        assert!(
            seen.into_iter().all(|flag| flag),
            "row-major mapping must cover the domain"
        );

        let hi_sec = LowDegreeExtender::new(4, 3, &PROFILE_HISEC_X16);
        for column in 0..hi_sec.trace_columns() {
            for row in 0..hi_sec.extended_rows() {
                let index = hi_sec.lde_index(row, column);
                let expected = column * hi_sec.extended_rows() + row;
                assert_eq!(
                    index, expected,
                    "column-interleaved mapping must be deterministic"
                );
            }
        }
    }

    #[test]
    fn mandated_lde_worker_chunk_determinism() {
        let trace_rows = 8;
        let trace_columns = 3;
        let extender = LowDegreeExtender::new(trace_rows, trace_columns, &PROFILE_X8);
        let trace: Vec<FieldElement> = (0..trace_rows * trace_columns)
            .map(|i| FieldElement::from((i as u64) + 1).to_montgomery())
            .collect();
        let reference = extender.extend_trace(&trace);

        for worker_count in 1..=4 {
            let mut reconstructed = vec![FieldElement::ZERO; reference.len()];
            let mut visited = vec![false; reference.len()];
            for worker_id in 0..worker_count {
                for chunk in extender.chunk_iter(worker_id, worker_count) {
                    for natural_row in chunk.start_row..chunk.end_row {
                        for column in 0..extender.trace_columns() {
                            let index = extender.lde_index(natural_row, column);
                            assert!(
                                !visited[index],
                                "chunk scheduling must be disjoint across workers"
                            );
                            visited[index] = true;
                            reconstructed[index] = reference[index];
                        }
                    }
                }
            }

            assert!(
                visited.into_iter().all(|flag| flag),
                "chunks must cover the entire domain"
            );
            assert_eq!(
                reconstructed, reference,
                "LDE output must be byte-identical regardless of worker count ({worker_count})"
            );
        }
    }

    #[test]
    fn lde_index_row_major_bit_reversed_mapping() {
        let extender = LowDegreeExtender::new(4, 2, &PROFILE_X8);
        assert_eq!(extender.extended_rows(), 32);
        assert_eq!(extender.lde_index(0, 0), 0);
        assert_eq!(extender.lde_index(0, 1), 1);
        let row_one_index =
            reverse_bits(1, extender.log2_extended_rows()) * extender.trace_columns();
        assert_eq!(extender.lde_index(1, 0), row_one_index);
        assert_eq!(extender.lde_index(1, 1), row_one_index + 1);
        let last_row = extender.extended_rows() - 1;
        let last_index =
            reverse_bits(last_row, extender.log2_extended_rows()) * extender.trace_columns();
        assert_eq!(extender.lde_index(last_row, 0), last_index);
    }

    #[test]
    fn lde_index_column_interleaved_natural_mapping() {
        let extender = LowDegreeExtender::new(8, 3, &PROFILE_HISEC_X16);
        let extended_rows = extender.extended_rows();
        assert_eq!(extender.lde_index(0, 0), 0);
        assert_eq!(extender.lde_index(0, 1), extended_rows);
        assert_eq!(extender.lde_index(1, 0), 1);
        assert_eq!(extender.lde_index(1, 2), 2 * extended_rows + 1);
    }

    #[test]
    fn scatter_respects_evaluation_ordering() {
        let extender = LowDegreeExtender::new(4, 2, &PROFILE_X8);
        let mut evaluations = vec![FieldElement::ZERO; extender.extended_rows()];
        for natural_row in 0..extender.extended_rows() {
            let evaluation_index = reverse_bits(natural_row, extender.log2_extended_rows());
            evaluations[evaluation_index] = FieldElement::from(natural_row as u64);
        }
        let mut output =
            vec![FieldElement::ZERO; extender.extended_rows() * extender.trace_columns()];
        extender.scatter_column(0, &evaluations, &mut output);

        for natural_row in 0..extender.extended_rows() {
            let evaluation_index = reverse_bits(natural_row, extender.log2_extended_rows());
            let expected_index = evaluation_index * extender.trace_columns();
            assert_eq!(
                output[expected_index],
                FieldElement::from(natural_row as u64)
            );
        }
    }

    #[test]
    fn coefficients_are_little_endian() {
        let log2_rows = 2;
        let trace_rows = 1usize << log2_rows;
        let coefficients = vec![
            FieldElement::from(3u64).to_montgomery(),
            FieldElement::from(5u64).to_montgomery(),
            FieldElement::from(7u64).to_montgomery(),
            FieldElement::ZERO,
        ];
        let mut evaluations = coefficients.clone();
        Radix2Fft::natural_order(log2_rows).forward(&mut evaluations);

        let extender = LowDegreeExtender::new(trace_rows, 1, &PROFILE_X8);
        let mut column = vec![FieldElement::ZERO; trace_rows];
        LowDegreeExtender::gather_column(&evaluations, 1, 0, &mut column);
        let mut recovered = column.clone();
        extender.inverse_plan.inverse(&mut recovered);
        assert_eq!(recovered[..coefficients.len()], coefficients[..]);
    }

    #[test]
    fn chunk_iter_domain_major_round_robin() {
        let extender = LowDegreeExtender::new(8, 2, &PROFILE_X8);
        let mut iter = extender.chunk_iter(0, 3);
        let first = iter.next().unwrap();
        assert_eq!(
            first,
            LdeChunk {
                start_row: 0,
                end_row: 8
            }
        );
        let second = iter.next().unwrap();
        assert_eq!(
            second,
            LdeChunk {
                start_row: 24,
                end_row: 32
            }
        );
        let third = iter.next().unwrap();
        assert_eq!(
            third,
            LdeChunk {
                start_row: 48,
                end_row: 56
            }
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn chunk_iter_worker_major_contiguous() {
        let extender = LowDegreeExtender::new(8, 3, &PROFILE_HISEC_X16);
        let mut iter0 = extender.chunk_iter(0, 2);
        assert_eq!(
            iter0.next().unwrap(),
            LdeChunk {
                start_row: 0,
                end_row: extender.params().chunking.chunk_size
            }
        );
        assert!(iter0.next().is_none());

        let mut iter1 = extender.chunk_iter(1, 2);
        assert_eq!(
            iter1.next().unwrap(),
            LdeChunk {
                start_row: extender.params().chunking.chunk_size,
                end_row: extender.extended_rows()
            }
        );
        assert!(iter1.next().is_none());
    }
}
