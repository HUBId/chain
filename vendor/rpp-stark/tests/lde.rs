use rpp_stark::fft::lde::{LdeChunk, LowDegreeExtender, PROFILE_HISEC_X16, PROFILE_X8};
use rpp_stark::field::FieldElement;

fn deterministic_trace(rows: usize, cols: usize) -> Vec<FieldElement> {
    let mut state = 0xd1b54a32d192ed03u64;
    let mut trace = Vec::with_capacity(rows * cols);
    for _ in 0..rows * cols {
        state = state
            .wrapping_mul(0x94d049bb133111eb)
            .wrapping_add(0xda942042e4dd58b5);
        trace.push(to_montgomery(FieldElement::from(state)));
    }
    trace
}

fn bit_reverse(value: usize, bits: usize) -> usize {
    if bits == 0 {
        value
    } else {
        value.reverse_bits() >> (usize::BITS as usize - bits)
    }
}

fn to_montgomery(value: FieldElement) -> FieldElement {
    let modulus = FieldElement::MODULUS.value as u128;
    let r = FieldElement::R as u128;
    let product = (value.0 as u128 * r) % modulus;
    FieldElement::from(product as u64)
}

#[test]
fn x8_extender_shape_and_ordering() {
    let trace_rows = 4;
    let trace_cols = 3;
    let trace = deterministic_trace(trace_rows, trace_cols);

    let extender = LowDegreeExtender::new(trace_rows, trace_cols, &PROFILE_X8);
    let extended = extender.extend_trace(&trace);

    assert_eq!(extended.len(), extender.extended_rows() * trace_cols);

    for natural_row in 0..extender.extended_rows() {
        let expected_bucket = bit_reverse(natural_row, extender.log2_extended_rows());
        for column in 0..trace_cols {
            let index = extender.lde_index(natural_row, column);
            assert_eq!(index / trace_cols, expected_bucket);
        }
    }
}

#[test]
fn x16_extender_shape_and_ordering() {
    let trace_rows = 2;
    let trace_cols = 2;
    let trace = deterministic_trace(trace_rows, trace_cols);

    let extender = LowDegreeExtender::new(trace_rows, trace_cols, &PROFILE_HISEC_X16);
    let extended = extender.extend_trace(&trace);

    assert_eq!(extended.len(), extender.extended_rows() * trace_cols);

    for natural_row in 0..extender.extended_rows() {
        for column in 0..trace_cols {
            let index = extender.lde_index(natural_row, column);
            assert_eq!(index, column * extender.extended_rows() + natural_row);
        }
    }
}

fn verify_chunk_invariance(extender: &LowDegreeExtender, baseline: &[FieldElement]) {
    let rows = extender.extended_rows();
    let cols = extender.trace_columns();
    let baseline_chunks: Vec<LdeChunk> = extender.chunk_iter(0, 1).collect();

    for workers in 1..=4 {
        let mut assembled = vec![FieldElement::ZERO; baseline.len()];
        let mut covered_rows = vec![false; rows];
        let mut combined: Vec<LdeChunk> = Vec::new();

        for worker_id in 0..workers {
            for chunk in extender.chunk_iter(worker_id, workers) {
                combined.push(chunk);
                for natural_row in chunk.start_row..chunk.end_row {
                    covered_rows[natural_row] = true;
                    for column in 0..cols {
                        let index = extender.lde_index(natural_row, column);
                        assembled[index] = baseline[index];
                    }
                }
            }
        }

        combined.sort_by_key(|chunk| chunk.start_row);
        assert_eq!(combined, baseline_chunks);
        assert!(covered_rows.into_iter().all(|covered| covered));
        assert_eq!(assembled, baseline);
    }
}

#[test]
fn deterministic_chunking_is_worker_invariant() {
    let trace_rows = 4;
    let trace_cols = 2;
    let trace = deterministic_trace(trace_rows, trace_cols);

    let extender_x8 = LowDegreeExtender::new(trace_rows, trace_cols, &PROFILE_X8);
    let baseline_x8 = extender_x8.extend_trace(&trace);
    verify_chunk_invariance(&extender_x8, &baseline_x8);

    let extender_x16 = LowDegreeExtender::new(trace_rows, trace_cols, &PROFILE_HISEC_X16);
    let baseline_x16 = extender_x16.extend_trace(&trace);
    verify_chunk_invariance(&extender_x16, &baseline_x16);
}
