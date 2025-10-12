use rpp_stark::fft::ifft::{Ifft, Radix2InverseFft};
use rpp_stark::fft::{Fft, Radix2Fft, Radix2Ordering};
use rpp_stark::field::FieldElement;
use rpp_stark::hash::Hasher;

fn deterministic_field_vector(len: usize) -> Vec<FieldElement> {
    let mut state = 0x9e3779b97f4a7c15u64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(0x5851f42d4c957f2d)
                .wrapping_add(0x14057b7ef767814f);
            FieldElement::from(state)
        })
        .collect()
}

fn to_montgomery(value: FieldElement) -> FieldElement {
    let modulus = FieldElement::MODULUS.value as u128;
    let r = FieldElement::R as u128;
    let product = (value.0 as u128 * r) % modulus;
    FieldElement::from(product as u64)
}

fn digest_table(entries: &[FieldElement]) -> String {
    let mut hasher = Hasher::new();
    for value in entries.iter() {
        hasher.update(&value.0.to_le_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

#[test]
fn radix2_fft_roundtrip_preserves_inputs() {
    let log2_size = 6;
    let size = 1usize << log2_size;

    let canonical = deterministic_field_vector(size);
    let mut montgomery: Vec<FieldElement> = canonical.iter().copied().map(to_montgomery).collect();
    let original = montgomery.clone();

    let forward = Radix2Fft::new(log2_size, Radix2Ordering::Natural);
    forward.forward(&mut montgomery);

    let inverse = Radix2InverseFft::new(log2_size, Radix2Ordering::Natural);
    inverse.inverse(&mut montgomery);

    assert_eq!(
        montgomery, original,
        "IFFT(FFT(v)) must recover the input vector"
    );
}

#[test]
fn radix2_twiddle_tables_digest_is_stable() {
    let log2_size = 8;
    let plan = Radix2Fft::natural_order(log2_size);
    let forward_digest = digest_table(plan.domain().generators.forward);
    let inverse_digest = digest_table(plan.domain().generators.inverse);

    // Audited digests for the Montgomery-encoded radix-2 roots of unity.
    // Update only if the deterministic seed or root derivation changes.
    assert_eq!(
        forward_digest,
        "18c042fc9243ad5f2dcacab733578b9962c1b5208a53e4b15e3cb0eb1381ba34"
    );
    assert_eq!(
        inverse_digest,
        "7e4c94519cc7de920f6ca19b46b38060b906e7056febe650c3c58a471fcc5b8d"
    );
}
