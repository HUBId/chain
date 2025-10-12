use crate::hash::{deterministic::DeterministicHashError, hash, Hash, Hasher, OutputReader};

use super::{VrfVerificationFailure, OUTPUT_XOF_PREFIX};

/// Prime modulus used by the Goldilocks field.
pub const GOLDILOCKS_MODULUS: u64 = 0xffffffff00000001;

/// Prefix used when deriving the negacyclic NTT root.
const ROOT_SELECTION_PREFIX: &str = "RPP-RLWE-NTT-ROOT";

/// Version tag used for deterministic root selection.
const ROOT_SELECTION_VERSION: &str = "V1";

/// Salt used when deriving the public `a(x)` polynomial from the VRF input.
const AX_SALT: &str = "RPP-VRF-A(x)";

/// Human readable description of the ω selection rule used when hashing parameters.
const OMEGA_SELECTION_RULE: &str = "omega=first_order_2n";

/// Serialization rule descriptor used in the RLWE parameter digest.
const SERIALIZATION_RULE: &str = "serialization=coefficients_le";

/// Mapping descriptor used in the VRF parameter digest.
const OUTPUT_MAPPING_RULE: &str = "output-mapping=blake3-xof-rejection-32";

/// Public key commitment rule descriptor used in the VRF parameter digest.
const PK_COMMIT_RULE: &str = "pk-commit=blake3(encode(sk))";

/// RLWE secret key represented in coefficient form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey {
    coeffs: Vec<u64>,
}

impl SecretKey {
    /// Constructs a secret key from canonical coefficients modulo the field modulus.
    pub fn from_coefficients(coeffs: Vec<u64>) -> Result<Self, VrfVerificationFailure> {
        if coeffs.iter().any(|&c| c >= GOLDILOCKS_MODULUS) {
            return Err(VrfVerificationFailure::ErrVrfParamMismatch);
        }
        Ok(Self { coeffs })
    }

    /// Returns a shared reference to the coefficient vector.
    pub fn coefficients(&self) -> &[u64] {
        &self.coeffs
    }

    /// Returns the canonical serialization of the secret key (little-endian coefficients).
    pub fn serialize(&self) -> Vec<u8> {
        serialize_polynomial(&self.coeffs)
    }
}

/// Deterministic RLWE parameter set used by the VRF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlweParameters {
    /// Degree of the polynomial ring (`n`).
    pub degree: usize,
    /// 2n-th primitive root of unity (ω).
    pub omega: u64,
    /// ω^2, the principal n-th root of unity used by the NTT.
    omega_sq: u64,
    /// Precomputed powers of ω used to enter the negacyclic NTT domain.
    psi_powers: Vec<u64>,
    /// Precomputed inverse powers of ω used to exit the NTT domain.
    psi_inv_powers: Vec<u64>,
    /// Twiddle factors for the forward NTT.
    twiddles: Vec<u64>,
    /// Twiddle factors for the inverse NTT.
    inv_twiddles: Vec<u64>,
    /// Multiplicative inverse of n modulo the field modulus.
    inv_degree: u64,
}

impl RlweParameters {
    /// Creates a new parameter set for the provided degree.
    pub fn new(degree: usize) -> Result<Self, VrfVerificationFailure> {
        if !degree.is_power_of_two() {
            return Err(VrfVerificationFailure::ErrVrfParamMismatch);
        }
        if degree < 2 {
            return Err(VrfVerificationFailure::ErrVrfParamMismatch);
        }
        let omega = select_primitive_root(degree as u32)?;
        let omega_sq = mod_mul(omega, omega);
        let psi_powers = compute_psi_powers(omega, degree);
        let psi_inv_powers = compute_psi_inv_powers(omega, degree);
        let twiddles = compute_twiddles(omega_sq, degree);
        let inv_twiddles = compute_twiddles(mod_inv(omega_sq), degree);
        let inv_degree = mod_inv(degree as u64 % GOLDILOCKS_MODULUS);

        Ok(Self {
            degree,
            omega,
            omega_sq,
            psi_powers,
            psi_inv_powers,
            twiddles,
            inv_twiddles,
            inv_degree,
        })
    }

    /// Returns the modulus associated with this parameter set.
    pub const fn modulus(&self) -> u64 {
        GOLDILOCKS_MODULUS
    }

    /// Performs a forward negacyclic NTT in-place.
    pub fn forward_ntt(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.degree);
        for (i, value) in values.iter_mut().enumerate() {
            *value = mod_mul(*value, self.psi_powers[i]);
        }
        cooley_tukey_ntt(values, &self.twiddles);
    }

    /// Performs an inverse negacyclic NTT in-place.
    pub fn inverse_ntt(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.degree);
        cooley_tukey_ntt(values, &self.inv_twiddles);
        for value in values.iter_mut() {
            *value = mod_mul(*value, self.inv_degree);
        }
        for (i, value) in values.iter_mut().enumerate() {
            *value = mod_mul(*value, self.psi_inv_powers[i]);
        }
    }
}

/// Computes the RLWE parameter identifier as specified in the documentation.
pub fn compute_rlwe_param_id(params: &RlweParameters) -> super::RlweParamId {
    let mut hasher = Hasher::new();
    hasher.update(&GOLDILOCKS_MODULUS.to_le_bytes());
    hasher.update(&(params.degree as u32).to_le_bytes());
    hasher.update(ROOT_SELECTION_PREFIX.as_bytes());
    hasher.update(&(params.degree as u32).to_le_bytes());
    hasher.update(ROOT_SELECTION_VERSION.as_bytes());
    hasher.update(OMEGA_SELECTION_RULE.as_bytes());
    hasher.update(SERIALIZATION_RULE.as_bytes());
    super::RlweParamId::from_hash(hasher.finalize())
}

/// Computes the VRF parameter identifier building on top of the RLWE digest.
pub fn compute_vrf_param_id(params: &RlweParameters) -> super::VrfParamId {
    let rlwe_id = compute_rlwe_param_id(params);
    let mut hasher = Hasher::new();
    hasher.update(rlwe_id.as_bytes());
    hasher.update(OUTPUT_MAPPING_RULE.as_bytes());
    hasher.update(PK_COMMIT_RULE.as_bytes());
    super::VrfParamId::from_hash(hasher.finalize())
}

/// Derives the deterministic public polynomial `a(x)` from the VRF input bytes.
pub fn derive_public_polynomial(
    params: &RlweParameters,
    input: &[u8],
) -> Result<Vec<u64>, VrfVerificationFailure> {
    let mut hasher = Hasher::new();
    hasher.update(AX_SALT.as_bytes());
    hasher.update(&(params.degree as u32).to_le_bytes());
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut coefficients = vec![0u64; params.degree];
    for coeff in &mut coefficients {
        let mut buf = [0u8; 8];
        reader
            .fill(&mut buf)
            .map_err(VrfVerificationFailure::from)?;
        *coeff = u64::from_le_bytes(buf) % GOLDILOCKS_MODULUS;
    }
    Ok(coefficients)
}

/// Evaluates the RLWE-based PRF `y = a(x) ⋆ s mod (X^n + 1, p)`.
pub fn evaluate_prf(
    params: &RlweParameters,
    input: &[u8],
    secret_key: &SecretKey,
) -> Result<Vec<u64>, VrfVerificationFailure> {
    assert_eq!(secret_key.coefficients().len(), params.degree);

    let mut a_poly = derive_public_polynomial(params, input)?;
    let mut s_poly = secret_key.coefficients().to_vec();
    params.forward_ntt(&mut a_poly);
    params.forward_ntt(&mut s_poly);
    let mut product = vec![0u64; params.degree];
    for i in 0..params.degree {
        product[i] = mod_mul(a_poly[i], s_poly[i]);
    }
    params.inverse_ntt(&mut product);
    Ok(product)
}

/// Computes the canonical serialization of a polynomial (little-endian coefficients).
pub fn serialize_polynomial(coeffs: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(coeffs.len() * 8);
    for &coeff in coeffs {
        let canonical = coeff % GOLDILOCKS_MODULUS;
        bytes.extend_from_slice(&canonical.to_le_bytes());
    }
    bytes
}

/// Deserializes a polynomial in canonical coefficient form.
pub fn deserialize_polynomial(
    bytes: &[u8],
    degree: usize,
) -> Result<Vec<u64>, VrfVerificationFailure> {
    if bytes.len() != degree * 8 {
        return Err(VrfVerificationFailure::ErrVrfProofInvalid);
    }
    let mut coeffs = Vec::with_capacity(degree);
    for chunk in bytes.chunks_exact(8) {
        let value = u64::from_le_bytes(chunk.try_into().expect("chunk length"));
        if value >= GOLDILOCKS_MODULUS {
            return Err(VrfVerificationFailure::ErrVrfProofInvalid);
        }
        coeffs.push(value);
    }
    Ok(coeffs)
}

/// Computes the VRF public key commitment `pk = BLAKE3(encode(s))`.
pub fn derive_public_key(secret_key: &SecretKey) -> Hash {
    hash(&secret_key.serialize())
}

/// Normalizes the RLWE output coefficients into a 32-byte VRF output.
pub fn normalize_output(coeffs: &[u64]) -> Result<[u8; 32], VrfVerificationFailure> {
    let serialized = serialize_polynomial(coeffs);
    let mut hasher = Hasher::new();
    hasher.update(OUTPUT_XOF_PREFIX.as_bytes());
    hasher.update(&(coeffs.len() as u32).to_le_bytes());
    hasher.update(&serialized);
    let mut reader = hasher.finalize_xof();
    rejection_sample_32(&mut reader).map_err(VrfVerificationFailure::from)
}

fn rejection_sample_32(reader: &mut OutputReader) -> Result<[u8; 32], DeterministicHashError> {
    // Target space is 2^256; every 32-byte value is currently accepted. The helper
    // retains the structure described in the specification but avoids the degenerate
    // loop that never iterated.
    let mut candidate = [0u8; 32];
    reader.fill(&mut candidate)?;
    Ok(candidate)
}

fn select_primitive_root(degree: u32) -> Result<u64, VrfVerificationFailure> {
    let mut seed_hasher = Hasher::new();
    seed_hasher.update(ROOT_SELECTION_PREFIX.as_bytes());
    seed_hasher.update(&degree.to_le_bytes());
    seed_hasher.update(ROOT_SELECTION_VERSION.as_bytes());
    let seed = seed_hasher.finalize();

    let mut xof = Hasher::new();
    xof.update(seed.as_bytes());
    let mut reader = xof.finalize_xof();

    let subgroup_exponent = (GOLDILOCKS_MODULUS - 1) / (2 * degree as u64);

    loop {
        let mut buf = [0u8; 8];
        reader
            .fill(&mut buf)
            .map_err(VrfVerificationFailure::from)?;
        let raw = u64::from_le_bytes(buf) % GOLDILOCKS_MODULUS;
        if raw == 0 {
            continue;
        }
        let candidate = mod_pow(raw, subgroup_exponent);
        if candidate == 0 {
            continue;
        }
        if mod_pow(candidate, degree as u64) != GOLDILOCKS_MODULUS - 1 {
            continue;
        }
        if mod_pow(candidate, (degree / 2) as u64) == GOLDILOCKS_MODULUS - 1 {
            continue;
        }
        return Ok(candidate);
    }
}

fn compute_psi_powers(omega: u64, degree: usize) -> Vec<u64> {
    let mut powers = vec![0u64; degree];
    powers[0] = 1;
    for i in 1..degree {
        powers[i] = mod_mul(powers[i - 1], omega);
    }
    powers
}

fn compute_psi_inv_powers(omega: u64, degree: usize) -> Vec<u64> {
    let omega_inv = mod_inv(omega);
    let mut powers = vec![0u64; degree];
    powers[0] = 1;
    for i in 1..degree {
        powers[i] = mod_mul(powers[i - 1], omega_inv);
    }
    powers
}

fn compute_twiddles(root: u64, degree: usize) -> Vec<u64> {
    let mut powers = vec![0u64; degree];
    powers[0] = 1;
    for i in 1..degree {
        powers[i] = mod_mul(powers[i - 1], root);
    }
    powers
}

fn cooley_tukey_ntt(values: &mut [u64], twiddles: &[u64]) {
    let n = values.len();
    debug_assert!(n.is_power_of_two());
    let log_n = n.trailing_zeros();
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            values.swap(i, j);
        }
    }

    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let step = n / len;
        for start in (0..n).step_by(len) {
            for j in 0..half {
                let idx = j * step;
                let twiddle = twiddles[idx];
                let u = values[start + j];
                let v = mod_mul(values[start + j + half], twiddle);
                values[start + j] = mod_add(u, v);
                values[start + j + half] = mod_sub(u, v);
            }
        }
        len <<= 1;
    }
}

fn bit_reverse(mut value: usize, bits: u32) -> usize {
    let mut reversed = 0usize;
    for _ in 0..bits {
        reversed = (reversed << 1) | (value & 1);
        value >>= 1;
    }
    reversed
}

#[inline(always)]
fn mod_add(a: u64, b: u64) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    if carry || sum >= GOLDILOCKS_MODULUS {
        sum.wrapping_sub(GOLDILOCKS_MODULUS)
    } else {
        sum
    }
}

#[inline(always)]
fn mod_sub(a: u64, b: u64) -> u64 {
    let modulus = GOLDILOCKS_MODULUS;
    if a >= b {
        a - b
    } else {
        modulus - (b - a)
    }
}

#[inline(always)]
fn mod_mul(a: u64, b: u64) -> u64 {
    let product = (a as u128 * b as u128) % GOLDILOCKS_MODULUS as u128;
    product as u64
}

fn mod_pow(mut base: u64, mut exponent: u64) -> u64 {
    let modulus = GOLDILOCKS_MODULUS;
    let mut result = 1u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mod_mul(result, base);
        }
        base = mod_mul(base, base);
        exponent >>= 1;
    }
    result % modulus
}

fn mod_inv(value: u64) -> u64 {
    mod_pow(value, GOLDILOCKS_MODULUS - 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret(params: &RlweParameters) -> SecretKey {
        let coeffs = (0..params.degree)
            .map(|i| (i as u64 * 17) % GOLDILOCKS_MODULUS)
            .collect::<Vec<_>>();
        SecretKey::from_coefficients(coeffs).expect("valid secret")
    }

    #[test]
    fn ntt_root_selection_deterministic_ok() {
        let params_a = RlweParameters::new(1024).expect("params");
        let params_b = RlweParameters::new(1024).expect("params");
        assert_eq!(params_a.omega, params_b.omega);

        let params_c = RlweParameters::new(2048).expect("params");
        assert_ne!(params_a.omega, params_c.omega);
    }

    #[test]
    fn prf_evaluation_deterministic_ok() {
        let params = RlweParameters::new(256).expect("params");
        let secret = sample_secret(&params);
        let input = b"deterministic-input";

        let y1 = evaluate_prf(&params, input, &secret).expect("prf evaluation");
        let y2 = evaluate_prf(&params, input, &secret).expect("prf evaluation");
        assert_eq!(y1, y2);

        let output1 = normalize_output(&y1).expect("normalize output");
        let output2 = normalize_output(&y2).expect("normalize output");
        assert_eq!(output1, output2);
    }

    #[test]
    fn normalize_output_bias_window_ok() {
        let params = RlweParameters::new(64).expect("params");
        let secret = sample_secret(&params);
        let mut histogram = [0usize; 256];

        for i in 0..8 {
            let input = format!("input-{i}");
            let y = evaluate_prf(&params, input.as_bytes(), &secret).expect("prf");
            let output = normalize_output(&y).expect("normalize");
            histogram[output[0] as usize] += 1;
        }

        let non_zero = histogram.iter().filter(|&&c| c > 0).count();
        assert!(non_zero > 2, "insufficient diversity: {non_zero}");
        let max = histogram.iter().max().copied().unwrap_or(0);
        assert!(max < 4, "outlier bucket detected: max={max}");
    }

    #[test]
    fn parameter_digests_change_with_degree_ok() {
        let params_std = RlweParameters::new(1024).expect("params");
        let params_hi = RlweParameters::new(2048).expect("params");

        let rlwe_std = compute_rlwe_param_id(&params_std);
        let rlwe_hi = compute_rlwe_param_id(&params_hi);
        assert_ne!(rlwe_std, rlwe_hi);

        let vrf_std = compute_vrf_param_id(&params_std);
        let vrf_hi = compute_vrf_param_id(&params_hi);
        assert_ne!(vrf_std, vrf_hi);
    }

    #[test]
    fn polynomial_serialization_roundtrip_ok() {
        let params = RlweParameters::new(1024).expect("params");
        let secret = sample_secret(&params);
        let serialized = serialize_polynomial(secret.coefficients());
        let deserialized = deserialize_polynomial(&serialized, params.degree).expect("roundtrip");
        assert_eq!(secret.coefficients(), deserialized.as_slice());
    }

    #[test]
    fn transcript_edge_cases_distinguish_inputs_ok() {
        let params = RlweParameters::new(32).expect("params");
        let secret = sample_secret(&params);

        let empty_poly = derive_public_polynomial(&params, b"").expect("empty poly");
        let zero_poly = derive_public_polynomial(&params, &[0]).expect("zero poly");
        assert_ne!(
            empty_poly, zero_poly,
            "transcript salt failed to separate inputs"
        );

        let y_empty = evaluate_prf(&params, b"", &secret).expect("empty prf");
        let y_zero = evaluate_prf(&params, &[0], &secret).expect("zero prf");
        assert_ne!(
            y_empty, y_zero,
            "PRF outputs must reflect transcript distinctions"
        );
    }
}
