use super::prime_field::{
    CanonicalSerialize, FieldDeserializeError, FieldElement, FieldElementOps,
};

#[test]
fn add_mul_inv_laws_ok() {
    let a = FieldElement::from(5u64);
    let b = FieldElement::from(7u64);

    let sum = a.add(&b);
    assert_eq!(sum, FieldElement::from(12u64));

    let neg_a = a.neg();
    assert_eq!(a.add(&neg_a), FieldElement::ZERO);

    let product = a.mul(&b);
    assert_eq!(product, FieldElement::from(35u64));

    let inv_b = b.inv().expect("inverse exists for non-zero element");
    let product = b.mul(&inv_b);
    assert_eq!(product, FieldElement::ONE);
}

#[test]
fn serde_le_roundtrip_ok() {
    let element = FieldElement::from(42u64);
    let bytes = element
        .to_bytes()
        .expect("canonical element should serialize");
    let decoded = FieldElement::from_bytes(&bytes).expect("canonical roundtrip");
    assert_eq!(decoded, element);
}

#[test]
fn reject_noncanonical_bytes_err() {
    let noncanonical = FieldElement::MODULUS.value.to_le_bytes();
    let err = FieldElement::from_bytes(&noncanonical)
        .expect_err("non-canonical representation should be rejected");
    assert_eq!(err, FieldDeserializeError::FieldDeserializeNonCanonical);
    assert_eq!(
        err.to_string(),
        "field element deserialization failed: non-canonical input"
    );
}

#[test]
fn pow_fermat_inverse_ok() {
    let element = FieldElement::from(19u64);
    let fermat_inverse = element.pow(FieldElement::MODULUS.value - 2);
    let inv = element.inv().expect("inverse exists for non-zero element");
    assert_eq!(fermat_inverse, inv);
    assert_eq!(element.mul(&fermat_inverse), FieldElement::ONE);
}
