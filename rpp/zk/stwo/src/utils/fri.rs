use serde::{Deserialize, Serialize};

use crate::params::FieldElement;

use stwo_official::core::fields::m31::BaseField;
use stwo_official::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use stwo_official::core::fri::{
    FriLayerProof as OfficialFriLayerProof, FriProof as OfficialFriProof,
};
use stwo_official::core::poly::line::LinePoly;
use stwo_official::core::queries::Queries as OfficialQueries;
use stwo_official::core::vcs::blake2_hash::{
    Blake2sHash as OfficialBlake2sHash, Blake2sHasher as OfficialBlake2sHasher,
};
use stwo_official::core::vcs::blake2_merkle::Blake2sMerkleHasher;
use stwo_official::core::vcs::verifier::MerkleDecommitment;

/// Wrapper around the official `Queries` structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriQuery {
    pub log_domain_size: u32,
    pub positions: Vec<usize>,
}

impl FriQuery {
    pub fn new(log_domain_size: u32, positions: Vec<usize>) -> Self {
        Self {
            log_domain_size,
            positions,
        }
    }

    pub fn to_official(&self) -> OfficialQueries {
        OfficialQueries {
            positions: self.positions.clone(),
            log_domain_size: self.log_domain_size,
        }
    }

    pub fn from_official(queries: OfficialQueries) -> Self {
        Self {
            log_domain_size: queries.log_domain_size,
            positions: queries.positions,
        }
    }
}

/// Deterministic wrapper that serialises official STWO FRI proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FriProof {
    proof: OfficialFriProof<Blake2sMerkleHasher>,
}

impl PartialEq for FriProof {
    fn eq(&self, other: &Self) -> bool {
        self.bytes() == other.bytes()
    }
}

impl Eq for FriProof {}

impl FriProof {
    /// Create an empty proof wrapper.
    pub fn empty() -> Self {
        Self::from_elements(&[])
    }

    /// Construct a wrapper from an official proof.
    pub fn from_official(proof: &OfficialFriProof<Blake2sMerkleHasher>) -> Self {
        Self {
            proof: proof.clone(),
        }
    }

    /// Deserialize the wrapper back into the official proof object.
    pub fn to_official(&self) -> OfficialFriProof<Blake2sMerkleHasher> {
        self.proof.clone()
    }

    /// Build a deterministic placeholder proof based on the supplied field elements.
    pub fn from_elements(values: &[FieldElement]) -> Self {
        let proof = placeholder_proof(values);
        Self::from_official(&proof)
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.proof).expect("official FRI proof serialises")
    }
}

pub struct FriProver;

impl FriProver {
    pub fn commit(values: &[FieldElement]) -> [u8; 32] {
        digest_elements(values).0
    }

    pub fn prove(values: &[FieldElement]) -> FriProof {
        FriProof::from_elements(values)
    }

    pub fn verify(values: &[FieldElement], proof: &FriProof) -> bool {
        &FriProof::from_elements(values) == proof
    }
}

pub fn compress_proof(proof: &FriProof) -> [u8; 32] {
    let encoded = proof.bytes();
    digest_bytes(&encoded).0
}

fn digest_bytes(data: &[u8]) -> OfficialBlake2sHash {
    OfficialBlake2sHasher::hash(data)
}

fn digest_elements(values: &[FieldElement]) -> OfficialBlake2sHash {
    let mut buffer = Vec::with_capacity(values.len() * 16);
    for value in values {
        buffer.extend_from_slice(&value.to_bytes());
    }
    OfficialBlake2sHasher::hash(&buffer)
}

fn placeholder_proof(values: &[FieldElement]) -> OfficialFriProof<Blake2sMerkleHasher> {
    let first_layer = OfficialFriLayerProof {
        fri_witness: values.iter().map(field_to_secure).collect(),
        decommitment: MerkleDecommitment {
            hash_witness: Vec::new(),
            column_witness: values.iter().map(field_to_base).collect(),
        },
        commitment: digest_elements(values),
    };

    let sum = values
        .iter()
        .copied()
        .fold(FieldElement::zero(), |acc, value| acc + value);
    let tail = SecureField::from(values.len() as u32);
    let last_layer_poly = LinePoly::new(vec![field_to_secure(&sum), tail]);

    OfficialFriProof {
        first_layer,
        inner_layers: Vec::new(),
        last_layer_poly,
    }
}

fn field_to_secure(value: &FieldElement) -> SecureField {
    let mut bytes = [0u8; 16];
    let repr = value.to_bytes();
    let copy_len = repr.len().min(bytes.len());
    let start = bytes.len() - copy_len;
    bytes[start..].copy_from_slice(&repr[repr.len() - copy_len..]);

    let mut limbs = [BaseField::from(0u32); SECURE_EXTENSION_DEGREE];
    for (idx, chunk) in bytes.chunks(4).take(SECURE_EXTENSION_DEGREE).enumerate() {
        limbs[idx] = BaseField::from(u32::from_be_bytes(chunk.try_into().unwrap()));
    }
    SecureField::from_m31_array(limbs)
}

fn field_to_base(value: &FieldElement) -> BaseField {
    let bytes = value.to_bytes();
    let last = bytes
        .iter()
        .rev()
        .take(4)
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    let mut padded = [0u8; 4];
    let offset = 4 - last.len();
    padded[offset..].copy_from_slice(&last);
    BaseField::from(u32::from_be_bytes(padded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_depends_on_values() {
        let values = vec![FieldElement::one(), FieldElement::from(7u128)];
        let different = vec![FieldElement::one(), FieldElement::from(11u128)];
        assert_ne!(FriProver::prove(&values), FriProver::prove(&different));
    }

    #[test]
    fn official_proof_roundtrip() {
        let values = vec![FieldElement::from(3u128), FieldElement::from(17u128)];
        let official = placeholder_proof(&values);

        let wrapped = FriProof::from_official(&official);
        let json = serde_json::to_string(&wrapped).unwrap();
        let decoded: FriProof = serde_json::from_str(&json).unwrap();
        assert_eq!(wrapped, decoded);

        let recovered = decoded.to_official();
        let recovered_bytes = serde_json::to_vec(&recovered).unwrap();
        let official_bytes = serde_json::to_vec(&official).unwrap();
        assert_eq!(recovered_bytes, official_bytes);
        assert!(FriProver::verify(&values, &decoded));
    }
}
