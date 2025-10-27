//! Pruning proof STARK constraints blueprint implementation.

use std::collections::HashSet;

use crate::official::air::{
    AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain,
};
use crate::official::params::{FieldElement, PoseidonHasher, StarkParameters};
use crate::state::merkle::compute_merkle_root;

use super::{string_to_field, CircuitError, ExecutionTrace, StarkCircuit, TraceSegment};

use rpp_pruning::{DIGEST_LENGTH, DOMAIN_TAG_LENGTH};

/// Witness for the pruning circuit describing the set of removed transactions.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PruningWitness {
    pub previous_tx_root: String,
    pub pruned_tx_root: String,
    pub original_transactions: Vec<String>,
    pub removed_transactions: Vec<String>,
    #[serde(default, with = "serde_prefixed_digest")]
    pub pruning_binding_digest: PrefixedDigest,
    #[serde(default, with = "serde_prefixed_digest_vec")]
    pub pruning_segment_commitments: Vec<PrefixedDigest>,
    pub pruning_fold: String,
}

#[derive(Debug)]
pub struct PruningCircuit {
    pub witness: PruningWitness,
}

impl PruningCircuit {
    pub fn new(witness: PruningWitness) -> Self {
        Self { witness }
    }

    fn decode_hash(hex: &str) -> Result<[u8; 32], CircuitError> {
        let bytes = hex::decode(hex)
            .map_err(|_| CircuitError::ConstraintViolation("invalid hex encoding".into()))?;
        if bytes.len() != 32 {
            return Err(CircuitError::ConstraintViolation(
                "transaction hash must be 32 bytes".into(),
            ));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }

    fn compute_root(hashes: &[String]) -> Result<String, CircuitError> {
        let mut leaves = hashes
            .iter()
            .map(|hash| Self::decode_hash(hash))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(hex::encode(compute_merkle_root(&mut leaves)))
    }

    fn verify_membership(&self) -> Result<(), CircuitError> {
        let root = Self::compute_root(&self.witness.original_transactions)?;
        if root != self.witness.previous_tx_root {
            return Err(CircuitError::ConstraintViolation(
                "original transaction set does not match previous root".into(),
            ));
        }
        Ok(())
    }

    fn verify_pruned_root(&self) -> Result<(), CircuitError> {
        let removed: HashSet<_> = self.witness.removed_transactions.iter().cloned().collect();
        let mut remaining = Vec::new();
        for hash in &self.witness.original_transactions {
            if !removed.contains(hash) {
                remaining.push(hash.clone());
            }
        }
        for hash in &self.witness.removed_transactions {
            if !self.witness.original_transactions.contains(hash) {
                return Err(CircuitError::ConstraintViolation(
                    "pruning removed transaction not present in original set".into(),
                ));
            }
        }
        let pruned_root = Self::compute_root(&remaining)?;
        if pruned_root != self.witness.pruned_tx_root {
            return Err(CircuitError::ConstraintViolation(
                "pruned transaction root mismatch".into(),
            ));
        }
        Ok(())
    }

    fn prefixed_digest_to_field(
        params: &StarkParameters,
        digest: &[u8],
    ) -> Result<FieldElement, CircuitError> {
        let expected = DOMAIN_TAG_LENGTH + DIGEST_LENGTH;
        if digest.len() != expected {
            return Err(CircuitError::InvalidWitness(format!(
                "invalid prefixed digest length: expected {expected} bytes, found {}",
                digest.len()
            )));
        }
        Ok(params.element_from_bytes(digest))
    }

    fn fold_pruning_digests(
        hasher: &PoseidonHasher,
        params: &StarkParameters,
        binding_digest: &PrefixedDigest,
        segment_commitments: &[PrefixedDigest],
    ) -> Result<FieldElement, CircuitError> {
        let zero = FieldElement::zero(params.modulus());
        let mut accumulator = zero.clone();
        let binding_element = Self::prefixed_digest_to_field(params, binding_digest)?;
        accumulator = hasher.hash(&[accumulator.clone(), binding_element, zero.clone()]);
        for digest in segment_commitments {
            let element = Self::prefixed_digest_to_field(params, digest)?;
            accumulator = hasher.hash(&[accumulator.clone(), element, zero.clone()]);
        }
        Ok(accumulator)
    }
}

impl StarkCircuit for PruningCircuit {
    fn name(&self) -> &'static str {
        "pruning"
    }

    fn evaluate_constraints(&self) -> Result<(), CircuitError> {
        self.verify_membership()?;
        self.verify_pruned_root()?;
        let params = StarkParameters::blueprint_default();
        let hasher = params.poseidon_hasher();
        let accumulator = Self::fold_pruning_digests(
            &hasher,
            &params,
            &self.witness.pruning_binding_digest,
            &self.witness.pruning_segment_commitments,
        )?;
        let expected = string_to_field(&params, &self.witness.pruning_fold);
        if accumulator != expected {
            return Err(CircuitError::ConstraintViolation(
                "pruning fold accumulator mismatch".into(),
            ));
        }
        Ok(())
    }

    fn generate_trace(&self, parameters: &StarkParameters) -> Result<ExecutionTrace, CircuitError> {
        let removed: HashSet<_> = self.witness.removed_transactions.iter().cloned().collect();
        let mut remaining = Vec::new();
        let mut original_rows = Vec::new();
        for hash in &self.witness.original_transactions {
            let is_removed = removed.contains(hash);
            if !is_removed {
                remaining.push(hash.clone());
            }
            let row = vec![
                string_to_field(parameters, hash),
                parameters.element_from_u64(if is_removed { 1 } else { 0 }),
            ];
            original_rows.push(row);
        }

        for hash in &self.witness.removed_transactions {
            if !self.witness.original_transactions.contains(hash) {
                return Err(CircuitError::ConstraintViolation(
                    "pruning removed transaction not present in original set".into(),
                ));
            }
        }

        let membership_segment = TraceSegment::new(
            "membership",
            vec!["tx_hash".to_string(), "removed_flag".to_string()],
            original_rows,
        )?;

        let previous_root_computed = Self::compute_root(&self.witness.original_transactions)?;
        let pruned_root_computed = Self::compute_root(&remaining)?;
        let hasher = parameters.poseidon_hasher();
        let zero = FieldElement::zero(parameters.modulus());
        let mut pruning_rows = Vec::new();
        let mut pruning_accumulator = zero.clone();
        let binding_element =
            Self::prefixed_digest_to_field(parameters, &self.witness.pruning_binding_digest)?;
        let mut next = hasher.hash(&[
            pruning_accumulator.clone(),
            binding_element.clone(),
            zero.clone(),
        ]);
        pruning_rows.push(vec![
            pruning_accumulator.clone(),
            binding_element,
            next.clone(),
        ]);
        pruning_accumulator = next;
        for digest in &self.witness.pruning_segment_commitments {
            let element = Self::prefixed_digest_to_field(parameters, digest)?;
            next = hasher.hash(&[pruning_accumulator.clone(), element.clone(), zero.clone()]);
            pruning_rows.push(vec![pruning_accumulator.clone(), element, next.clone()]);
            pruning_accumulator = next;
        }
        let pruning_fold_witness = string_to_field(parameters, &self.witness.pruning_fold);
        let pruning_fold_segment = TraceSegment::new(
            "pruning_fold",
            vec![
                "accumulator_in".to_string(),
                "commitment".to_string(),
                "accumulator_out".to_string(),
            ],
            pruning_rows,
        )?;

        let summary_row = vec![
            string_to_field(parameters, &self.witness.previous_tx_root),
            string_to_field(parameters, &previous_root_computed),
            string_to_field(parameters, &self.witness.pruned_tx_root),
            string_to_field(parameters, &pruned_root_computed),
            parameters.element_from_u64(self.witness.removed_transactions.len() as u64),
            pruning_fold_witness.clone(),
            pruning_accumulator.clone(),
        ];
        let summary_segment = TraceSegment::new(
            "roots",
            vec![
                "previous_root_witness".to_string(),
                "previous_root_computed".to_string(),
                "pruned_root_witness".to_string(),
                "pruned_root_computed".to_string(),
                "removed_count".to_string(),
                "pruning_fold_witness".to_string(),
                "pruning_fold_computed".to_string(),
            ],
            vec![summary_row],
        )?;

        ExecutionTrace::from_segments(vec![
            membership_segment,
            pruning_fold_segment,
            summary_segment,
        ])
    }

    fn define_air(
        &self,
        parameters: &StarkParameters,
        _trace: &ExecutionTrace,
    ) -> Result<AirDefinition, CircuitError> {
        let membership_segment = "membership";
        let removed_flag = AirColumn::new(membership_segment, "removed_flag");

        let roots_segment = "roots";
        let previous_root_witness = AirColumn::new(roots_segment, "previous_root_witness");
        let previous_root_computed = AirColumn::new(roots_segment, "previous_root_computed");
        let pruned_root_witness = AirColumn::new(roots_segment, "pruned_root_witness");
        let pruned_root_computed = AirColumn::new(roots_segment, "pruned_root_computed");
        let removed_count = AirColumn::new(roots_segment, "removed_count");
        let pruning_fold_witness = AirColumn::new(roots_segment, "pruning_fold_witness");
        let pruning_fold_computed = AirColumn::new(roots_segment, "pruning_fold_computed");

        let fold_segment = "pruning_fold";
        let accumulator_in = AirColumn::new(fold_segment, "accumulator_in");
        let commitment = AirColumn::new(fold_segment, "commitment");
        let accumulator_out = AirColumn::new(fold_segment, "accumulator_out");

        let one = parameters.element_from_u64(1);
        let removed_len =
            parameters.element_from_u64(self.witness.removed_transactions.len() as u64);
        let binding_element =
            Self::prefixed_digest_to_field(parameters, &self.witness.pruning_binding_digest)?;
        let pruning_fold = string_to_field(parameters, &self.witness.pruning_fold);

        let constraints = vec![
            AirConstraint::new(
                "membership_flag_boolean",
                membership_segment,
                ConstraintDomain::AllRows,
                AirExpression::product(vec![
                    removed_flag.expr(),
                    AirExpression::difference(
                        removed_flag.expr(),
                        AirExpression::constant(one.clone()),
                    ),
                ]),
            ),
            AirConstraint::new(
                "previous_root_matches",
                roots_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    previous_root_witness.expr(),
                    previous_root_computed.expr(),
                ),
            ),
            AirConstraint::new(
                "pruned_root_matches",
                roots_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(pruned_root_witness.expr(), pruned_root_computed.expr()),
            ),
            AirConstraint::new(
                "removed_count_matches",
                roots_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    removed_count.expr(),
                    AirExpression::constant(removed_len),
                ),
            ),
            AirConstraint::new(
                "pruning_fold_matches_witness",
                roots_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    pruning_fold_computed.expr(),
                    pruning_fold_witness.expr(),
                ),
            ),
            AirConstraint::new(
                "pruning_fold_initial_binding",
                fold_segment,
                ConstraintDomain::FirstRow,
                AirExpression::difference(
                    commitment.expr(),
                    AirExpression::constant(binding_element),
                ),
            ),
            AirConstraint::new(
                "pruning_fold_links_rows",
                fold_segment,
                ConstraintDomain::Range {
                    start: 1,
                    end: None,
                },
                AirExpression::difference(accumulator_in.expr(), accumulator_out.shifted(-1)),
            ),
            AirConstraint::new(
                "pruning_fold_summary_consistency",
                fold_segment,
                ConstraintDomain::LastRow,
                AirExpression::difference(
                    accumulator_out.expr(),
                    AirExpression::constant(pruning_fold),
                ),
            ),
        ];

        Ok(AirDefinition::new(constraints))
    }
}

pub type PrefixedDigest = [u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];

mod serde_prefixed_digest {
    use super::{PrefixedDigest, DIGEST_LENGTH, DOMAIN_TAG_LENGTH};
    use hex;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &PrefixedDigest, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PrefixedDigest, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = hex::decode(&encoded).map_err(D::Error::custom)?;
        let expected = DOMAIN_TAG_LENGTH + DIGEST_LENGTH;
        if bytes.len() != expected {
            return Err(D::Error::custom(format!(
                "invalid prefixed digest length: expected {expected} bytes, found {}",
                bytes.len()
            )));
        }
        let mut digest = [0u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];
        digest.copy_from_slice(&bytes);
        Ok(digest)
    }
}

mod serde_prefixed_digest_vec {
    use super::{PrefixedDigest, DIGEST_LENGTH, DOMAIN_TAG_LENGTH};
    use hex;
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(values: &Vec<PrefixedDigest>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            seq.serialize_element(&hex::encode(value))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PrefixedDigest>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrefixedDigestVecVisitor;

        impl<'de> Visitor<'de> for PrefixedDigestVecVisitor {
            type Value = Vec<PrefixedDigest>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence of hex-encoded prefixed digests")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(encoded) = seq.next_element::<String>()? {
                    let bytes = hex::decode(&encoded).map_err(A::Error::custom)?;
                    let expected = DOMAIN_TAG_LENGTH + DIGEST_LENGTH;
                    if bytes.len() != expected {
                        return Err(A::Error::custom(format!(
                            "invalid prefixed digest length: expected {expected} bytes, found {}",
                            bytes.len()
                        )));
                    }
                    let mut digest = [0u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];
                    digest.copy_from_slice(&bytes);
                    values.push(digest);
                }
                Ok(values)
            }
        }

        deserializer.deserialize_seq(PrefixedDigestVecVisitor)
    }
}
