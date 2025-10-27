//! Recursive proof aggregation circuit blueprint implementation.

use crate::official::air::{
    AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain,
};
use crate::official::params::{FieldElement, PoseidonHasher, StarkParameters};

use rpp_pruning::{DIGEST_LENGTH, DOMAIN_TAG_LENGTH};

use super::{string_to_field, CircuitError, ExecutionTrace, StarkCircuit, TraceSegment};

/// Witness connecting previous proof commitments with the latest aggregation.

#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize)]
pub struct RecursiveWitness {
    pub previous_commitment: Option<String>,
    pub aggregated_commitment: String,
    pub identity_commitments: Vec<String>,
    pub tx_commitments: Vec<String>,
    pub uptime_commitments: Vec<String>,
    pub consensus_commitments: Vec<String>,
    pub state_commitment: String,
    pub global_state_root: String,
    pub utxo_root: String,
    pub reputation_root: String,
    pub timetoke_root: String,
    pub zsi_root: String,
    pub proof_root: String,
    #[serde(default, with = "serde::prefixed_digest")]
    pub pruning_binding_digest: PrefixedDigest,
    #[serde(default, with = "serde::prefixed_digest_vec")]
    pub pruning_segment_commitments: Vec<PrefixedDigest>,
    pub block_height: u64,
}

pub type PrefixedDigest = [u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];

#[derive(Debug)]
pub struct RecursiveCircuit {
    pub witness: RecursiveWitness,
}

impl RecursiveCircuit {
    pub fn new(witness: RecursiveWitness) -> Self {
        Self { witness }
    }

    fn decode_field(params: &StarkParameters, value: &str) -> Result<FieldElement, CircuitError> {
        Ok(string_to_field(params, value))
    }

    fn fold_commitments(
        hasher: &PoseidonHasher,
        params: &StarkParameters,
        commitments: &[String],
    ) -> Result<FieldElement, CircuitError> {
        let mut acc = FieldElement::zero(params.modulus());
        for commitment in commitments {
            let element = Self::decode_field(params, commitment)?;
            let inputs = vec![acc.clone(), element, FieldElement::zero(params.modulus())];
            acc = hasher.hash(&inputs);
        }
        Ok(acc)
    }

    fn aggregate_with_params(
        &self,
        params: &StarkParameters,
    ) -> Result<FieldElement, CircuitError> {
        let hasher = params.poseidon_hasher();
        let previous = match &self.witness.previous_commitment {
            Some(value) => Self::decode_field(params, value)?,
            None => FieldElement::zero(params.modulus()),
        };
        let pruning_element = params.element_from_bytes(&self.witness.pruning_binding_digest);
        let mut commitments = self.witness.identity_commitments.clone();
        commitments.extend(self.witness.tx_commitments.clone());
        commitments.extend(self.witness.uptime_commitments.clone());
        commitments.extend(self.witness.consensus_commitments.clone());
        let activity_digest = Self::fold_commitments(&hasher, params, &commitments)?;
        let state_digest = hasher.hash(&[
            Self::decode_field(params, &self.witness.state_commitment)?,
            Self::decode_field(params, &self.witness.global_state_root)?,
            Self::decode_field(params, &self.witness.utxo_root)?,
            Self::decode_field(params, &self.witness.reputation_root)?,
            Self::decode_field(params, &self.witness.timetoke_root)?,
            Self::decode_field(params, &self.witness.zsi_root)?,
            Self::decode_field(params, &self.witness.proof_root)?,
            params.element_from_u64(self.witness.block_height),
        ]);
        let final_inputs = vec![previous, state_digest, pruning_element, activity_digest];
        Ok(hasher.hash(&final_inputs))
    }
}

impl StarkCircuit for RecursiveCircuit {
    fn name(&self) -> &'static str {
        "recursive"
    }

    fn evaluate_constraints(&self) -> Result<(), CircuitError> {
        if self.witness.identity_commitments.is_empty()
            && self.witness.tx_commitments.is_empty()
            && self.witness.uptime_commitments.is_empty()
            && self.witness.consensus_commitments.is_empty()
        {
            return Err(CircuitError::ConstraintViolation(
                "recursive witness missing aggregated commitments".into(),
            ));
        }
        let params = StarkParameters::blueprint_default();
        let aggregated = self.aggregate_with_params(&params)?;
        let expected = Self::decode_field(&params, &self.witness.aggregated_commitment)?;
        if aggregated != expected {
            return Err(CircuitError::ConstraintViolation(
                "aggregated commitment mismatch".into(),
            ));
        }
        Ok(())
    }

    fn generate_trace(&self, parameters: &StarkParameters) -> Result<ExecutionTrace, CircuitError> {
        let hasher = parameters.poseidon_hasher();
        let zero = FieldElement::zero(parameters.modulus());
        let mut accumulator = zero.clone();
        let mut fold_rows = Vec::new();
        let mut commitments = self.witness.identity_commitments.clone();
        commitments.extend(self.witness.tx_commitments.clone());
        commitments.extend(self.witness.uptime_commitments.clone());
        commitments.extend(self.witness.consensus_commitments.clone());
        for commitment in commitments.iter() {
            let commitment_element = Self::decode_field(parameters, commitment)?;
            let next = hasher.hash(&[
                accumulator.clone(),
                commitment_element.clone(),
                zero.clone(),
            ]);
            fold_rows.push(vec![accumulator.clone(), commitment_element, next.clone()]);
            accumulator = next;
        }
        let fold_segment = TraceSegment::new(
            "commit_fold",
            vec![
                "accumulator_in".to_string(),
                "commitment".to_string(),
                "accumulator_out".to_string(),
            ],
            fold_rows,
        )?;

        let previous = match &self.witness.previous_commitment {
            Some(value) => Self::decode_field(parameters, value)?,
            None => FieldElement::zero(parameters.modulus()),
        };
        let pruning_element = parameters.element_from_bytes(&self.witness.pruning_binding_digest);
        let pruning_commitment_rows: Vec<Vec<FieldElement>> = self
            .witness
            .pruning_segment_commitments
            .iter()
            .map(|digest| vec![parameters.element_from_bytes(digest)])
            .collect();
        let pruning_segment = TraceSegment::new(
            "pruning_commitments",
            vec!["commitment".to_string()],
            pruning_commitment_rows,
        )?;
        let state_digest = hasher.hash(&[
            Self::decode_field(parameters, &self.witness.state_commitment)?,
            Self::decode_field(parameters, &self.witness.global_state_root)?,
            Self::decode_field(parameters, &self.witness.utxo_root)?,
            Self::decode_field(parameters, &self.witness.reputation_root)?,
            Self::decode_field(parameters, &self.witness.timetoke_root)?,
            Self::decode_field(parameters, &self.witness.zsi_root)?,
            Self::decode_field(parameters, &self.witness.proof_root)?,
            parameters.element_from_u64(self.witness.block_height),
        ]);
        let aggregate = hasher.hash(&[
            previous.clone(),
            state_digest.clone(),
            pruning_element.clone(),
            accumulator.clone(),
        ]);
        let witness_commitment =
            Self::decode_field(parameters, &self.witness.aggregated_commitment)?;
        let summary_segment = TraceSegment::new(
            "aggregation",
            vec![
                "previous".to_string(),
                "state_digest".to_string(),
                "pruning".to_string(),
                "activity_digest".to_string(),
                "aggregate_computed".to_string(),
                "aggregate_witness".to_string(),
            ],
            vec![vec![
                previous,
                state_digest,
                pruning_element,
                accumulator,
                aggregate.clone(),
                witness_commitment,
            ]],
        )?;

        let mut segments = Vec::new();
        if !pruning_segment.rows.is_empty() {
            segments.push(pruning_segment);
        }
        segments.push(fold_segment);
        segments.push(summary_segment);
        ExecutionTrace::from_segments(segments)
    }

    fn define_air(
        &self,
        parameters: &StarkParameters,
        trace: &ExecutionTrace,
    ) -> Result<AirDefinition, CircuitError> {
        let fold_segment = "commit_fold";
        let accumulator_in = AirColumn::new(fold_segment, "accumulator_in");
        let accumulator_out = AirColumn::new(fold_segment, "accumulator_out");

        let aggregation_segment = "aggregation";
        let aggregate_computed = AirColumn::new(aggregation_segment, "aggregate_computed");
        let aggregate_witness = AirColumn::new(aggregation_segment, "aggregate_witness");

        let zero = FieldElement::zero(parameters.modulus());

        let mut constraints = vec![
            AirConstraint::new(
                "fold_initial_accumulator",
                fold_segment,
                ConstraintDomain::FirstRow,
                AirExpression::difference(
                    accumulator_in.expr(),
                    AirExpression::constant(zero.clone()),
                ),
            ),
            AirConstraint::new(
                "fold_links_rows",
                fold_segment,
                ConstraintDomain::Range {
                    start: 1,
                    end: None,
                },
                AirExpression::difference(accumulator_in.expr(), accumulator_out.shifted(-1)),
            ),
            AirConstraint::new(
                "aggregate_matches_witness",
                aggregation_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(aggregate_computed.expr(), aggregate_witness.expr()),
            ),
        ];

        if trace
            .segments
            .iter()
            .find(|segment| segment.name == fold_segment)
            .map(|segment| segment.rows.is_empty())
            .unwrap_or(false)
        {
            constraints.retain(|constraint| constraint.segment != fold_segment);
        }

        Ok(AirDefinition::new(constraints))
    }
}

mod serde {
    use super::{PrefixedDigest, DIGEST_LENGTH, DOMAIN_TAG_LENGTH};
    use ::serde::de::{SeqAccess, Visitor};
    use ::serde::ser::SerializeSeq;
    use ::serde::{Deserialize, Deserializer, Serializer};
    use std::fmt;

    const EXPECTED_LENGTH: usize = DOMAIN_TAG_LENGTH + DIGEST_LENGTH;

    fn decode_prefixed_digest(bytes: &[u8]) -> Result<PrefixedDigest, String> {
        if bytes.len() != EXPECTED_LENGTH {
            return Err(format!(
                "invalid digest length: expected {} bytes, found {}",
                EXPECTED_LENGTH,
                bytes.len()
            ));
        }
        let mut digest = [0u8; EXPECTED_LENGTH];
        digest.copy_from_slice(bytes);
        Ok(digest)
    }

    pub mod prefixed_digest {
        use super::*;

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
            let bytes = hex::decode(&encoded).map_err(|err| D::Error::custom(err.to_string()))?;
            decode_prefixed_digest(&bytes).map_err(D::Error::custom)
        }
    }

    pub mod prefixed_digest_vec {
        use super::*;

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
                        let bytes = hex::decode(&encoded)
                            .map_err(|err| A::Error::custom(err.to_string()))?;
                        let digest = decode_prefixed_digest(&bytes).map_err(A::Error::custom)?;
                        values.push(digest);
                    }
                    Ok(values)
                }
            }

            deserializer.deserialize_seq(PrefixedDigestVecVisitor)
        }
    }
}
