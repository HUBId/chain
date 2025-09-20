//! Recursive proof aggregation circuit blueprint implementation.

use crate::stwo::air::{AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain};
use crate::stwo::params::{FieldElement, PoseidonHasher, StarkParameters};

use super::{CircuitError, ExecutionTrace, StarkCircuit, TraceSegment, string_to_field};

/// Witness connecting previous proof commitments with the latest aggregation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RecursiveWitness {
    pub previous_commitment: Option<String>,
    pub aggregated_commitment: String,
    pub identity_commitments: Vec<String>,
    pub tx_commitments: Vec<String>,
    pub state_commitment: String,
    pub pruning_commitment: String,
    pub block_height: u64,
}

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
        let state_element = Self::decode_field(params, &self.witness.state_commitment)?;
        let pruning_element = Self::decode_field(params, &self.witness.pruning_commitment)?;
        let state_pruning_digest = hasher.hash(&[
            state_element,
            pruning_element,
            params.element_from_u64(self.witness.block_height),
        ]);
        let mut commitments = self.witness.identity_commitments.clone();
        commitments.extend(self.witness.tx_commitments.clone());
        let tx_digest = Self::fold_commitments(&hasher, params, &commitments)?;
        let final_inputs = vec![previous, state_pruning_digest, tx_digest];
        Ok(hasher.hash(&final_inputs))
    }
}

impl StarkCircuit for RecursiveCircuit {
    fn name(&self) -> &'static str {
        "recursive"
    }

    fn evaluate_constraints(&self) -> Result<(), CircuitError> {
        if self.witness.identity_commitments.is_empty() && self.witness.tx_commitments.is_empty() {
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
            "tx_fold",
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
        let state_element = Self::decode_field(parameters, &self.witness.state_commitment)?;
        let pruning_element = Self::decode_field(parameters, &self.witness.pruning_commitment)?;
        let state_pruning_digest = hasher.hash(&[
            state_element,
            pruning_element,
            parameters.element_from_u64(self.witness.block_height),
        ]);
        let aggregate = hasher.hash(&[
            previous.clone(),
            state_pruning_digest.clone(),
            accumulator.clone(),
        ]);
        let witness_commitment =
            Self::decode_field(parameters, &self.witness.aggregated_commitment)?;
        let summary_segment = TraceSegment::new(
            "aggregation",
            vec![
                "previous".to_string(),
                "state_pruning_digest".to_string(),
                "tx_digest".to_string(),
                "aggregate_computed".to_string(),
                "aggregate_witness".to_string(),
            ],
            vec![vec![
                previous,
                state_pruning_digest,
                accumulator,
                aggregate.clone(),
                witness_commitment,
            ]],
        )?;

        ExecutionTrace::from_segments(vec![fold_segment, summary_segment])
    }

    fn define_air(
        &self,
        parameters: &StarkParameters,
        trace: &ExecutionTrace,
    ) -> Result<AirDefinition, CircuitError> {
        let fold_segment = "tx_fold";
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
