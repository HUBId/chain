//! Uptime (Timetoke) circuit implementation capturing node availability.

use crate::official::air::{
    AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain,
};
use crate::official::params::StarkParameters;
use crate::types::UptimeProof;

use super::{string_to_field, CircuitError, ExecutionTrace, StarkCircuit, TraceSegment};

/// Witness attesting to a node's uptime within a given observation window.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UptimeWitness {
    pub wallet_address: String,
    pub node_clock: u64,
    pub epoch: u64,
    pub head_hash: String,
    pub window_start: u64,
    pub window_end: u64,
    pub commitment: String,
}

impl UptimeWitness {
    fn duration(&self) -> Result<u64, CircuitError> {
        self.window_end
            .checked_sub(self.window_start)
            .ok_or_else(|| CircuitError::ConstraintViolation("uptime window underflow".into()))
    }
}

#[derive(Debug)]
pub struct UptimeCircuit {
    pub witness: UptimeWitness,
}

impl UptimeCircuit {
    pub fn new(witness: UptimeWitness) -> Self {
        Self { witness }
    }

    fn expected_commitment(&self) -> Result<String, CircuitError> {
        let commitment = UptimeProof::commitment_bytes(
            &self.witness.wallet_address,
            self.witness.window_start,
            self.witness.window_end,
        );
        Ok(hex::encode(commitment))
    }

    fn ensure_head_hash(&self) -> Result<(), CircuitError> {
        let bytes = hex::decode(&self.witness.head_hash).map_err(|err| {
            CircuitError::InvalidWitness(format!("invalid head hash encoding: {err}"))
        })?;
        if bytes.len() != 32 {
            return Err(CircuitError::ConstraintViolation(
                "head hash must encode 32 bytes".into(),
            ));
        }
        Ok(())
    }
}

impl StarkCircuit for UptimeCircuit {
    fn name(&self) -> &'static str {
        "uptime"
    }

    fn evaluate_constraints(&self) -> Result<(), CircuitError> {
        if self.witness.window_end <= self.witness.window_start {
            return Err(CircuitError::ConstraintViolation(
                "uptime window must progress forward in time".into(),
            ));
        }
        if self.witness.node_clock < self.witness.window_end {
            return Err(CircuitError::ConstraintViolation(
                "node clock precedes observation window".into(),
            ));
        }
        if self.witness.epoch == 0 {
            return Err(CircuitError::ConstraintViolation(
                "epoch counter must be positive".into(),
            ));
        }
        self.ensure_head_hash()?;

        let expected = self.expected_commitment()?;
        if expected != self.witness.commitment {
            return Err(CircuitError::ConstraintViolation(
                "uptime commitment mismatch".into(),
            ));
        }
        Ok(())
    }

    fn generate_trace(&self, parameters: &StarkParameters) -> Result<ExecutionTrace, CircuitError> {
        let duration = self.witness.duration()?;
        let expected_commitment = self.expected_commitment()?;
        let segment = TraceSegment::new(
            "uptime",
            vec![
                "wallet".to_string(),
                "node_clock".to_string(),
                "epoch".to_string(),
                "head_hash".to_string(),
                "window_start".to_string(),
                "window_end".to_string(),
                "window_duration".to_string(),
                "commitment_provided".to_string(),
                "commitment_expected".to_string(),
            ],
            vec![vec![
                string_to_field(parameters, &self.witness.wallet_address),
                parameters.element_from_u64(self.witness.node_clock),
                parameters.element_from_u64(self.witness.epoch),
                string_to_field(parameters, &self.witness.head_hash),
                parameters.element_from_u64(self.witness.window_start),
                parameters.element_from_u64(self.witness.window_end),
                parameters.element_from_u64(duration),
                string_to_field(parameters, &self.witness.commitment),
                string_to_field(parameters, &expected_commitment),
            ]],
        )?;
        ExecutionTrace::single(segment)
    }

    fn define_air(
        &self,
        _parameters: &StarkParameters,
        _trace: &ExecutionTrace,
    ) -> Result<AirDefinition, CircuitError> {
        let segment = "uptime";
        let window_start = AirColumn::new(segment, "window_start");
        let window_end = AirColumn::new(segment, "window_end");
        let duration = AirColumn::new(segment, "window_duration");
        let provided = AirColumn::new(segment, "commitment_provided");
        let expected = AirColumn::new(segment, "commitment_expected");

        let constraints = vec![
            AirConstraint::new(
                "duration_matches_window",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    window_end.expr(),
                    AirExpression::sum(vec![window_start.expr(), duration.expr()]),
                ),
            ),
            AirConstraint::new(
                "commitment_matches",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(provided.expr(), expected.expr()),
            ),
        ];

        Ok(AirDefinition::new(constraints))
    }
}
