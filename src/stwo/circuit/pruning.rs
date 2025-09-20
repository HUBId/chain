//! Pruning proof STARK constraints blueprint implementation.

use std::collections::HashSet;

use crate::ledger::compute_merkle_root;
use crate::stwo::air::{AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain};
use crate::stwo::params::StarkParameters;

use super::{CircuitError, ExecutionTrace, StarkCircuit, TraceSegment, string_to_field};

/// Witness for the pruning circuit describing the set of removed transactions.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PruningWitness {
    pub previous_tx_root: String,
    pub pruned_tx_root: String,
    pub original_transactions: Vec<String>,
    pub removed_transactions: Vec<String>,
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
}

impl StarkCircuit for PruningCircuit {
    fn name(&self) -> &'static str {
        "pruning"
    }

    fn evaluate_constraints(&self) -> Result<(), CircuitError> {
        self.verify_membership()?;
        self.verify_pruned_root()?;
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
        let summary_row = vec![
            string_to_field(parameters, &self.witness.previous_tx_root),
            string_to_field(parameters, &previous_root_computed),
            string_to_field(parameters, &self.witness.pruned_tx_root),
            string_to_field(parameters, &pruned_root_computed),
            parameters.element_from_u64(self.witness.removed_transactions.len() as u64),
        ];
        let summary_segment = TraceSegment::new(
            "roots",
            vec![
                "previous_root_witness".to_string(),
                "previous_root_computed".to_string(),
                "pruned_root_witness".to_string(),
                "pruned_root_computed".to_string(),
                "removed_count".to_string(),
            ],
            vec![summary_row],
        )?;

        ExecutionTrace::from_segments(vec![membership_segment, summary_segment])
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

        let one = parameters.element_from_u64(1);
        let removed_len =
            parameters.element_from_u64(self.witness.removed_transactions.len() as u64);

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
        ];

        Ok(AirDefinition::new(constraints))
    }
}
