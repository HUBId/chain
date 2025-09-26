//! Identity STARK constraints blueprint implementation.

use crate::errors::{ChainError, ChainResult};
use crate::identity_tree::{IDENTITY_TREE_DEPTH, IdentityCommitmentProof, IdentityCommitmentTree};
use crate::stwo::air::{AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain};
use crate::stwo::params::StarkParameters;

use super::{CircuitError, ExecutionTrace, StarkCircuit, TraceSegment, string_to_field};
use crate::vrf;

/// Witness data required to validate an identity genesis declaration.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct IdentityWitness {
    pub wallet_pk: String,
    pub wallet_addr: String,
    pub vrf_tag: String,
    pub epoch_nonce: String,
    pub state_root: String,
    pub identity_root: String,
    pub initial_reputation: i64,
    pub commitment: String,
    pub identity_leaf: String,
    pub identity_path: Vec<String>,
}

/// Circuit enforcing the constraints of a sovereign identity declaration.
#[derive(Debug, Clone)]
pub struct IdentityCircuit {
    pub witness: IdentityWitness,
}

impl IdentityCircuit {
    pub fn new(witness: IdentityWitness) -> Self {
        Self { witness }
    }

    fn epoch_seed(&self) -> ChainResult<[u8; 32]> {
        let bytes = hex::decode(&self.witness.epoch_nonce).map_err(|err| {
            ChainError::Transaction(format!("invalid epoch nonce encoding: {err}"))
        })?;
        if bytes.len() != 32 {
            return Err(ChainError::Transaction(
                "epoch nonce must encode exactly 32 bytes".into(),
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(seed)
    }

    fn computed_wallet_addr(&self) -> ChainResult<String> {
        let pk_bytes = hex::decode(&self.witness.wallet_pk).map_err(|err| {
            ChainError::Transaction(format!("invalid wallet public key encoding: {err}"))
        })?;
        Ok(hex::encode::<[u8; 32]>(
            stwo::core::vcs::blake2_hash::Blake2sHasher::hash(&pk_bytes).into(),
        ))
    }

    fn computed_commitment(&self) -> ChainResult<String> {
        let parameters = StarkParameters::blueprint_default();
        let hasher = parameters.poseidon_hasher();
        let inputs = vec![
            string_to_field(&parameters, &self.witness.wallet_addr),
            string_to_field(&parameters, &self.witness.vrf_tag),
            string_to_field(&parameters, &self.witness.identity_root),
            string_to_field(&parameters, &self.witness.state_root),
        ];
        Ok(hasher.hash(&inputs).to_hex())
    }

    fn commitment_proof(&self) -> IdentityCommitmentProof {
        IdentityCommitmentProof {
            leaf: self.witness.identity_leaf.clone(),
            siblings: self.witness.identity_path.clone(),
        }
    }

    fn check_constraints(&self) -> ChainResult<()> {
        let computed_addr = self.computed_wallet_addr()?;
        if computed_addr != self.witness.wallet_addr {
            return Err(ChainError::Transaction(
                "wallet address does not match provided public key".into(),
            ));
        }
        if self.witness.initial_reputation != 0 {
            return Err(ChainError::Transaction(
                "identity must start with zero reputation".into(),
            ));
        }
        let seed = self.epoch_seed()?;
        let _ = seed;
        self.verify_vrf_tag_format()?;
        let expected_commitment = self.computed_commitment()?;
        if expected_commitment != self.witness.commitment {
            return Err(ChainError::Transaction(
                "identity commitment mismatch".into(),
            ));
        }
        if self.witness.identity_path.len() != IDENTITY_TREE_DEPTH {
            return Err(ChainError::Transaction(
                "identity proof has invalid depth".into(),
            ));
        }
        let proof = self.commitment_proof();
        if !proof.is_vacant()? {
            return Err(ChainError::Transaction(
                "identity slot already occupied".into(),
            ));
        }
        let computed_root = proof.compute_root(&self.witness.wallet_addr)?;
        if computed_root != self.witness.identity_root {
            return Err(ChainError::Transaction(
                "identity path does not reconstruct root".into(),
            ));
        }
        Ok(())
    }

    fn verify_vrf_tag_format(&self) -> ChainResult<()> {
        let bytes = hex::decode(&self.witness.vrf_tag)
            .map_err(|err| ChainError::Transaction(format!("invalid VRF tag encoding: {err}")))?;
        if bytes.len() != vrf::VRF_PROOF_LENGTH {
            return Err(ChainError::Transaction(
                "VRF tag must encode a full VRF proof".into(),
            ));
        }
        Ok(())
    }
}

impl StarkCircuit for IdentityCircuit {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn evaluate_constraints(&self) -> Result<(), CircuitError> {
        self.check_constraints()
            .map_err(|err| CircuitError::ConstraintViolation(err.to_string()))
    }

    fn generate_trace(&self, parameters: &StarkParameters) -> Result<ExecutionTrace, CircuitError> {
        let computed_addr = self
            .computed_wallet_addr()
            .map_err(|err| CircuitError::InvalidWitness(err.to_string()))?;
        self.epoch_seed()
            .map_err(|err| CircuitError::InvalidWitness(err.to_string()))?;
        self.verify_vrf_tag_format()
            .map_err(|err| CircuitError::InvalidWitness(err.to_string()))?;
        let expected_commitment = self
            .computed_commitment()
            .map_err(|err| CircuitError::InvalidWitness(err.to_string()))?;
        let proof = self.commitment_proof();
        let path_root = proof
            .compute_root(&self.witness.wallet_addr)
            .map_err(|err| CircuitError::InvalidWitness(err.to_string()))?;
        let default_leaf = IdentityCommitmentTree::default_leaf_hex();

        let columns = vec![
            "wallet_addr_provided".to_string(),
            "wallet_addr_computed".to_string(),
            "vrf_tag".to_string(),
            "vrf_expected".to_string(),
            "state_root".to_string(),
            "identity_root".to_string(),
            "initial_reputation".to_string(),
            "commitment_provided".to_string(),
            "commitment_expected".to_string(),
            "identity_leaf_provided".to_string(),
            "identity_leaf_default".to_string(),
            "identity_root_computed".to_string(),
        ];

        let reputation_value = if self.witness.initial_reputation >= 0 {
            parameters.element_from_u64(self.witness.initial_reputation as u64)
        } else {
            return Err(CircuitError::InvalidWitness(
                "initial reputation cannot be negative".into(),
            ));
        };

        let row = vec![
            string_to_field(parameters, &self.witness.wallet_addr),
            string_to_field(parameters, &computed_addr),
            string_to_field(parameters, &self.witness.vrf_tag),
            string_to_field(parameters, &self.witness.vrf_tag),
            string_to_field(parameters, &self.witness.state_root),
            string_to_field(parameters, &self.witness.identity_root),
            reputation_value,
            string_to_field(parameters, &self.witness.commitment),
            string_to_field(parameters, &expected_commitment),
            string_to_field(parameters, &self.witness.identity_leaf),
            string_to_field(parameters, &default_leaf),
            string_to_field(parameters, &path_root),
        ];

        let segment = TraceSegment::new("identity", columns, vec![row])?;
        ExecutionTrace::single(segment)
    }

    fn define_air(
        &self,
        parameters: &StarkParameters,
        _trace: &ExecutionTrace,
    ) -> Result<AirDefinition, CircuitError> {
        let segment = "identity";
        let provided_addr = AirColumn::new(segment, "wallet_addr_provided");
        let computed_addr = AirColumn::new(segment, "wallet_addr_computed");
        let vrf_tag = AirColumn::new(segment, "vrf_tag");
        let vrf_expected = AirColumn::new(segment, "vrf_expected");
        let commitment_provided = AirColumn::new(segment, "commitment_provided");
        let commitment_expected = AirColumn::new(segment, "commitment_expected");
        let initial_reputation = AirColumn::new(segment, "initial_reputation");
        let identity_leaf_provided = AirColumn::new(segment, "identity_leaf_provided");
        let identity_leaf_default = AirColumn::new(segment, "identity_leaf_default");
        let identity_root = AirColumn::new(segment, "identity_root");
        let identity_root_computed = AirColumn::new(segment, "identity_root_computed");
        let zero = parameters.element_from_u64(0);

        let constraints = vec![
            AirConstraint::new(
                "address_matches",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(provided_addr.expr(), computed_addr.expr()),
            ),
            AirConstraint::new(
                "vrf_matches",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(vrf_tag.expr(), vrf_expected.expr()),
            ),
            AirConstraint::new(
                "commitment_matches",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(commitment_provided.expr(), commitment_expected.expr()),
            ),
            AirConstraint::new(
                "reputation_zero",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(initial_reputation.expr(), AirExpression::constant(zero)),
            ),
            AirConstraint::new(
                "identity_leaf_empty",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    identity_leaf_provided.expr(),
                    identity_leaf_default.expr(),
                ),
            ),
            AirConstraint::new(
                "identity_root_matches",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(identity_root.expr(), identity_root_computed.expr()),
            ),
        ];

        Ok(AirDefinition::new(constraints))
    }
}
