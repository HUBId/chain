use std::collections::BTreeMap;

use num_traits::identities::Zero;
use serde::{Deserialize, Serialize};
use stwo_lib::core::channel::{Blake2sChannel, MerkleChannel};
use stwo_lib::core::fields::m31::{BaseField, P as M31_MODULUS};
use stwo_lib::core::fields::qm31::SecureField;
use stwo_lib::core::fri::{
    CirclePolyDegreeBound, FriConfig, FriProof as StwoFriProof, FriVerifier,
};
use stwo_lib::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use stwo_lib::prover::backend::cpu::CpuCirclePoly;
use stwo_lib::prover::backend::CpuBackend;
use stwo_lib::prover::fri::FriProver as StwoFriProver;
use stwo_lib::prover::poly::circle::{PolyOps, SecureEvaluation};
use stwo_lib::prover::poly::twiddles::TwiddleTree;
use stwo_lib::prover::poly::BitReversedOrder;

use crate::core::vcs::blake2_hash::Blake2sHasher;
use crate::params::{FieldElement, StwoConfig};

#[derive(Debug, thiserror::Error)]
pub enum FriWrapperError {
    #[error("fri blowup factor must be a power of two greater than one, got {blowup_factor}")]
    InvalidBlowupFactor { blowup_factor: usize },
    #[error("fri polynomial degree {log_degree} exceeds supported maximum {max_log_degree}")]
    DegreeTooLarge {
        log_degree: u32,
        max_log_degree: u32,
    },
    #[error("fri column degree bounds mismatch between witness and proof")]
    ColumnBoundsMismatch,
    #[error("fri configuration mismatch between witness and proof")]
    ConfigMismatch,
    #[error("fri query evaluations mismatch")]
    QueryMismatch,
    #[error("fri verification failed: {0}")]
    Verification(#[from] stwo_lib::core::fri::FriVerificationError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriProof {
    pub config: FriConfig,
    pub column_log_degree_bounds: Vec<u32>,
    pub proof: StwoFriProof<<Blake2sMerkleChannel as MerkleChannel>::H>,
    pub query_values: Vec<Vec<SecureField>>,
}

impl PartialEq for FriProof {
    fn eq(&self, other: &Self) -> bool {
        self.column_log_degree_bounds == other.column_log_degree_bounds
            && self.config.log_blowup_factor == other.config.log_blowup_factor
            && self.config.log_last_layer_degree_bound == other.config.log_last_layer_degree_bound
            && self.config.n_queries == other.config.n_queries
            && self.query_values == other.query_values
            && serde_json::to_vec(&self.proof).ok() == serde_json::to_vec(&other.proof).ok()
    }
}

impl Eq for FriProof {}

struct FriInputs {
    config: FriConfig,
    columns: Vec<SecureEvaluation<CpuBackend, BitReversedOrder>>,
    column_log_degree_bounds: Vec<u32>,
    twiddles: TwiddleTree<CpuBackend>,
}

const MAX_LOG_DEGREE: u32 = 10;

impl FriInputs {
    fn new(values: &[FieldElement], config: &StwoConfig) -> Result<Self, FriWrapperError> {
        let blowup_factor = config.blowup_factor;
        if blowup_factor.count_ones() != 1 || blowup_factor <= 1 {
            return Err(FriWrapperError::InvalidBlowupFactor { blowup_factor });
        }

        let log_blowup_factor = blowup_factor.ilog2() as u32;

        let input_len = values.len().max(1);
        let log_degree = (input_len.next_power_of_two().ilog2()) as u32;
        if log_degree > MAX_LOG_DEGREE {
            return Err(FriWrapperError::DegreeTooLarge {
                log_degree,
                max_log_degree: MAX_LOG_DEGREE,
            });
        }

        let coeffs_len = 1usize << log_degree;
        let mut coeffs = vec![BaseField::zero(); coeffs_len];
        for (coeff, value) in coeffs.iter_mut().zip(values.iter().copied()) {
            *coeff = field_to_base(value);
        }

        let circle_poly = CpuCirclePoly::new(coeffs);
        let coset = stwo_lib::core::circle::Coset::half_odds(log_degree + log_blowup_factor - 1);
        let domain = stwo_lib::core::poly::circle::CircleDomain::new(coset);
        let evaluation = circle_poly.evaluate(domain);
        let secure_evaluation = SecureEvaluation::new(
            domain,
            evaluation.into_iter().map(SecureField::from).collect(),
        );
        debug_assert_eq!(
            secure_evaluation.domain.log_size(),
            log_degree + log_blowup_factor,
            "secure evaluation domain log size mismatch"
        );

        let twiddles = CpuBackend::precompute_twiddles(secure_evaluation.domain.half_coset);
        let last_layer_log = log_degree.saturating_sub(2);
        let fri_config = FriConfig::new(last_layer_log, log_blowup_factor, config.fri_repetitions);

        Ok(Self {
            config: fri_config,
            columns: vec![secure_evaluation],
            column_log_degree_bounds: vec![log_degree],
            twiddles,
        })
    }

    fn collect_query_values(
        &self,
        query_positions: &BTreeMap<u32, Vec<usize>>,
    ) -> Vec<Vec<SecureField>> {
        self.columns
            .iter()
            .map(|column| {
                let log_size = column.domain.log_size();
                query_positions
                    .get(&log_size)
                    .into_iter()
                    .flat_map(|positions| positions.iter())
                    .map(|index| column.values.at(*index))
                    .collect()
            })
            .collect()
    }
}

fn field_to_base(value: FieldElement) -> BaseField {
    let modulus_square = (M31_MODULUS as u128) * (M31_MODULUS as u128);
    let reduced = value.as_u128() % modulus_square;
    BaseField::reduce(reduced as u64)
}

pub struct FriProver;

impl FriProver {
    pub fn prove(
        values: &[FieldElement],
        config: &StwoConfig,
    ) -> Result<FriProof, FriWrapperError> {
        let inputs = FriInputs::new(values, config)?;

        let mut channel = Blake2sChannel::default();
        let stwo_prover = StwoFriProver::<CpuBackend, Blake2sMerkleChannel>::commit(
            &mut channel,
            inputs.config,
            &inputs.columns,
            &inputs.twiddles,
        );
        let (proof, query_positions) = stwo_prover.decommit(&mut channel);
        let query_values = inputs.collect_query_values(&query_positions);
        let FriInputs {
            config,
            column_log_degree_bounds,
            ..
        } = inputs;

        Ok(FriProof {
            config,
            column_log_degree_bounds,
            proof,
            query_values,
        })
    }

    pub fn verify(
        values: &[FieldElement],
        proof: &FriProof,
        config: &StwoConfig,
    ) -> Result<(), FriWrapperError> {
        let inputs = FriInputs::new(values, config)?;
        if inputs.column_log_degree_bounds != proof.column_log_degree_bounds {
            return Err(FriWrapperError::ColumnBoundsMismatch);
        }

        if inputs.config.log_blowup_factor != proof.config.log_blowup_factor
            || inputs.config.log_last_layer_degree_bound != proof.config.log_last_layer_degree_bound
            || inputs.config.n_queries != proof.config.n_queries
        {
            return Err(FriWrapperError::ConfigMismatch);
        }

        let mut channel = Blake2sChannel::default();
        let column_bounds = proof
            .column_log_degree_bounds
            .iter()
            .map(|&log_degree| CirclePolyDegreeBound::new(log_degree))
            .collect();

        let mut verifier = FriVerifier::<Blake2sMerkleChannel>::commit(
            &mut channel,
            proof.config,
            proof.proof.clone(),
            column_bounds,
        )?;

        let query_positions = verifier.sample_query_positions(&mut channel);
        let expected_query_values = inputs.collect_query_values(&query_positions);
        if expected_query_values != proof.query_values {
            return Err(FriWrapperError::QueryMismatch);
        }

        verifier.decommit(proof.query_values.clone())?;
        Ok(())
    }
}

pub fn compress_proof(proof: &FriProof) -> [u8; 32] {
    let encoded = serde_json::to_vec(proof).expect("fri proof is serialisable");
    Blake2sHasher::hash(&encoded).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_values() -> Vec<FieldElement> {
        vec![1u128.into(), 2u128.into(), 3u128.into(), 4u128.into()]
    }

    #[test]
    fn roundtrip_prove_verify() {
        let config = StwoConfig::default();
        let values = sample_values();
        let proof = FriProver::prove(&values, &config).expect("prove");
        FriProver::verify(&values, &proof, &config).expect("verify");
    }

    #[test]
    fn verification_detects_tampering() {
        let config = StwoConfig::default();
        let values = sample_values();
        let mut proof = FriProver::prove(&values, &config).expect("prove");
        proof.query_values[0][0] = SecureField::from(999u32);
        let err = FriProver::verify(&values, &proof, &config).expect_err("verification fails");
        assert!(matches!(err, FriWrapperError::QueryMismatch));
    }
}
