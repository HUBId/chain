//! Deterministic FRI proof generation backed by the official STWO prover.

use crate::official::air::AirDefinition;
use crate::official::circuit::ExecutionTrace;
use crate::official::conversions::field_to_secure;
use crate::official::official_adapter::BlueprintComponent;
use crate::official::params::{FieldElement, StarkParameters};
use crate::official::proof::{CommitmentSchemeProofData, FriProof};

use crate::stwo_official::core::channel::{Blake2sChannel, Channel};
use crate::stwo_official::core::pcs::PcsConfig;
use crate::stwo_official::core::poly::circle::CanonicCoset;
use crate::stwo_official::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use crate::stwo_official::prover::backend::cpu::CpuBackend;
use crate::stwo_official::prover::poly::circle::PolyOps;
use crate::stwo_official::prover::ComponentProver;
use crate::stwo_official::prover::{prove, CommitmentSchemeProver};

/// Helper encapsulating the deterministic FRI-style commitment process.
pub struct FriProver<'a> {
    parameters: &'a StarkParameters,
    pcs_config: PcsConfig,
}

impl<'a> FriProver<'a> {
    /// Create a prover helper backed by the supplied STARK parameters.
    pub fn new(parameters: &'a StarkParameters) -> Self {
        Self {
            parameters,
            pcs_config: PcsConfig::default(),
        }
    }

    /// Generate a deterministic FRI-style commitment proof for the supplied
    /// execution trace and public inputs.
    pub fn prove(
        &self,
        air: &AirDefinition,
        trace: &ExecutionTrace,
        public_inputs: &[FieldElement],
    ) -> FriProverOutput {
        let component = BlueprintComponent::new(air, trace, self.parameters)
            .expect("component adapter initialises");

        let mut channel = Blake2sChannel::default();
        let secure_inputs = public_inputs
            .iter()
            .map(field_to_secure)
            .collect::<Vec<_>>();
        channel.mix_felts(&secure_inputs);
        self.pcs_config.mix_into(&mut channel);

        let max_log = component
            .segments
            .iter()
            .map(|segment| segment.log_size.max(1))
            .max()
            .unwrap_or(0);
        let evaluation_log = max_log + self.pcs_config.fri_config.log_blowup_factor + 1;
        let domain = CanonicCoset::new(evaluation_log).circle_domain();
        let twiddles = CpuBackend::precompute_twiddles(domain.half_coset);

        let mut commitment_scheme =
            CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(self.pcs_config, &twiddles);
        component.build_commitment_views(&mut commitment_scheme, &mut channel);

        let component_refs: [&dyn ComponentProver<CpuBackend>; 1] = [&component];
        let stark_proof = prove(&component_refs, &mut channel, commitment_scheme)
            .expect("official prover succeeds");

        let commitment_proof = CommitmentSchemeProofData::from_official(&stark_proof.0);
        let fri_proof = FriProof::from_official(&stark_proof.0.fri_proof);

        FriProverOutput {
            commitment_proof,
            fri_proof,
        }
    }
}

/// Prover output bundling the commitment scheme and FRI proofs.
#[derive(Clone, Debug)]
pub struct FriProverOutput {
    pub commitment_proof: CommitmentSchemeProofData,
    pub fri_proof: FriProof,
}
