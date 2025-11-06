use crate::messages::{ConsensusCertificate, ConsensusWitnessBundle};
use crate::validator::ValidatorId;

/// Construct a consensus witness bundle by extracting the metadata encoded in the
/// consensus certificate for the committed block.
pub fn build_consensus_witness(
    height: u64,
    round: u64,
    participants: Vec<ValidatorId>,
    certificate: &ConsensusCertificate,
) -> ConsensusWitnessBundle {
    let (vrf_outputs, vrf_proofs): (Vec<_>, Vec<_>) = certificate
        .metadata
        .vrf
        .entries
        .iter()
        .map(|entry| (entry.pre_output.clone(), entry.proof.clone()))
        .unzip();

    ConsensusWitnessBundle {
        height,
        round,
        participants,
        vrf_outputs,
        vrf_proofs,
        witness_commitments: certificate.metadata.witness_commitments.clone(),
        quorum_bitmap_root: certificate.metadata.quorum_bitmap_root.clone(),
        quorum_signature_root: certificate.metadata.quorum_signature_root.clone(),
    }
}
