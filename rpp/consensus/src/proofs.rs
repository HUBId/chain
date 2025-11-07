use crate::messages::{ConsensusCertificate, ConsensusWitnessBindings, ConsensusWitnessBundle};
use crate::validator::ValidatorId;

/// Construct a consensus witness bundle by extracting the metadata encoded in the
/// consensus certificate for the committed block.
pub fn build_consensus_witness(
    height: u64,
    round: u64,
    participants: Vec<ValidatorId>,
    certificate: &ConsensusCertificate,
) -> ConsensusWitnessBundle {
    let public_inputs = certificate
        .consensus_public_inputs()
        .expect("consensus certificate metadata must be valid");
    let (vrf_outputs, vrf_proofs): (Vec<_>, Vec<_>) = certificate
        .metadata
        .vrf
        .entries
        .iter()
        .map(|entry| (entry.pre_output.clone(), entry.proof.clone()))
        .unzip();

    let encode_digest = |digest: [u8; 32]| hex::encode(digest);

    ConsensusWitnessBundle {
        height,
        round,
        participants,
        vrf_entries: certificate.metadata.vrf.entries.clone(),
        vrf_outputs,
        vrf_proofs,
        witness_commitments: certificate.metadata.witness_commitments.clone(),
        reputation_roots: certificate.metadata.reputation_roots.clone(),
        epoch: certificate.metadata.epoch,
        slot: certificate.metadata.slot,
        quorum_bitmap_root: certificate.metadata.quorum_bitmap_root.clone(),
        quorum_signature_root: certificate.metadata.quorum_signature_root.clone(),
        bindings: ConsensusWitnessBindings {
            vrf_output: encode_digest(public_inputs.vrf_output_binding),
            vrf_proof: encode_digest(public_inputs.vrf_proof_binding),
            witness_commitment: encode_digest(public_inputs.witness_commitment_binding),
            reputation_root: encode_digest(public_inputs.reputation_root_binding),
            quorum_bitmap: encode_digest(public_inputs.quorum_bitmap_binding),
            quorum_signature: encode_digest(public_inputs.quorum_signature_binding),
        },
    }
}
