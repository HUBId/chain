use hex;
use rpp_consensus::messages::{BlockId, ConsensusCertificate, ConsensusProofMetadata};
use rpp_consensus::proof_backend::ProofSystemKind;

fn sample_metadata() -> ConsensusProofMetadata {
    ConsensusProofMetadata {
        vrf_outputs: vec!["11".repeat(32)],
        witness_commitments: vec!["22".repeat(32), "33".repeat(32)],
        reputation_roots: vec!["44".repeat(32)],
    }
}

fn sample_certificate() -> ConsensusCertificate {
    ConsensusCertificate {
        block_hash: BlockId("aa".repeat(32)),
        height: 42,
        round: 7,
        total_power: 10,
        quorum_threshold: 7,
        prevote_power: 8,
        precommit_power: 8,
        commit_power: 8,
        prevotes: Vec::new(),
        precommits: Vec::new(),
        metadata: sample_metadata(),
    }
}

#[test]
fn consensus_witness_roundtrip_preserves_metadata() {
    let certificate = sample_certificate();
    let witness = certificate
        .encode_witness(ProofSystemKind::Mock)
        .expect("encode consensus witness");
    let (_, decoded): (_, ConsensusCertificate) =
        witness.decode().expect("decode consensus witness");
    assert_eq!(decoded.metadata, certificate.metadata);
}

#[test]
fn consensus_public_inputs_include_structured_metadata() {
    let certificate = sample_certificate();
    let inputs = certificate
        .consensus_public_inputs()
        .expect("public inputs");

    assert_eq!(inputs.vrf_outputs.len(), 1);
    assert_eq!(inputs.witness_commitments.len(), 2);
    assert_eq!(inputs.reputation_roots.len(), 1);

    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(&hex::decode(&certificate.metadata.vrf_outputs[0]).unwrap());
    assert_eq!(inputs.vrf_outputs[0], buffer);
}
