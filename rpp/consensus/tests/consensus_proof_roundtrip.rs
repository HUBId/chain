use hex;
use rpp_consensus::messages::{
    BlockId, ConsensusCertificate, ConsensusProofMetadata, ConsensusVrfEntry,
    ConsensusVrfPoseidonInput,
};
use rpp_consensus::proof_backend::ProofSystemKind;
use rpp_crypto_vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};

fn sample_metadata() -> ConsensusProofMetadata {
    ConsensusProofMetadata {
        vrf_entries: vec![ConsensusVrfEntry {
            randomness: "11".repeat(32),
            pre_output: "22".repeat(VRF_PREOUTPUT_LENGTH),
            proof: "22".repeat(VRF_PROOF_LENGTH),
            public_key: "33".repeat(32),
            poseidon: ConsensusVrfPoseidonInput {
                digest: "44".repeat(32),
                last_block_header: "55".repeat(32),
                epoch: "3".into(),
                tier_seed: "66".repeat(32),
            },
        }],
        witness_commitments: vec!["77".repeat(32), "88".repeat(32)],
        reputation_roots: vec!["99".repeat(32)],
        epoch: 3,
        slot: 9,
        quorum_bitmap_root: "aa".repeat(32),
        quorum_signature_root: "bb".repeat(32),
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
    assert_eq!(inputs.vrf_proofs.len(), 1);
    assert_eq!(inputs.witness_commitments.len(), 2);
    assert_eq!(inputs.reputation_roots.len(), 1);
    assert_eq!(inputs.epoch, sample_metadata().epoch);
    assert_eq!(inputs.slot, sample_metadata().slot);
    assert_eq!(
        inputs.quorum_bitmap_root,
        hex_to_array(&sample_metadata().quorum_bitmap_root)
    );

    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(&hex::decode(&certificate.metadata.vrf_entries[0].randomness).unwrap());
    assert_eq!(inputs.vrf_outputs[0], buffer);
}

fn hex_to_array(value: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hex::decode(value).unwrap());
    bytes
}
