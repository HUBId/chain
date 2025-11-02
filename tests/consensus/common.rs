use rpp_chain::consensus::{ConsensusProofMetadata, ConsensusVrfEntry, ConsensusVrfPoseidonInput};
use rpp_crypto_vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};

pub fn digest(byte: u8) -> String {
    hex::encode([byte; 32])
}

pub fn pre_output(byte: u8) -> String {
    hex::encode(vec![byte; VRF_PREOUTPUT_LENGTH])
}

pub fn proof_bytes(byte: u8) -> String {
    hex::encode(vec![byte; VRF_PROOF_LENGTH])
}

pub fn vrf_entry(randomness_byte: u8, proof_byte: u8) -> ConsensusVrfEntry {
    let poseidon_seed = randomness_byte.wrapping_add(1);
    ConsensusVrfEntry {
        randomness: digest(randomness_byte),
        pre_output: pre_output(randomness_byte),
        proof: proof_bytes(proof_byte),
        public_key: digest(randomness_byte.wrapping_add(2)),
        poseidon: ConsensusVrfPoseidonInput {
            digest: digest(poseidon_seed),
            last_block_header: digest(poseidon_seed.wrapping_add(1)),
            epoch: format!("{}", poseidon_seed),
            tier_seed: digest(poseidon_seed.wrapping_add(2)),
        },
    }
}

pub fn metadata_fixture(
    vrf_entries: Vec<ConsensusVrfEntry>,
    witness_commitments: Vec<String>,
    reputation_roots: Vec<String>,
    epoch: u64,
    slot: u64,
    quorum_bitmap_root: String,
    quorum_signature_root: String,
) -> ConsensusProofMetadata {
    ConsensusProofMetadata {
        vrf_entries,
        witness_commitments,
        reputation_roots,
        epoch,
        slot,
        quorum_bitmap_root,
        quorum_signature_root,
    }
}
