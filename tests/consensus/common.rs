use rpp_chain::consensus::{ConsensusProofMetadata, ConsensusVrfEntry, ConsensusVrfPoseidonInput};
use rpp_crypto_vrf::{generate_vrf, PoseidonVrfInput, VrfSecretKey};
use std::convert::{TryFrom, TryInto};

const TEST_SECRET_KEY_BYTES: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

fn test_secret_key() -> VrfSecretKey {
    VrfSecretKey::try_from(TEST_SECRET_KEY_BYTES).expect("valid VRF secret key")
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    let bytes = hex::decode(value).expect("decode hex");
    let array: [u8; N] = bytes.as_slice().try_into().expect("hex length");
    array
}

fn build_vrf_entry(block_hash_hex: &str, epoch: u64, tier_seed_hex: &str) -> ConsensusVrfEntry {
    let input = PoseidonVrfInput::new(
        decode_hex::<32>(block_hash_hex),
        epoch,
        decode_hex::<32>(tier_seed_hex),
    );
    let secret = test_secret_key();
    let output = generate_vrf(&input, &secret).expect("generate vrf output");
    let public_key = secret.derive_public();

    ConsensusVrfEntry {
        randomness: hex::encode(output.randomness),
        pre_output: hex::encode(output.preoutput),
        proof: hex::encode(output.proof),
        public_key: hex::encode(public_key.to_bytes()),
        poseidon: ConsensusVrfPoseidonInput {
            digest: input.poseidon_digest_hex(),
            last_block_header: block_hash_hex.to_ascii_lowercase(),
            epoch: epoch.to_string(),
            tier_seed: tier_seed_hex.to_string(),
        },
    }
}

pub fn digest(byte: u8) -> String {
    hex::encode([byte; 32])
}

pub fn vrf_entry(randomness_byte: u8, proof_byte: u8, epoch: u64) -> ConsensusVrfEntry {
    let block_hash = digest(randomness_byte);
    let tier_seed = digest(proof_byte);
    build_vrf_entry(&block_hash, epoch, &tier_seed)
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
    ConsensusMetadataBuilder::new(epoch, slot)
        .with_vrf_entries(vrf_entries)
        .with_witness_commitments(witness_commitments)
        .with_reputation_roots(reputation_roots)
        .with_quorum_bitmap_root(quorum_bitmap_root)
        .with_quorum_signature_root(quorum_signature_root)
        .build()
}

pub struct ConsensusMetadataBuilder {
    vrf_entries: Vec<ConsensusVrfEntry>,
    witness_commitments: Vec<String>,
    reputation_roots: Vec<String>,
    epoch: u64,
    slot: u64,
    quorum_bitmap_root: String,
    quorum_signature_root: String,
}

impl ConsensusMetadataBuilder {
    pub fn new(epoch: u64, slot: u64) -> Self {
        Self {
            vrf_entries: Vec::new(),
            witness_commitments: Vec::new(),
            reputation_roots: Vec::new(),
            epoch,
            slot,
            quorum_bitmap_root: digest(0x00),
            quorum_signature_root: digest(0x00),
        }
    }

    pub fn with_vrf_entries(mut self, entries: Vec<ConsensusVrfEntry>) -> Self {
        self.vrf_entries = entries;
        self
    }

    pub fn with_witness_commitments(mut self, commitments: Vec<String>) -> Self {
        self.witness_commitments = commitments;
        self
    }

    pub fn with_reputation_roots(mut self, roots: Vec<String>) -> Self {
        self.reputation_roots = roots;
        self
    }

    pub fn with_quorum_bitmap_root(mut self, root: String) -> Self {
        self.quorum_bitmap_root = root;
        self
    }

    pub fn with_quorum_signature_root(mut self, root: String) -> Self {
        self.quorum_signature_root = root;
        self
    }

    pub fn build(self) -> ConsensusProofMetadata {
        ConsensusProofMetadata {
            vrf_entries: self.vrf_entries,
            witness_commitments: self.witness_commitments,
            reputation_roots: self.reputation_roots,
            epoch: self.epoch,
            slot: self.slot,
            quorum_bitmap_root: self.quorum_bitmap_root,
            quorum_signature_root: self.quorum_signature_root,
        }
    }
}

pub fn align_poseidon_last_block_header(
    metadata: &mut ConsensusProofMetadata,
    block_hash_hex: &str,
) {
    for entry in metadata.vrf_entries.iter_mut() {
        recompute_vrf_entry(entry, block_hash_hex);
    }
}

fn recompute_vrf_entry(entry: &mut ConsensusVrfEntry, block_hash_hex: &str) {
    let epoch = entry
        .poseidon
        .epoch
        .parse::<u64>()
        .expect("poseidon epoch parse");
    let tier_seed_hex = entry.poseidon.tier_seed.clone();
    let input = PoseidonVrfInput::new(
        decode_hex::<32>(block_hash_hex),
        epoch,
        decode_hex::<32>(&tier_seed_hex),
    );
    let secret = test_secret_key();
    let output = generate_vrf(&input, &secret).expect("generate vrf output");
    let public_key = secret.derive_public();

    entry.randomness = hex::encode(output.randomness);
    entry.pre_output = hex::encode(output.preoutput);
    entry.proof = hex::encode(output.proof);
    entry.public_key = hex::encode(public_key.to_bytes());
    entry.poseidon.digest = input.poseidon_digest_hex();
    entry.poseidon.last_block_header = block_hash_hex.to_ascii_lowercase();
}
