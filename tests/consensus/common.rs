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

pub fn vrf_entry(randomness_byte: u8, proof_byte: u8, epoch: u64) -> ConsensusVrfEntry {
    let poseidon_seed = randomness_byte.wrapping_add(1);
    ConsensusVrfEntryBuilder::new()
        .with_randomness(digest(randomness_byte))
        .with_pre_output(pre_output(randomness_byte))
        .with_proof(proof_bytes(proof_byte))
        .with_public_key(digest(randomness_byte.wrapping_add(2)))
        .with_poseidon(
            ConsensusVrfPoseidonInputBuilder::new()
                .with_digest(digest(poseidon_seed))
                .with_last_block_header(digest(poseidon_seed.wrapping_add(1)))
                .with_epoch(format!("{epoch}"))
                .with_tier_seed(digest(poseidon_seed.wrapping_add(2)))
                .build(),
        )
        .build()
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
        entry.poseidon.last_block_header = block_hash_hex.to_string();
    }
}

pub struct ConsensusVrfEntryBuilder {
    randomness: String,
    pre_output: String,
    proof: String,
    public_key: String,
    poseidon: ConsensusVrfPoseidonInput,
}

impl ConsensusVrfEntryBuilder {
    pub fn new() -> Self {
        Self {
            randomness: digest(0x00),
            pre_output: pre_output(0x00),
            proof: proof_bytes(0x00),
            public_key: digest(0x00),
            poseidon: ConsensusVrfPoseidonInput::default(),
        }
    }

    pub fn with_randomness(mut self, randomness: String) -> Self {
        self.randomness = randomness;
        self
    }

    pub fn with_pre_output(mut self, pre_output: String) -> Self {
        self.pre_output = pre_output;
        self
    }

    pub fn with_proof(mut self, proof: String) -> Self {
        self.proof = proof;
        self
    }

    pub fn with_public_key(mut self, public_key: String) -> Self {
        self.public_key = public_key;
        self
    }

    pub fn with_poseidon(mut self, poseidon: ConsensusVrfPoseidonInput) -> Self {
        self.poseidon = poseidon;
        self
    }

    pub fn build(self) -> ConsensusVrfEntry {
        ConsensusVrfEntry {
            randomness: self.randomness,
            pre_output: self.pre_output,
            proof: self.proof,
            public_key: self.public_key,
            poseidon: self.poseidon,
        }
    }
}

pub struct ConsensusVrfPoseidonInputBuilder {
    digest: String,
    last_block_header: String,
    epoch: String,
    tier_seed: String,
}

impl ConsensusVrfPoseidonInputBuilder {
    pub fn new() -> Self {
        Self {
            digest: digest(0x00),
            last_block_header: digest(0x00),
            epoch: "0".into(),
            tier_seed: digest(0x00),
        }
    }

    pub fn with_digest(mut self, digest: String) -> Self {
        self.digest = digest;
        self
    }

    pub fn with_last_block_header(mut self, last_block_header: String) -> Self {
        self.last_block_header = last_block_header;
        self
    }

    pub fn with_epoch(mut self, epoch: String) -> Self {
        self.epoch = epoch;
        self
    }

    pub fn with_tier_seed(mut self, tier_seed: String) -> Self {
        self.tier_seed = tier_seed;
        self
    }

    pub fn build(self) -> ConsensusVrfPoseidonInput {
        ConsensusVrfPoseidonInput {
            digest: self.digest,
            last_block_header: self.last_block_header,
            epoch: self.epoch,
            tier_seed: self.tier_seed,
        }
    }
}
