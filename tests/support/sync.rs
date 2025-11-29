use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::Signature;
use rpp_chain::consensus::ConsensusCertificate;
use rpp_chain::errors::{ChainError, ChainResult};
use rpp_chain::reputation::{ReputationWeights, Tier};
use rpp_chain::rpp::{ModuleWitnessBundle, ProofArtifact};
use rpp_chain::runtime::sync::{
    PayloadProvider, ReconstructionEngine, ReconstructionRequest, StateSyncPlan,
};
#[cfg(feature = "backend-rpp-stark")]
use rpp_chain::runtime::types::RppStarkProof;
use rpp_chain::runtime::types::{
    pruning_from_previous, AttestedIdentityRequest, Block, BlockHeader, BlockMetadata,
    BlockPayload, BlockProofBundle, ChainProof, PruningProof, PruningProofExt, RecursiveProof,
    ReputationUpdate, SignedBftVote, SignedTransaction, TimetokeUpdate, UptimeProof,
};
use rpp_chain::state::merkle::compute_merkle_root;
use rpp_chain::storage::Storage;
use rpp_chain::stwo::aggregation::StateCommitmentSnapshot;
use rpp_chain::stwo::circuit::{
    pruning::PruningWitness, recursive::RecursiveWitness, state::StateWitness, ExecutionTrace,
};
use rpp_chain::stwo::params::{FieldElement, StarkParameters};
use rpp_chain::stwo::proof::{
    CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
};
use rpp_p2p::{
    NetworkLightClientUpdate, NetworkStateSyncChunk, NetworkStateSyncPlan, NetworkTaggedDigestHex,
};
use rpp_pruning::{
    TaggedDigest, DIGEST_LENGTH, DOMAIN_TAG_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG,
};

/// In-memory payload provider used to feed reconstructed payloads back into the engine.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPayloadProvider {
    payloads: HashMap<u64, BlockPayload>,
}

impl InMemoryPayloadProvider {
    pub fn new(payloads: HashMap<u64, BlockPayload>) -> Self {
        Self { payloads }
    }

    pub fn from_blocks(blocks: &[Block]) -> Self {
        let payloads = blocks
            .iter()
            .map(|block| (block.header.height, BlockPayload::from_block(block)))
            .collect();
        Self { payloads }
    }
}

impl PayloadProvider for InMemoryPayloadProvider {
    fn fetch_payload(&self, request: &ReconstructionRequest) -> ChainResult<BlockPayload> {
        self.payloads.get(&request.height).cloned().ok_or_else(|| {
            ChainError::Config(format!("missing payload for height {}", request.height))
        })
    }
}

/// Snapshot artefacts captured from a reconstruction plan.
#[derive(Clone, Debug)]
pub struct StateSyncArtifacts {
    pub plan: StateSyncPlan,
    pub network_plan: NetworkStateSyncPlan,
    pub chunk_messages: Vec<NetworkStateSyncChunk>,
    pub updates: Vec<NetworkLightClientUpdate>,
}

impl StateSyncArtifacts {
    pub fn requests(&self) -> impl Iterator<Item = &ReconstructionRequest> {
        self.plan
            .chunks
            .iter()
            .flat_map(|chunk| chunk.requests.iter())
    }
}

/// Collects the state-sync artefacts emitted by the engine for the configured chunk size.
pub fn collect_state_sync_artifacts(
    engine: &ReconstructionEngine,
    chunk_size: usize,
) -> ChainResult<StateSyncArtifacts> {
    let plan = engine.state_sync_plan(chunk_size)?;
    let network_plan = plan.to_network_plan()?;
    let chunk_messages = plan.chunk_messages()?;
    let updates = plan.light_client_messages()?;
    Ok(StateSyncArtifacts {
        plan,
        network_plan,
        chunk_messages,
        updates,
    })
}

/// Stores the provided blocks, prunes their payloads, and returns the captured payload map.
pub fn install_pruned_chain(
    storage: &Storage,
    blocks: &[Block],
) -> ChainResult<HashMap<u64, BlockPayload>> {
    let mut payloads = HashMap::new();
    for block in blocks {
        let metadata = BlockMetadata::from(block);
        storage.store_block(block, &metadata)?;
        payloads.insert(block.header.height, BlockPayload::from_block(block));
        let _ = storage.prune_block_payload(block.header.height)?;
    }
    Ok(payloads)
}

/// Generates a deterministic dummy block suitable for storage and reconstruction tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestProofBackend {
    Stwo,
    #[cfg(feature = "backend-rpp-stark")]
    RppStark,
}

pub fn make_dummy_block(height: u64, previous: Option<&Block>) -> Block {
    make_dummy_block_with_backend(height, previous, TestProofBackend::Stwo)
}

pub fn make_dummy_block_with_backend(
    height: u64,
    previous: Option<&Block>,
    backend: TestProofBackend,
) -> Block {
    let previous_hash = previous
        .map(|block| block.hash.clone())
        .unwrap_or_else(|| hex::encode([0u8; 32]));
    let mut tx_leaves: Vec<[u8; 32]> = Vec::new();
    let tx_root = hex::encode(compute_merkle_root(&mut tx_leaves));
    let state_root = hex::encode([height as u8 + 2; 32]);
    let utxo_root = hex::encode([height as u8 + 3; 32]);
    let reputation_root = hex::encode([height as u8 + 4; 32]);
    let timetoke_root = hex::encode([height as u8 + 5; 32]);
    let zsi_root = hex::encode([height as u8 + 6; 32]);
    let proof_root = hex::encode([height as u8 + 7; 32]);
    let header = BlockHeader::new(
        height,
        previous_hash,
        tx_root,
        state_root.clone(),
        utxo_root.clone(),
        reputation_root.clone(),
        timetoke_root.clone(),
        zsi_root.clone(),
        proof_root.clone(),
        "0".to_string(),
        height.to_string(),
        vec![height as u8; 32],
        hex::encode([height as u8 + 8; 32]),
        hex::encode([height as u8 + 9; 32]),
        hex::encode([height as u8 + 10; 32]),
        hex::encode([height as u8 + 11; 32]),
        hex::encode([height as u8 + 12; 32]),
        hex::encode([height as u8 + 13; 32]),
    );
    let pruning_proof = pruning_from_previous(previous, &header);
    let pruning_binding_digest = pruning_proof.binding_digest().prefixed_bytes();
    let pruning_segment_commitments: Vec<_> = pruning_proof
        .segments()
        .iter()
        .map(|segment| segment.segment_commitment().prefixed_bytes())
        .collect();

    let recursive_commitment = format!("{:064x}", height + 0x99);
    let recursive_previous = previous
        .map(|block| block.recursive_proof.commitment.clone())
        .or_else(|| Some(RecursiveProof::anchor()));

    let (state_proof, pruning_chain, recursive_chain, recursive_proof) = match backend {
        TestProofBackend::Stwo => {
            let recursive_proof = RecursiveProof::from_parts(
                rpp_chain::runtime::types::ProofSystem::Stwo,
                recursive_commitment.clone(),
                None,
                pruning_binding_digest,
                pruning_segment_commitments.clone(),
                ChainProof::Stwo(dummy_recursive_proof(
                    None,
                    recursive_commitment.clone(),
                    &header,
                    &pruning_proof,
                )),
            )
            .expect("construct recursive proof");

            (
                ChainProof::Stwo(dummy_state_proof()),
                ChainProof::Stwo(dummy_pruning_proof()),
                ChainProof::Stwo(dummy_recursive_proof(
                    recursive_proof.previous_commitment.clone(),
                    recursive_proof.commitment.clone(),
                    &header,
                    &pruning_proof,
                )),
                recursive_proof,
            )
        }
        #[cfg(feature = "backend-rpp-stark")]
        TestProofBackend::RppStark => {
            let params = vec![0xAA, 0x10, height as u8];
            let public_inputs = format!("pruning-{height}").into_bytes();
            let proof_bytes = vec![0xBB, 0x20, height as u8];
            let recursive_proof = RecursiveProof {
                system: rpp_chain::runtime::types::ProofSystem::RppStark,
                commitment: recursive_commitment.clone(),
                previous_commitment: recursive_previous,
                pruning_binding_digest,
                pruning_segment_commitments: pruning_segment_commitments.clone(),
                proof: ChainProof::RppStark(RppStarkProof::new(
                    params.clone(),
                    public_inputs.clone(),
                    proof_bytes.clone(),
                )),
            };

            (
                ChainProof::RppStark(RppStarkProof::new(
                    params.clone(),
                    public_inputs.clone(),
                    proof_bytes.clone(),
                )),
                ChainProof::RppStark(RppStarkProof::new(
                    params.clone(),
                    public_inputs.clone(),
                    proof_bytes.clone(),
                )),
                ChainProof::RppStark(RppStarkProof::new(params, public_inputs, proof_bytes)),
                recursive_proof,
            )
        }
    };
    let module_witnesses = ModuleWitnessBundle::default();
    let proof_artifacts = Vec::<ProofArtifact>::new();
    let stark_bundle =
        BlockProofBundle::new(Vec::new(), state_proof, pruning_chain, recursive_chain);
    let signature = ed25519_dalek::Signature::from_bytes(&[0u8; 64]).expect("signature bytes");
    let mut consensus = ConsensusCertificate::genesis();
    consensus.round = height;
    Block::new(
        header,
        Vec::<AttestedIdentityRequest>::new(),
        Vec::<SignedTransaction>::new(),
        Vec::<UptimeProof>::new(),
        Vec::<TimetokeUpdate>::new(),
        Vec::<ReputationUpdate>::new(),
        Vec::<SignedBftVote>::new(),
        module_witnesses,
        proof_artifacts,
        pruning_proof,
        recursive_proof,
        stark_bundle,
        signature,
        consensus,
        None,
    )
}

/// Produces a genesis pruning proof for the provided state root.
pub fn dummy_state_proof() -> StarkProof {
    StarkProof {
        kind: ProofKind::State,
        commitment: "11".repeat(32),
        public_inputs: Vec::new(),
        payload: ProofPayload::State(StateWitness {
            prev_state_root: "22".repeat(32),
            new_state_root: "33".repeat(32),
            identities: Vec::new(),
            transactions: Vec::new(),
            accounts_before: Vec::new(),
            accounts_after: Vec::new(),
            required_tier: Tier::Tl0,
            reputation_weights: ReputationWeights::default(),
        }),
        trace: ExecutionTrace {
            segments: Vec::new(),
        },
        commitment_proof: CommitmentSchemeProofData::default(),
        fri_proof: FriProof::default(),
    }
}

/// Builds a deterministic pruning proof witness for tests.
pub fn dummy_pruning_proof() -> StarkProof {
    let parameters = StarkParameters::blueprint_default();
    let hasher = parameters.poseidon_hasher();
    let zero = FieldElement::zero(parameters.modulus());
    let pruning_binding_digest =
        TaggedDigest::new(ENVELOPE_TAG, [0x44; DIGEST_LENGTH]).prefixed_bytes();
    let pruning_segment_commitments =
        vec![TaggedDigest::new(PROOF_SEGMENT_TAG, [0x55; DIGEST_LENGTH]).prefixed_bytes()];
    let pruning_fold = {
        let mut accumulator = zero.clone();
        let binding_element = parameters.element_from_bytes(&pruning_binding_digest);
        accumulator = hasher.hash(&[accumulator.clone(), binding_element, zero.clone()]);
        for digest in &pruning_segment_commitments {
            let element = parameters.element_from_bytes(digest);
            accumulator = hasher.hash(&[accumulator.clone(), element, zero.clone()]);
        }
        accumulator.to_hex()
    };

    StarkProof {
        kind: ProofKind::Pruning,
        commitment: "44".repeat(32),
        public_inputs: Vec::new(),
        payload: ProofPayload::Pruning(PruningWitness {
            previous_tx_root: "55".repeat(32),
            pruned_tx_root: "66".repeat(32),
            original_transactions: Vec::new(),
            removed_transactions: Vec::new(),
            pruning_binding_digest,
            pruning_segment_commitments,
            pruning_fold,
        }),
        trace: ExecutionTrace {
            segments: Vec::new(),
        },
        commitment_proof: CommitmentSchemeProofData::default(),
        fri_proof: FriProof::default(),
    }
}

/// Constructs a deterministic recursive proof witness for tests.
pub fn dummy_recursive_proof(
    previous_commitment: Option<String>,
    aggregated_commitment: String,
    header: &BlockHeader,
    pruning: &PruningProof,
) -> StarkProof {
    let previous_commitment = previous_commitment.or_else(|| Some(RecursiveProof::anchor()));
    let pruning_binding_digest = pruning.binding_digest().prefixed_bytes();
    let pruning_segment_commitments = pruning
        .segments()
        .iter()
        .map(|segment| segment.segment_commitment().prefixed_bytes())
        .collect();
    StarkProof {
        kind: ProofKind::Recursive,
        commitment: aggregated_commitment.clone(),
        public_inputs: Vec::new(),
        payload: ProofPayload::Recursive(RecursiveWitness {
            previous_commitment,
            aggregated_commitment,
            identity_commitments: Vec::new(),
            tx_commitments: Vec::new(),
            uptime_commitments: Vec::new(),
            consensus_commitments: Vec::new(),
            state_commitment: header.state_root.clone(),
            global_state_root: header.state_root.clone(),
            utxo_root: header.utxo_root.clone(),
            reputation_root: header.reputation_root.clone(),
            timetoke_root: header.timetoke_root.clone(),
            zsi_root: header.zsi_root.clone(),
            proof_root: header.proof_root.clone(),
            pruning_binding_digest,
            pruning_segment_commitments,
            block_height: header.height,
        }),
        trace: ExecutionTrace {
            segments: Vec::new(),
        },
        commitment_proof: CommitmentSchemeProofData::default(),
        fri_proof: FriProof::default(),
    }
}

/// Flips the last hexadecimal digit of the provided string while preserving length.
pub fn mutate_hex(value: &str) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = match *last {
            '0' => '1',
            '1' => '2',
            '2' => '3',
            '3' => '4',
            '4' => '5',
            '5' => '6',
            '6' => '7',
            '7' => '8',
            '8' => '9',
            '9' => 'a',
            'a' => 'b',
            'b' => 'c',
            'c' => 'd',
            'd' => 'e',
            'e' => 'f',
            'f' => '0',
            other => {
                debug_assert!(false, "unexpected hex digit: {other}");
                '0'
            }
        };
    }
    chars.into_iter().collect()
}

/// Mutates a base64 payload deterministically while keeping it valid.
pub fn mutate_base64(value: &str) -> String {
    let mut bytes = BASE64
        .decode(value.as_bytes())
        .unwrap_or_else(|_| value.as_bytes().to_vec());
    if let Some(first) = bytes.first_mut() {
        *first ^= 0x01;
    }
    BASE64.encode(bytes)
}

/// Returns a cloned chunk with the aggregate commitment flipped.
pub fn corrupt_chunk_commitment(chunk: &NetworkStateSyncChunk) -> NetworkStateSyncChunk {
    let mut corrupted = chunk.clone();
    if let Some(request) = corrupted.requests.first_mut() {
        let current = request
            .pruning
            .commitment
            .aggregate_commitment
            .as_str()
            .to_owned();
        request.pruning.commitment.aggregate_commitment =
            NetworkTaggedDigestHex::from(mutate_hex(&current));
    }
    corrupted
}

/// Returns a cloned chunk with its first merkle proof mutated.
pub fn corrupt_chunk_proof(chunk: &NetworkStateSyncChunk) -> NetworkStateSyncChunk {
    let mut corrupted = chunk.clone();
    if let Some(proof) = corrupted.proofs.first_mut() {
        *proof = mutate_base64(proof);
    }
    corrupted
}

/// Returns a cloned light client update with a mutated commitment.
pub fn corrupt_light_client_commitment(
    update: &NetworkLightClientUpdate,
) -> NetworkLightClientUpdate {
    let mut corrupted = update.clone();
    corrupted.proof_commitment = mutate_hex(&corrupted.proof_commitment);
    corrupted
}

/// Encodes a `StateCommitmentSnapshot` for convenience in tests.
pub fn snapshot_from_block(block: &Block) -> StateCommitmentSnapshot {
    StateCommitmentSnapshot::from_header_fields(
        block.header.height,
        &block.header.previous_hash,
        &block.header.state_root,
        &block.header.tx_root,
    )
    .expect("snapshot from block")
}
