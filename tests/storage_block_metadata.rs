use ed25519_dalek::Signature;
use rpp_chain::consensus::ConsensusCertificate;
use rpp_chain::errors::ChainError;
use rpp_chain::reputation::{ReputationWeights, Tier};
use rpp_chain::rpp::{ModuleWitnessBundle, ProofArtifact};
use rpp_chain::storage::Storage;
use rpp_chain::stwo::circuit::{
    pruning::PruningWitness, recursive::RecursiveWitness, state::StateWitness, ExecutionTrace,
};
use rpp_chain::stwo::params::{FieldElement, StarkParameters};
use rpp_pruning::{
    TaggedDigest, DIGEST_LENGTH, DOMAIN_TAG_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG,
};
use rpp_chain::stwo::proof::{
    CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
};
use rpp_chain::types::{
    AttestedIdentityRequest, Block, BlockHeader, BlockMetadata, BlockProofBundle, ChainProof,
    ProofSystem, PruningProof, PruningProofExt, RecursiveProof, SignedTransaction,
    pruning_from_previous,
};
use storage_firewood::kv::FirewoodKv;
use tempfile::tempdir;

fn dummy_state_proof() -> StarkProof {
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

fn dummy_pruning_proof() -> StarkProof {
    let parameters = StarkParameters::blueprint_default();
    let hasher = parameters.poseidon_hasher();
    let zero = FieldElement::zero(parameters.modulus());
    let pruning_binding_digest =
        TaggedDigest::new(ENVELOPE_TAG, [0x44; DIGEST_LENGTH]).prefixed_bytes();
    let pruning_segment_commitments = vec![
        TaggedDigest::new(PROOF_SEGMENT_TAG, [0x55; DIGEST_LENGTH]).prefixed_bytes(),
    ];
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

fn dummy_recursive_proof(
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

fn make_block(height: u64, previous: Option<&Block>) -> Block {
    let previous_hash = previous
        .map(|block| block.hash.clone())
        .unwrap_or_else(|| hex::encode([0u8; 32]));
    let mut tx_leaves: Vec<[u8; 32]> = Vec::new();
    let tx_root = hex::encode(rpp_chain::state::merkle::compute_merkle_root(
        &mut tx_leaves,
    ));
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
        state_root,
        utxo_root,
        reputation_root,
        timetoke_root,
        zsi_root,
        proof_root,
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
    let pruning_segment_commitments = pruning_proof
        .segments()
        .iter()
        .map(|segment| segment.segment_commitment().prefixed_bytes())
        .collect();
    let recursive_proof = RecursiveProof::from_parts(
        ProofSystem::Stwo,
        "99".repeat(32),
        None,
        pruning_binding_digest,
        pruning_segment_commitments,
        ChainProof::Stwo(dummy_recursive_proof(
            None,
            "99".repeat(32),
            &header,
            &pruning_proof,
        )),
    )
    .expect("construct recursive proof");
    let state_stark = dummy_state_proof();
    let pruning_stark = dummy_pruning_proof();
    let recursive_chain_proof = ChainProof::Stwo(dummy_recursive_proof(
        recursive_proof.previous_commitment.clone(),
        recursive_proof.commitment.clone(),
        &header,
        &pruning_proof,
    ));
    let module_witnesses = ModuleWitnessBundle::default();
    let proof_artifacts = Vec::<ProofArtifact>::new();
    let stark_bundle = BlockProofBundle::new(
        Vec::new(),
        ChainProof::Stwo(state_stark),
        ChainProof::Stwo(pruning_stark),
        recursive_chain_proof,
    );
    let signature = Signature::from_bytes(&[0u8; 64]).expect("signature bytes");
    let mut consensus = ConsensusCertificate::genesis();
    consensus.round = height;
    Block::new(
        header,
        Vec::<AttestedIdentityRequest>::new(),
        Vec::<SignedTransaction>::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
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

#[test]
fn storage_persists_extended_block_metadata() {
    let temp_dir = tempdir().expect("tempdir");
    let storage = Storage::open(temp_dir.path()).expect("open storage");
    let genesis = make_block(0, None);
    let metadata = BlockMetadata::from(&genesis);
    storage
        .store_block(&genesis, &metadata)
        .expect("store genesis");
    drop(storage);

    let reopened = Storage::open(temp_dir.path()).expect("reopen storage");
    let persisted = reopened
        .read_block_metadata(genesis.header.height)
        .expect("read metadata")
        .expect("metadata present");
    assert_eq!(persisted.proof_hash, genesis.header.proof_root);
    assert_eq!(
        persisted.pruning_binding_digest,
        genesis
            .pruning_proof
            .binding_digest()
            .prefixed_bytes()
    );
    let expected_segments: Vec<_> = genesis
        .pruning_proof
        .segments()
        .iter()
        .map(|segment| segment.segment_commitment().prefixed_bytes())
        .collect();
    assert_eq!(persisted.pruning_segment_commitments, expected_segments);
    assert_eq!(
        persisted.pruning_binding_digest,
        metadata.pruning_binding_digest
    );
    assert_eq!(
        persisted.pruning_segment_commitments,
        metadata.pruning_segment_commitments
    );
    assert_eq!(persisted.previous_state_root, metadata.previous_state_root);
    assert_eq!(persisted.new_state_root, metadata.new_state_root);
    let persisted_pruning = persisted
        .pruning_metadata()
        .expect("persisted pruning metadata");
    let expected_pruning = metadata
        .pruning_metadata()
        .expect("expected pruning metadata");
    assert_eq!(
        persisted_pruning
            .snapshot
            .state_commitment
            .as_str(),
        expected_pruning
            .snapshot
            .state_commitment
            .as_str()
    );
    assert_eq!(
        persisted_pruning
            .segments
            .get(0)
            .map(|segment| segment.segment_commitment.as_str()),
        expected_pruning
            .segments
            .get(0)
            .map(|segment| segment.segment_commitment.as_str()),
    );
    let expected_segment_hex: Vec<_> = genesis
        .pruning_proof
        .segments()
        .iter()
        .map(|segment| hex::encode(segment.segment_commitment().prefixed_bytes()))
        .collect();
    assert_eq!(persisted_pruning.segments.len(), expected_segment_hex.len());
    for (segment, expected_hex) in persisted_pruning
        .segments
        .iter()
        .zip(expected_segment_hex.iter())
    {
        assert_eq!(segment.segment_commitment.as_str(), expected_hex);
    }
    assert_eq!(
        persisted_pruning.binding_digest.as_str(),
        expected_pruning.binding_digest.as_str()
    );
    assert_eq!(
        persisted_pruning
            .commitment
            .aggregate_commitment
            .as_str(),
        expected_pruning
            .commitment
            .aggregate_commitment
            .as_str()
    );
    let expected_binding =
        hex::encode(genesis.pruning_proof.binding_digest().prefixed_bytes());
    assert_eq!(persisted_pruning.binding_digest.as_str(), expected_binding);
    let expected_commitment = hex::encode(
        genesis
            .pruning_proof
            .aggregate_commitment()
            .prefixed_bytes()
    );
    assert_eq!(
        persisted_pruning
            .commitment
            .aggregate_commitment
            .as_str(),
        expected_commitment
    );
}

#[test]
fn storage_rejects_corrupted_block_metadata() {
    let temp_dir = tempdir().expect("tempdir");
    let storage = Storage::open(temp_dir.path()).expect("open storage");
    let genesis = make_block(0, None);
    let metadata = BlockMetadata::from(&genesis);
    storage
        .store_block(&genesis, &metadata)
        .expect("store genesis");
    drop(storage);

    let mut kv = FirewoodKv::open(temp_dir.path()).expect("open kv");
    let mut suffix = Vec::from(b"block_metadata/".as_slice());
    suffix.extend_from_slice(&genesis.header.height.to_be_bytes());
    let mut key = Vec::with_capacity(1 + suffix.len());
    key.push(b'm');
    key.extend_from_slice(&suffix);
    kv.put(key, vec![0xFF]);
    kv.commit().expect("commit corruption");
    drop(kv);

    let reopened = Storage::open(temp_dir.path()).expect("reopen storage");
    let err = reopened
        .read_block_metadata(genesis.header.height)
        .expect_err("corrupted metadata should fail");
    assert!(matches!(err, ChainError::Serialization(_)));
}
