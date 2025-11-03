use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use libp2p::identity::Keypair;
use libp2p::PeerId;
use rpp_crypto_vrf::{
    derive_tier_seed, generate_vrf, PoseidonVrfInput, VrfKeypair, VrfSecretKey,
    VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH,
};

use super::bft_loop::{run_bft_loop, shutdown, submit_precommit, submit_prevote, submit_proposal};
use super::evidence::EvidenceType;
#[cfg(feature = "prover-stwo")]
use super::leader::{Leader, LeaderContext};
use super::messages::{
    compute_consensus_bindings, Block, BlockId, ConsensusCertificate, ConsensusProof,
    ConsensusProofMetadata, ConsensusVrfEntry, ConsensusVrfPoseidonInput, PreCommit, PreVote,
    ProofVerificationError, Proposal, TalliedVote,
};
#[cfg(feature = "prover-stwo")]
use super::messages::{Commit, Signature};
use super::state::{ConsensusConfig, GenesisConfig, TreasuryAccounts, WitnessPoolWeights};

use super::validator::{
    select_leader, select_validators, StakeInfo, VRFOutput, Validator, ValidatorLedgerEntry,
};

use crate::proof_backend::{
    BackendError, BackendResult, ConsensusCircuitDef, ConsensusPublicInputs,
    ConsensusVrfPublicEntry, ProofBackend, ProofBytes, ProofHeader, ProofSystemKind, VerifyingKey,
    WitnessBytes,
};

#[cfg(feature = "prover-mock")]
use prover_mock_backend::MockBackend;
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::backend::{decode_consensus_proof, StwoBackend};
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::official::verifier::NodeVerifier;
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::types::ChainProof;

fn sample_seed(id: &str) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let id_bytes = id.as_bytes();
    let len = id_bytes.len().min(32);
    seed[..len].copy_from_slice(&id_bytes[..len]);
    seed
}

fn build_vrf_output(
    epoch: u64,
    id: &str,
    _output: [u8; 32],
    tier: u8,
    score: f64,
    timetoken: u64,
) -> VRFOutput {
    let seed = sample_seed(id);
    let tier_seed = derive_tier_seed(&id.to_string(), timetoken);
    let keypair = deterministic_keypair(id);
    let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
    let vrf_output = generate_vrf(&input, &keypair.secret).expect("generate vrf output");
    VRFOutput {
        validator_id: id.to_string(),
        output: vrf_output.randomness,
        preoutput: vrf_output.preoutput.to_vec(),
        proof: vrf_output.proof.to_vec(),
        reputation_tier: tier,
        reputation_score: score,
        timetoken_balance: timetoken,
        seed,
        public_key: keypair.public.to_bytes().to_vec(),
    }
}

fn deterministic_keypair(id: &str) -> VrfKeypair {
    let mut hash = blake3::hash(id.as_bytes()).as_bytes().to_vec();
    hash.resize(32, 0);
    let mut tweak = 0u8;
    loop {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        bytes[0] ^= tweak;
        if let Ok(secret) = VrfSecretKey::try_from(bytes) {
            let public = secret.derive_public();
            return VrfKeypair { public, secret };
        }
        tweak = tweak.wrapping_add(1);
        if tweak == 0 {
            panic!("failed to derive deterministic VRF keypair");
        }
    }
}

fn sample_vrf_entry(randomness_byte: u8, proof_byte: u8, epoch: u64) -> ConsensusVrfEntry {
    let poseidon_seed = randomness_byte.wrapping_add(1);
    ConsensusVrfEntry {
        randomness: hex::encode([randomness_byte; 32]),
        pre_output: hex::encode(vec![randomness_byte; rpp_crypto_vrf::VRF_PREOUTPUT_LENGTH]),
        proof: hex::encode(vec![proof_byte; rpp_crypto_vrf::VRF_PROOF_LENGTH]),
        public_key: hex::encode([randomness_byte.wrapping_add(2); 32]),
        poseidon: ConsensusVrfPoseidonInput {
            digest: hex::encode([poseidon_seed; 32]),
            last_block_header: hex::encode([poseidon_seed.wrapping_add(1); 32]),
            epoch: format!("{epoch}"),
            tier_seed: hex::encode([poseidon_seed.wrapping_add(2); 32]),
        },
    }
}

fn sample_certificate_metadata(epoch: u64, slot: u64) -> ConsensusProofMetadata {
    ConsensusProofMetadata {
        vrf_entries: vec![sample_vrf_entry(0x11, 0x22, epoch)],
        witness_commitments: vec!["33".repeat(32)],
        reputation_roots: vec!["44".repeat(32)],
        epoch,
        slot,
        quorum_bitmap_root: "55".repeat(32),
        quorum_signature_root: "66".repeat(32),
    }
}

fn align_poseidon_last_block_header(metadata: &mut ConsensusProofMetadata, block_hash_hex: &str) {
    for entry in metadata.vrf_entries.iter_mut() {
        entry.poseidon.last_block_header = block_hash_hex.to_string();
    }
}

fn decode_digest_hex(value: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hex::decode(value).expect("decode digest"));
    bytes
}

fn decode_array_hex<const N: usize>(value: &str) -> [u8; N] {
    let bytes = hex::decode(value).expect("decode array");
    assert_eq!(bytes.len(), N, "unexpected byte length");
    let mut buffer = [0u8; N];
    buffer.copy_from_slice(&bytes);
    buffer
}

fn decode_vec_hex(value: &str, expected: usize) -> Vec<u8> {
    let bytes = hex::decode(value).expect("decode vec");
    assert_eq!(bytes.len(), expected, "unexpected byte length");
    bytes
}

fn sample_consensus_public_inputs(round: u64) -> ConsensusPublicInputs {
    let mut metadata = sample_certificate_metadata(5, round);
    let block_hash_hex = "aa".repeat(32);
    align_poseidon_last_block_header(&mut metadata, &block_hash_hex);
    let block_hash_bytes = decode_digest_hex(&block_hash_hex);
    let quorum_bitmap_root = decode_digest_hex(&metadata.quorum_bitmap_root);
    let quorum_signature_root = decode_digest_hex(&metadata.quorum_signature_root);
    let vrf_public_entries: Vec<ConsensusVrfPublicEntry> = metadata
        .vrf_entries
        .iter()
        .map(|entry| ConsensusVrfPublicEntry {
            randomness: decode_digest_hex(&entry.randomness),
            pre_output: decode_array_hex::<VRF_PREOUTPUT_LENGTH>(&entry.pre_output),
            proof: decode_vec_hex(&entry.proof, VRF_PROOF_LENGTH),
            public_key: decode_digest_hex(&entry.public_key),
            poseidon_digest: decode_digest_hex(&entry.poseidon.digest),
            poseidon_last_block_header: decode_digest_hex(&entry.poseidon.last_block_header),
            poseidon_epoch: entry.poseidon.epoch.parse().expect("decode poseidon epoch"),
            poseidon_tier_seed: decode_digest_hex(&entry.poseidon.tier_seed),
        })
        .collect();
    let witness_commitments: Vec<[u8; 32]> = metadata
        .witness_commitments
        .iter()
        .map(|value| decode_digest_hex(value))
        .collect();
    let reputation_roots: Vec<[u8; 32]> = metadata
        .reputation_roots
        .iter()
        .map(|value| decode_digest_hex(value))
        .collect();

    let bindings = compute_consensus_bindings(
        &block_hash_bytes,
        &vrf_public_entries,
        &witness_commitments,
        &reputation_roots,
        &quorum_bitmap_root,
        &quorum_signature_root,
    )
    .expect("bindings");

    ConsensusPublicInputs {
        block_hash: block_hash_bytes,
        round,
        leader_proposal: block_hash_bytes,
        epoch: metadata.epoch,
        slot: metadata.slot,
        quorum_threshold: 1,
        quorum_bitmap_root,
        quorum_signature_root,
        vrf_entries: vrf_public_entries,
        witness_commitments,
        reputation_roots,
        vrf_output_binding: bindings.vrf_output,
        vrf_proof_binding: bindings.vrf_proof,
        witness_commitment_binding: bindings.witness_commitment,
        reputation_root_binding: bindings.reputation_root,
        quorum_bitmap_binding: bindings.quorum_bitmap,
        quorum_signature_binding: bindings.quorum_signature,
    }
}

#[derive(Default, Clone)]
struct FixtureBackend {
    fail: bool,
}

impl FixtureBackend {
    fn new() -> Self {
        Self { fail: false }
    }

    fn failing() -> Self {
        Self { fail: true }
    }
}

impl ProofBackend for FixtureBackend {
    fn name(&self) -> &'static str {
        "consensus-fixture"
    }

    fn verify_consensus(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        circuit: &ConsensusCircuitDef,
        _public_inputs: &ConsensusPublicInputs,
    ) -> BackendResult<()> {
        if self.fail {
            return Err(BackendError::Failure("forced failure".into()));
        }
        if vk.as_slice().is_empty() {
            return Err(BackendError::Failure("verifying key empty".into()));
        }
        if proof.as_slice().is_empty() {
            return Err(BackendError::Failure("proof bytes empty".into()));
        }
        if circuit.identifier.trim().is_empty() {
            return Err(BackendError::Failure("circuit identifier empty".into()));
        }
        Ok(())
    }

    fn prove_consensus(
        &self,
        witness: &WitnessBytes,
    ) -> BackendResult<(ProofBytes, VerifyingKey, ConsensusCircuitDef)> {
        if self.fail {
            return Err(BackendError::Failure("forced failure".into()));
        }
        let digest = blake3::hash(witness.as_slice());
        let identifier = format!("fixture.consensus.{}", digest.to_hex());
        let circuit = ConsensusCircuitDef::new(identifier.clone());
        let header = ProofHeader::new(ProofSystemKind::Mock, identifier.clone());
        let proof = ProofBytes::encode(&header, witness.as_slice())?;
        let verifying_key = VerifyingKey(identifier.into_bytes());
        Ok((proof, verifying_key, circuit))
    }
}

fn backend() -> Arc<dyn ProofBackend> {
    #[cfg(feature = "prover-mock")]
    {
        return Arc::new(MockBackend::new());
    }

    #[cfg(feature = "prover-stwo")]
    {
        return Arc::new(StwoBackend::new());
    }

    Arc::new(FixtureBackend::new())
}

fn failing_backend() -> Arc<dyn ProofBackend> {
    Arc::new(FixtureBackend::failing())
}

fn build_ledger(entries: &[(&str, u64, u8, f64)]) -> BTreeMap<String, ValidatorLedgerEntry> {
    entries
        .iter()
        .map(|(id, stake, tier, score)| {
            (
                (*id).to_string(),
                ValidatorLedgerEntry {
                    stake: *stake,
                    reputation_tier: *tier,
                    reputation_score: *score,
                },
            )
        })
        .collect()
}

fn make_vote_signature(
    peer: &PeerId,
    block_hash: &BlockId,
    round: u64,
    height: u64,
    phase: &str,
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&peer.to_bytes());
    hasher.update(block_hash.0.as_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(&height.to_le_bytes());
    hasher.update(phase.as_bytes());
    hasher.finalize().as_bytes().to_vec()
}

const CONSENSUS_VOTE_WEIGHTS: [(&str, u64); 3] =
    [("validator-1", 10), ("validator-2", 8), ("validator-3", 6)];

const CONSENSUS_DEFAULT_ROUND: u64 = 5;

fn deterministic_peer(id: &str) -> PeerId {
    let mut secret = sample_seed(&format!("peer:{id}"));
    let keypair = Keypair::ed25519_from_bytes(&mut secret).expect("peer key derivation");
    PeerId::from_public_key(&keypair.public())
}

fn build_tallied_votes(
    block_hash: &BlockId,
    round: u64,
    height: u64,
    phase: &str,
    weights: &[(&str, u64)],
) -> Vec<TalliedVote> {
    weights
        .iter()
        .map(|(validator_id, weight)| {
            let peer = deterministic_peer(validator_id);
            TalliedVote {
                validator_id: (*validator_id).to_string(),
                peer_id: peer.clone(),
                signature: make_vote_signature(&peer, block_hash, round, height, phase),
                voting_power: *weight,
            }
        })
        .collect()
}

fn quorum_threshold(total_power: u64) -> u64 {
    std::cmp::max(1, (total_power * 2) / 3)
}

#[cfg(feature = "prover-stwo")]
#[derive(Clone)]
struct ProofVerifierRegistry {
    stwo: NodeVerifier,
}

#[cfg(feature = "prover-stwo")]
impl Default for ProofVerifierRegistry {
    fn default() -> Self {
        Self {
            stwo: NodeVerifier::new(),
        }
    }
}

#[cfg(feature = "prover-stwo")]
impl ProofVerifierRegistry {
    fn verify_consensus(&self, proof: &ChainProof) -> Result<(), String> {
        self.stwo
            .verify_consensus(proof)
            .map_err(|err| err.to_string())
    }
}

fn certificate_for_block(block: &Block, round: u64) -> ConsensusCertificate {
    let block_hash = block.hash();
    let weights = &CONSENSUS_VOTE_WEIGHTS;
    let total_power: u64 = weights.iter().map(|(_, weight)| *weight).sum();
    let prevotes = build_tallied_votes(&block_hash, round, block.height, "prevote", weights);
    let precommits = build_tallied_votes(&block_hash, round, block.height, "precommit", weights);

    let mut metadata = sample_certificate_metadata(block.epoch, round);
    align_poseidon_last_block_header(&mut metadata, &block_hash.0);

    ConsensusCertificate {
        block_hash,
        height: block.height,
        round,
        total_power,
        quorum_threshold: quorum_threshold(total_power),
        prevote_power: total_power,
        precommit_power: total_power,
        commit_power: total_power,
        prevotes,
        precommits,
        metadata,
    }
}

fn build_prevote(
    validator: &Validator,
    peer: &PeerId,
    block_hash: &BlockId,
    round: u64,
    height: u64,
    proof_valid: bool,
) -> PreVote {
    PreVote {
        block_hash: block_hash.clone(),
        proof_valid,
        validator_id: validator.id.clone(),
        peer_id: peer.clone(),
        signature: make_vote_signature(peer, block_hash, round, height, "prevote"),
        height,
        round,
    }
}

fn build_precommit(
    validator: &Validator,
    peer: &PeerId,
    block_hash: &BlockId,
    round: u64,
    height: u64,
) -> PreCommit {
    PreCommit {
        block_hash: block_hash.clone(),
        validator_id: validator.id.clone(),
        peer_id: peer.clone(),
        signature: make_vote_signature(peer, block_hash, round, height, "precommit"),
        height,
        round,
    }
}

fn backend_system(backend: &dyn ProofBackend) -> ProofSystemKind {
    match backend.name() {
        "mock" => ProofSystemKind::Mock,
        "consensus-fixture" => ProofSystemKind::Mock,
        "stwo" => ProofSystemKind::Stwo,
        "plonky3" => ProofSystemKind::Plonky3,
        "plonky2" => ProofSystemKind::Plonky2,
        "halo2" => ProofSystemKind::Halo2,
        "rpp-stark" => ProofSystemKind::RppStark,
        _ => ProofSystemKind::Mock,
    }
}

fn encode_consensus_witness(
    backend: &dyn ProofBackend,
    certificate: &ConsensusCertificate,
) -> WitnessBytes {
    certificate
        .encode_witness(backend_system(backend))
        .expect("encode consensus witness")
}

fn prove_consensus_certificate(
    backend: &dyn ProofBackend,
    certificate: &ConsensusCertificate,
) -> ConsensusProof {
    let witness = encode_consensus_witness(backend, certificate);
    let (proof_bytes, verifying_key, circuit) = backend
        .prove_consensus(&witness)
        .expect("prove consensus witness");
    let public_inputs = certificate
        .consensus_public_inputs()
        .expect("consensus public inputs");
    let proof =
        ConsensusProof::from_backend_artifacts(proof_bytes, verifying_key, circuit, public_inputs);
    if let Err(err) = proof.verify(backend) {
        if !matches!(
            err,
            ProofVerificationError::Backend(message)
                if message.contains("not implemented")
                    || message.contains("unsupported")
        ) {
            panic!("unexpected consensus verification failure: {err:?}");
        }
    }
    proof
}

fn certificate_with_block(label: &str) -> ConsensusCertificate {
    let hash_input = format!("consensus-{label}");
    let block_hash = BlockId(blake3::hash(hash_input.as_bytes()).to_hex().to_string());
    let weights = &CONSENSUS_VOTE_WEIGHTS;
    let total_power: u64 = weights.iter().map(|(_, weight)| *weight).sum();
    let prevotes = build_tallied_votes(&block_hash, CONSENSUS_DEFAULT_ROUND, 1, "prevote", weights);
    let precommits = build_tallied_votes(
        &block_hash,
        CONSENSUS_DEFAULT_ROUND,
        1,
        "precommit",
        weights,
    );

    let mut metadata = sample_certificate_metadata(0, CONSENSUS_DEFAULT_ROUND);
    align_poseidon_last_block_header(&mut metadata, &block_hash.0);

    ConsensusCertificate {
        block_hash,
        height: 1,
        round: CONSENSUS_DEFAULT_ROUND,
        total_power,
        quorum_threshold: quorum_threshold(total_power),
        prevote_power: total_power,
        precommit_power: total_power,
        commit_power: total_power,
        prevotes,
        precommits,
        metadata,
    }
}

fn acquire_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("lock poisoned")
}

#[test]
fn consensus_public_inputs_rejects_short_vrf_randomness() {
    let mut certificate = certificate_with_block("invalid-randomness");
    certificate.metadata.vrf_entries[0].randomness = hex::encode(vec![0xAA; 31]);

    let error = certificate.consensus_public_inputs().unwrap_err();
    assert!(matches!(
        error,
        BackendError::Failure(message) if message.contains("vrf randomness #0 must encode 32 bytes")
    ));
}

#[test]
fn consensus_public_inputs_rejects_poseidon_epoch_mismatch() {
    let mut certificate = certificate_with_block("epoch-mismatch");
    certificate.metadata.vrf_entries[0].poseidon.epoch =
        format!("{}", certificate.metadata.epoch.saturating_add(1));

    let error = certificate.consensus_public_inputs().unwrap_err();
    assert!(matches!(
        error,
        BackendError::Failure(message) if message.contains("poseidon epoch")
    ));
}

#[test]
fn consensus_public_inputs_rejects_poseidon_last_block_header_mismatch() {
    let mut certificate = certificate_with_block("block-mismatch");
    certificate.metadata.vrf_entries[0]
        .poseidon
        .last_block_header = "ff".repeat(32);

    let error = certificate.consensus_public_inputs().unwrap_err();
    assert!(matches!(
        error,
        BackendError::Failure(message)
            if message.contains("poseidon last block header mismatch block hash")
    ));
}

#[test]
fn bft_flow_reaches_commit() {
    let _guard = acquire_test_lock();
    let vrf_outputs = vec![
        build_vrf_output(0, "validator-1", [1; 32], 4, 1.5, 2_000_000),
        build_vrf_output(0, "validator-2", [2; 32], 3, 1.2, 1_500_000),
        build_vrf_output(0, "validator-3", [3; 32], 3, 1.1, 1_300_000),
    ];
    let ledger = build_ledger(&[
        ("validator-1", 10, 4, 1.5),
        ("validator-2", 8, 3, 1.2),
        ("validator-3", 6, 3, 1.1),
    ]);

    let config = ConsensusConfig::new(50, 50, 10, 0.1);
    let genesis = GenesisConfig::new(
        0,
        vrf_outputs.clone(),
        ledger.clone(),
        "root".into(),
        config,
    );
    let backend = backend();
    let state = super::state::ConsensusState::new(genesis, backend.clone()).expect("state init");

    let handle = thread::spawn(move || {
        let mut state = state;
        run_bft_loop(&mut state);
        state
    });

    thread::sleep(Duration::from_millis(25));

    let validator_set = select_validators(0, &vrf_outputs, &ledger);
    let leader = select_leader(&validator_set).expect("leader");
    let certificate = certificate_with_block("bft-1");
    let proof = prove_consensus_certificate(backend.as_ref(), &certificate);
    let proposal = Proposal {
        block: Block {
            height: 1,
            epoch: 0,
            payload: serde_json::json!({"tx": []}),
            timestamp: 0,
        },
        proof,
        certificate,
        leader_id: leader.id.clone(),
    };

    submit_proposal(proposal.clone()).expect("proposal");
    thread::sleep(Duration::from_millis(25));

    let mut peers: HashMap<_, _> = HashMap::new();
    for validator in &validator_set.validators {
        peers.insert(validator.id.clone(), PeerId::random());
    }

    for validator in &validator_set.validators {
        let peer = peers.get(&validator.id).expect("peer id");
        let block_hash = proposal.block_hash();
        let height = proposal.block.height;
        let prevote = build_prevote(validator, peer, &block_hash, 0, height, true);
        submit_prevote(prevote).expect("prevote");
        let precommit = build_precommit(validator, peer, &block_hash, 0, height);
        submit_precommit(precommit).expect("precommit");
    }

    thread::sleep(Duration::from_millis(150));

    shutdown().expect("shutdown");
    let final_state = handle.join().expect("join");

    assert_eq!(final_state.block_height, 1);
    assert!(final_state.pending_rewards.len() >= 1);
    assert!(final_state.pending_proofs.len() >= 1);
}

#[test]
fn detects_conflicting_prevotes_triggers_slash() {
    let _guard = acquire_test_lock();
    let vrf_outputs = vec![
        build_vrf_output(0, "validator-1", [1; 32], 4, 1.5, 2_000_000),
        build_vrf_output(0, "validator-2", [2; 32], 3, 1.2, 1_500_000),
        build_vrf_output(0, "validator-3", [3; 32], 3, 1.1, 1_300_000),
    ];
    let ledger = build_ledger(&[
        ("validator-1", 10, 4, 1.5),
        ("validator-2", 8, 3, 1.2),
        ("validator-3", 6, 3, 1.1),
    ]);

    let config = ConsensusConfig::new(60, 60, 10, 0.1);
    let genesis = GenesisConfig::new(
        0,
        vrf_outputs.clone(),
        ledger.clone(),
        "root".into(),
        config,
    );
    let backend = backend();
    let state = super::state::ConsensusState::new(genesis, backend.clone()).expect("state init");

    let handle = thread::spawn(move || {
        let mut state = state;
        run_bft_loop(&mut state);
        state
    });

    thread::sleep(Duration::from_millis(20));

    let validator_set = select_validators(0, &vrf_outputs, &ledger);
    let leader = select_leader(&validator_set).expect("leader");
    let conflicting = validator_set
        .validators
        .iter()
        .find(|validator| validator.id == "validator-1")
        .expect("validator-1 present")
        .clone();

    let mut peers: HashMap<_, _> = HashMap::new();
    for validator in &validator_set.validators {
        peers.insert(validator.id.clone(), PeerId::random());
    }

    let certificate_a = certificate_with_block("double-a");
    let proof_a = prove_consensus_certificate(backend.as_ref(), &certificate_a);
    let proposal_a = Proposal {
        block: Block {
            height: 1,
            epoch: 0,
            payload: serde_json::json!({"tx": [1]}),
            timestamp: 10,
        },
        proof: proof_a,
        certificate: certificate_a.clone(),
        leader_id: leader.id.clone(),
    };

    let certificate_b = certificate_with_block("double-b");
    let proof_b = prove_consensus_certificate(backend.as_ref(), &certificate_b);
    let proposal_b = Proposal {
        block: Block {
            height: 1,
            epoch: 0,
            payload: serde_json::json!({"tx": [2]}),
            timestamp: 20,
        },
        proof: proof_b,
        certificate: certificate_b.clone(),
        leader_id: leader.id.clone(),
    };

    submit_proposal(proposal_a.clone()).expect("proposal a");
    submit_proposal(proposal_b.clone()).expect("proposal b");

    thread::sleep(Duration::from_millis(25));

    let peer = peers.get(&conflicting.id).expect("peer id");
    let height = proposal_a.block.height;
    let hash_a = proposal_a.block_hash();
    let hash_b = proposal_b.block_hash();

    let prevote_a = build_prevote(&conflicting, peer, &hash_a, 0, height, true);
    submit_prevote(prevote_a).expect("prevote a");

    thread::sleep(Duration::from_millis(10));

    let prevote_b = build_prevote(&conflicting, peer, &hash_b, 0, height, true);
    submit_prevote(prevote_b).expect("prevote b");

    thread::sleep(Duration::from_millis(80));

    shutdown().expect("shutdown");
    let final_state = handle.join().expect("join");

    let evidence = final_state
        .pending_evidence
        .iter()
        .find(|record| {
            record.accused == conflicting.id
                && matches!(record.evidence, EvidenceType::DoubleSign { .. })
        })
        .expect("double-sign evidence recorded");

    if let EvidenceType::DoubleSign {
        height: evidence_height,
    } = evidence.evidence
    {
        assert_eq!(evidence_height, 1);
    }

    let punished = final_state
        .validator_set
        .validators
        .iter()
        .find(|validator| validator.id == conflicting.id)
        .expect("validator still present");

    assert_eq!(
        punished.timetoken_balance,
        conflicting.timetoken_balance - 1
    );
    assert_eq!(punished.reputation_tier, conflicting.reputation_tier - 1);
}

#[test]
fn consensus_config_accepts_reward_pools() {
    let accounts = TreasuryAccounts::new(
        "validator-treasury".into(),
        "witness-treasury".into(),
        "fee-pool".into(),
    );
    let weights = WitnessPoolWeights::new(0.25, 0.75);
    let config = ConsensusConfig::new(40, 40, 10, 0.1)
        .with_treasury_accounts(accounts.clone())
        .with_witness_pool_weights(weights);
    assert_eq!(
        config.treasury_accounts.validator_account(),
        "validator-treasury"
    );
    let (treasury_share, fee_share) = config.witness_pool_weights.split(200);
    assert_eq!(treasury_share + fee_share, 200);
    assert!(treasury_share > 0);
    assert!(fee_share > treasury_share);
}

#[test]
fn timeout_triggers_new_proposal_flow() {
    let _guard = acquire_test_lock();
    let vrf_outputs = vec![
        build_vrf_output(0, "validator-1", [1; 32], 4, 1.5, 2_000_000),
        build_vrf_output(0, "validator-2", [2; 32], 3, 1.2, 1_500_000),
        build_vrf_output(0, "validator-3", [3; 32], 3, 1.1, 1_300_000),
    ];
    let ledger = build_ledger(&[
        ("validator-1", 10, 4, 1.5),
        ("validator-2", 8, 3, 1.2),
        ("validator-3", 6, 3, 1.1),
    ]);

    let config = ConsensusConfig::new(30, 30, 10, 0.1);
    let genesis = GenesisConfig::new(
        0,
        vrf_outputs.clone(),
        ledger.clone(),
        "root".into(),
        config,
    );
    let backend = backend();
    let state = super::state::ConsensusState::new(genesis, backend.clone()).expect("state init");

    let handle = thread::spawn(move || {
        let mut state = state;
        run_bft_loop(&mut state);
        state
    });

    thread::sleep(Duration::from_millis(10));

    let validator_set = select_validators(0, &vrf_outputs, &ledger);
    let leader = select_leader(&validator_set).expect("leader");

    let certificate = certificate_with_block("manual");
    let proof = prove_consensus_certificate(backend.as_ref(), &certificate);
    let manual_proposal = Proposal {
        block: Block {
            height: 1,
            epoch: 0,
            payload: serde_json::json!({"tx": []}),
            timestamp: 0,
        },
        proof,
        certificate,
        leader_id: leader.id.clone(),
    };
    let manual_hash = manual_proposal.block_hash();

    submit_proposal(manual_proposal.clone()).expect("manual proposal");
    thread::sleep(Duration::from_millis(10));

    let leader_peer = PeerId::random();
    let height = manual_proposal.block.height;
    let prevote = build_prevote(&leader, &leader_peer, &manual_hash, 0, height, true);
    submit_prevote(prevote).expect("prevote");

    thread::sleep(Duration::from_millis(120));

    shutdown().expect("shutdown");
    let final_state = handle.join().expect("join");

    assert!(final_state.round >= 1, "timeout should advance the round");
    assert!(
        final_state.pending_proposals.iter().any(|proposal| proposal
            .proof
            .circuit
            .identifier
            .starts_with("consensus-")),
        "expected timeout to trigger a new leader proposal",
    );
    if !final_state
        .pending_prevote_messages
        .iter()
        .any(|vote| vote.validator_id == leader.id && vote.block_hash == manual_hash)
    {
        assert!(
            final_state.pending_prevote_messages.is_empty(),
            "expected either manual prevote to remain or queue to be drained after timeout",
        );
    }
}

#[test]
fn select_validators_rejects_manipulated_proof() {
    let epoch = 0;
    let valid = build_vrf_output(epoch, "validator-1", [9; 32], 3, 1.2, 1_000_000);
    let mut tampered = build_vrf_output(epoch, "validator-2", [7; 32], 3, 1.2, 1_000_000);
    tampered.proof[0] ^= 0xFF;

    let outputs = vec![valid.clone(), tampered.clone()];
    let ledger = build_ledger(&[("validator-1", 5, 3, 1.2), ("validator-2", 5, 3, 1.2)]);

    let set = select_validators(epoch, &outputs, &ledger);
    assert_eq!(set.validators.len(), 1);
    assert_eq!(set.validators[0].id, "validator-1");
}

#[test]
fn consensus_proof_verifies_with_backend() {
    let backend = backend();
    let certificate = certificate_with_block("roundtrip-ok");
    let proof = prove_consensus_certificate(backend.as_ref(), &certificate);
    assert!(proof.verify(&*backend).is_ok());
}

#[cfg(feature = "prover-stwo")]
#[test]
fn stwo_leader_builds_proposal_and_registry_verifies() {
    let _guard = acquire_test_lock();

    let backend = Arc::new(StwoBackend::new());
    let vrf_outputs = vec![
        build_vrf_output(0, "validator-1", [1; 32], 4, 1.5, 2_000_000),
        build_vrf_output(0, "validator-2", [2; 32], 3, 1.2, 1_500_000),
        build_vrf_output(0, "validator-3", [3; 32], 3, 1.1, 1_300_000),
    ];
    let ledger = build_ledger(&[
        ("validator-1", 10, 4, 1.5),
        ("validator-2", 8, 3, 1.2),
        ("validator-3", 6, 3, 1.1),
    ]);

    let config = ConsensusConfig::new(30, 30, 10, 0.1);
    let genesis = GenesisConfig::new(0, vrf_outputs, ledger, "root".into(), config);
    let mut state =
        super::state::ConsensusState::new(genesis, backend.clone()).expect("state initialises");

    let committed_block = Block {
        height: 1,
        epoch: 0,
        payload: serde_json::json!({"committed": true}),
        timestamp: 1,
    };
    let committed_certificate = certificate_for_block(&committed_block, 0);
    let committed_proof = prove_consensus_certificate(backend.as_ref(), &committed_certificate);
    let signatures = committed_certificate
        .precommits
        .iter()
        .map(|vote| Signature {
            validator_id: vote.validator_id.clone(),
            peer_id: vote.peer_id.clone(),
            signature: vote.signature.clone(),
        })
        .collect();

    let commit = Commit {
        block: committed_block,
        proof: committed_proof,
        certificate: committed_certificate.clone(),
        signatures,
    };
    state.stage_certificate(committed_certificate);
    state.apply_commit(commit);
    state.update_leader();

    let leader_validator = state
        .current_leader
        .clone()
        .expect("leader present after commit");
    let leader = Leader::new(leader_validator);
    let context = LeaderContext {
        epoch: state.epoch,
        round: state.round,
    };
    let proposal = leader
        .build_proposal(&state, context)
        .expect("leader builds proposal");

    proposal
        .proof
        .verify(backend.as_ref())
        .expect("backend verifies proposal proof");

    let proof_bytes = proposal.proof.proof_bytes().clone();
    let (_header, decoded) = decode_consensus_proof(&proof_bytes).expect("consensus proof decodes");
    let chain_proof = ChainProof::Stwo(decoded);
    let registry = ProofVerifierRegistry::default();
    registry
        .verify_consensus(&chain_proof)
        .expect("registry verifies proposal proof");
}

#[test]
fn consensus_proof_propagates_backend_error() {
    let backend = backend();
    let certificate = certificate_with_block("roundtrip-fail");
    let proof = prove_consensus_certificate(backend.as_ref(), &certificate);
    let backend = failing_backend();
    assert!(matches!(
        proof.verify(&*backend),
        Err(ProofVerificationError::Backend(message)) if message.contains("forced failure")
    ));
}

#[test]
fn consensus_proof_rejects_empty_payload() {
    let circuit = ConsensusCircuitDef::new("consensus-empty");
    let header = ProofHeader::new(ProofSystemKind::Mock, circuit.identifier.clone());
    let proof_bytes =
        ProofBytes::encode(&header, &Vec::<u8>::new()).expect("encode consensus proof");
    let verifying_key = VerifyingKey(Vec::new());
    let proof = ConsensusProof::from_backend_artifacts(
        proof_bytes,
        verifying_key,
        circuit,
        sample_consensus_public_inputs(0),
    );
    let backend = backend();
    assert!(matches!(
        proof.verify(&*backend),
        Err(ProofVerificationError::Backend(message))
            if message.contains("verifying key empty")
                || message.contains("key payload")
                || message.contains("serialization")
    ));
}

#[test]
fn select_validators_applies_stake_weights() {
    let epoch = 1;
    let a = build_vrf_output(epoch, "validator-a", [4; 32], 3, 1.0, 1_000_000);
    let b = build_vrf_output(epoch, "validator-b", [5; 32], 3, 1.0, 1_000_000);
    let outputs = vec![a, b];
    let ledger = build_ledger(&[("validator-a", 5, 3, 1.0), ("validator-b", 10, 3, 1.0)]);

    let set = select_validators(epoch, &outputs, &ledger);
    assert_eq!(set.validators.len(), 2);

    let weight_a = set.voting_power(&"validator-a".to_string());
    let weight_b = set.voting_power(&"validator-b".to_string());
    assert!(weight_b > weight_a);
    assert_eq!(weight_b, weight_a * 2);
}

#[test]
fn validator_weight_saturates_for_extreme_stake() {
    let mut validator = Validator {
        id: "validator-heavy".into(),
        reputation_tier: u8::MAX,
        reputation_score: 10_000_000.0,
        stake: 0,
        timetoken_balance: u64::MAX,
        vrf_output: [0; 32],
        weight: 0,
    };

    validator.update_weight(StakeInfo::new(u64::MAX));
    assert_eq!(validator.weight, u64::MAX);
}

#[test]
fn validator_weight_handles_zero_stake() {
    let mut validator = Validator {
        id: "validator-zero".into(),
        reputation_tier: 3,
        reputation_score: 1.5,
        stake: 0,
        timetoken_balance: 500_000,
        vrf_output: [0; 32],
        weight: 0,
    };

    validator.update_weight(StakeInfo::new(0));
    assert_eq!(validator.weight, 0);
}

#[test]
fn validator_weight_reputation_edge_behaviour() {
    let mut validator = Validator {
        id: "validator-edge".into(),
        reputation_tier: 0,
        reputation_score: 0.0,
        stake: 0,
        timetoken_balance: 0,
        vrf_output: [0; 32],
        weight: 0,
    };

    validator.update_weight(StakeInfo::new(5));
    let baseline = validator.weight;
    assert_eq!(baseline, 500);

    validator.reputation_score = 0.999;
    validator.update_weight(StakeInfo::new(5));
    assert!(validator.weight >= baseline);

    validator.reputation_tier = 1;
    validator.reputation_score = 1.0;
    validator.update_weight(StakeInfo::new(5));
    assert!(validator.weight > baseline);
}
