#![cfg(feature = "prover-stwo")]

use prover_backend_interface::{
    ConsensusPublicInputs, IdentityPublicInputs, ProofSystemKind, PruningPublicInputs,
    RecursivePublicInputs, StatePublicInputs, UptimePublicInputs, WitnessBytes, WitnessHeader,
};
use prover_stwo_backend::official::circuit::consensus::{ConsensusWitness, VotePower};
use prover_stwo_backend::official::circuit::identity::IdentityWitness;
use prover_stwo_backend::official::circuit::pruning::PruningWitness;
use prover_stwo_backend::official::circuit::recursive::RecursiveWitness;
use prover_stwo_backend::official::circuit::state::StateWitness;
use prover_stwo_backend::official::circuit::string_to_field;
use prover_stwo_backend::official::circuit::uptime::UptimeWitness;
use prover_stwo_backend::official::params::{FieldElement, StarkParameters};
use prover_stwo_backend::reputation::{ReputationWeights, Tier};
use prover_stwo_backend::state::compute_merkle_root;
use prover_stwo_backend::types::{Account, Stake, UptimeProof};
use prover_stwo_backend::Blake2sHasher;

pub const IDENTITY_CIRCUIT: &str = "identity";
pub const STATE_CIRCUIT: &str = "state";
pub const PRUNING_CIRCUIT: &str = "pruning";
pub const RECURSIVE_CIRCUIT: &str = "recursive";
pub const UPTIME_CIRCUIT: &str = "uptime";
pub const CONSENSUS_CIRCUIT: &str = "consensus";

pub fn identity_witness() -> IdentityWitness {
    let parameters = StarkParameters::blueprint_default();
    let wallet_pk_bytes = [0x11u8; 32];
    let wallet_pk = hex::encode(wallet_pk_bytes);
    let wallet_addr = hex::encode(<[u8; 32]>::from(Blake2sHasher::hash(&wallet_pk_bytes)));
    let vrf_tag = "55".repeat(vrf_proof_length());
    let epoch_nonce = hex::encode([0x22u8; 32]);
    let state_root = hex::encode([0x33u8; 32]);

    let defaults = identity_default_nodes();
    let identity_leaf = hex::encode(defaults[identity_tree_depth()]);
    let identity_path = identity_siblings(&defaults, &wallet_addr);
    let identity_root = hex::encode(defaults[0]);

    let hasher = parameters.poseidon_hasher();
    let commitment = hasher
        .hash(&[
            string_to_field(&parameters, &wallet_addr),
            string_to_field(&parameters, &vrf_tag),
            string_to_field(&parameters, &identity_root),
            string_to_field(&parameters, &state_root),
        ])
        .to_hex();

    IdentityWitness {
        wallet_pk,
        wallet_addr,
        vrf_tag,
        epoch_nonce,
        state_root,
        identity_root,
        initial_reputation: 0,
        commitment,
        identity_leaf,
        identity_path,
    }
}

pub fn identity_witness_bytes() -> WitnessBytes {
    let header = WitnessHeader::new(ProofSystemKind::Stwo, IDENTITY_CIRCUIT);
    WitnessBytes::encode(&header, &identity_witness()).expect("identity witness encodes")
}

pub fn identity_public_inputs() -> IdentityPublicInputs {
    let witness = identity_witness();
    IdentityPublicInputs {
        wallet_address: hex_to_array(&witness.wallet_addr),
        vrf_tag: hex::decode(&witness.vrf_tag).expect("vrf tag decodes"),
        identity_root: hex_to_array(&witness.identity_root),
        state_root: hex_to_array(&witness.state_root),
    }
}

pub fn state_witness() -> StateWitness {
    let mut before = vec![Account::new(
        hex::encode([0x44u8; 32]),
        1_000,
        Stake::default(),
    )];
    before[0].reputation.tier = Tier::Tl2;
    before[0].reputation.zsi.validated = true;
    before[0].reputation.timetokes.last_decay_timestamp = 1_717_171_717;
    let mut after = before.clone();

    let prev_state_root = state_root_for(&before);
    let new_state_root = state_root_for(&after);

    StateWitness {
        prev_state_root,
        new_state_root,
        identities: Vec::new(),
        transactions: Vec::new(),
        accounts_before: before,
        accounts_after: after,
        required_tier: Tier::Tl1,
        reputation_weights: ReputationWeights::default(),
    }
}

pub fn state_witness_bytes() -> WitnessBytes {
    let header = WitnessHeader::new(ProofSystemKind::Stwo, STATE_CIRCUIT);
    WitnessBytes::encode(&header, &state_witness()).expect("state witness encodes")
}

pub fn state_public_inputs() -> StatePublicInputs {
    let witness = state_witness();
    StatePublicInputs {
        previous_state_root: hex_to_array(&witness.prev_state_root),
        new_state_root: hex_to_array(&witness.new_state_root),
        transaction_count: witness.transactions.len() as u64,
    }
}

pub fn pruning_witness() -> PruningWitness {
    let original = vec![hex::encode([0x55u8; 32]), hex::encode([0x66u8; 32])];
    let removed = vec![original[0].clone()];
    let previous_tx_root = merkle_root(&original);
    let pruned_tx_root = merkle_root(&original[1..].to_vec());

    PruningWitness {
        previous_tx_root,
        pruned_tx_root,
        original_transactions: original,
        removed_transactions: removed,
    }
}

pub fn pruning_witness_bytes() -> WitnessBytes {
    let header = WitnessHeader::new(ProofSystemKind::Stwo, PRUNING_CIRCUIT);
    WitnessBytes::encode(&header, &pruning_witness()).expect("pruning witness encodes")
}

pub fn pruning_public_inputs() -> PruningPublicInputs {
    let witness = pruning_witness();
    PruningPublicInputs {
        previous_tx_root: hex_to_array(&witness.previous_tx_root),
        pruned_tx_root: hex_to_array(&witness.pruned_tx_root),
        removed_transactions: witness.removed_transactions.len() as u64,
    }
}

pub fn recursive_witness() -> RecursiveWitness {
    let parameters = StarkParameters::blueprint_default();
    let identity_commitments = vec![parameters.element_from_u64(11).to_hex()];
    let tx_commitments = vec![parameters.element_from_u64(22).to_hex()];
    let uptime_commitments = vec![parameters.element_from_u64(33).to_hex()];
    let consensus_commitments = vec![parameters.element_from_u64(44).to_hex()];
    let pruning_commitment = parameters.element_from_u64(55).to_hex();
    let state_commitment = parameters.element_from_u64(66).to_hex();
    let global_state_root = parameters.element_from_u64(77).to_hex();
    let utxo_root = parameters.element_from_u64(88).to_hex();
    let reputation_root = parameters.element_from_u64(99).to_hex();
    let timetoke_root = parameters.element_from_u64(111).to_hex();
    let zsi_root = parameters.element_from_u64(122).to_hex();
    let proof_root = parameters.element_from_u64(133).to_hex();
    let block_height = 9;

    let mut witness = RecursiveWitness {
        previous_commitment: None,
        aggregated_commitment: String::new(),
        identity_commitments,
        tx_commitments,
        uptime_commitments,
        consensus_commitments,
        state_commitment,
        global_state_root,
        utxo_root,
        reputation_root,
        timetoke_root,
        zsi_root,
        proof_root,
        pruning_commitment,
        block_height,
    };

    let aggregated = recursive_aggregate(&parameters, &witness);
    witness.aggregated_commitment = aggregated.to_hex();
    witness
}

pub fn recursive_witness_bytes() -> WitnessBytes {
    let header = WitnessHeader::new(ProofSystemKind::Stwo, RECURSIVE_CIRCUIT);
    WitnessBytes::encode(&header, &recursive_witness()).expect("recursive witness encodes")
}

pub fn recursive_public_inputs() -> RecursivePublicInputs {
    let parameters = StarkParameters::blueprint_default();
    let witness = recursive_witness();
    let previous = witness
        .previous_commitment
        .as_ref()
        .map(|value| field_to_padded_bytes(&string_to_field(&parameters, value)));

    RecursivePublicInputs {
        previous_commitment: previous,
        aggregated_commitment: field_to_padded_bytes(&string_to_field(
            &parameters,
            &witness.aggregated_commitment,
        )),
        transaction_commitments: witness.tx_commitments.len() as u64,
    }
}

pub fn uptime_witness() -> UptimeWitness {
    let wallet_address = hex::encode([0x77u8; 32]);
    let window_start = 10;
    let window_end = 20;
    let commitment_bytes = UptimeProof::commitment_bytes(&wallet_address, window_start, window_end);
    UptimeWitness {
        wallet_address,
        node_clock: 42,
        epoch: 3,
        head_hash: hex::encode([0x88u8; 32]),
        window_start,
        window_end,
        commitment: hex::encode(commitment_bytes),
    }
}

pub fn uptime_witness_bytes() -> WitnessBytes {
    let header = WitnessHeader::new(ProofSystemKind::Stwo, UPTIME_CIRCUIT);
    WitnessBytes::encode(&header, &uptime_witness()).expect("uptime witness encodes")
}

pub fn uptime_public_inputs() -> UptimePublicInputs {
    let witness = uptime_witness();
    UptimePublicInputs {
        wallet_address: hex_to_array(&witness.wallet_address),
        node_clock: witness.node_clock,
        epoch: witness.epoch,
        head_hash: hex_to_array(&witness.head_hash),
        window_start: witness.window_start,
        window_end: witness.window_end,
        commitment: hex_to_array(&witness.commitment),
    }
}

pub fn consensus_witness() -> ConsensusWitness {
    let block_hash = hex::encode([0x99u8; 32]);
    let votes = vec![
        VotePower {
            voter: "validator-1".into(),
            weight: 10,
        },
        VotePower {
            voter: "validator-2".into(),
            weight: 8,
        },
    ];
    ConsensusWitness {
        block_hash: block_hash.clone(),
        round: 5,
        leader_proposal: block_hash,
        quorum_threshold: 12,
        pre_votes: votes.clone(),
        pre_commits: votes.clone(),
        commit_votes: votes,
    }
}

pub fn consensus_witness_bytes() -> WitnessBytes {
    let header = WitnessHeader::new(ProofSystemKind::Stwo, CONSENSUS_CIRCUIT);
    WitnessBytes::encode(&header, &consensus_witness()).expect("consensus witness encodes")
}

pub fn consensus_public_inputs() -> ConsensusPublicInputs {
    let witness = consensus_witness();
    ConsensusPublicInputs {
        block_hash: hex_to_array(&witness.block_hash),
        round: witness.round,
        leader_proposal: hex_to_array(&witness.leader_proposal),
        quorum_threshold: witness.quorum_threshold,
    }
}

fn identity_tree_depth() -> usize {
    32
}

fn vrf_proof_length() -> usize {
    80
}

fn identity_default_nodes() -> Vec<[u8; 32]> {
    let mut defaults = vec![[0u8; 32]; identity_tree_depth() + 1];
    defaults[identity_tree_depth()] = domain_hash(b"rpp-zsi-empty-leaf", &[]);
    for level in (0..identity_tree_depth()).rev() {
        let child = defaults[level + 1];
        defaults[level] = hash_children(&child, &child);
    }
    defaults
}

fn identity_siblings(defaults: &[[u8; 32]], wallet_addr: &str) -> Vec<String> {
    let mut siblings = Vec::with_capacity(identity_tree_depth());
    let mut index = derive_index(wallet_addr);
    for level in (0..identity_tree_depth()).rev() {
        let sibling = defaults[level + 1];
        siblings.push(hex::encode(sibling));
        index /= 2;
    }
    siblings
}

fn recursive_aggregate(parameters: &StarkParameters, witness: &RecursiveWitness) -> FieldElement {
    let hasher = parameters.poseidon_hasher();
    let zero = FieldElement::zero(parameters.modulus());
    let previous = witness
        .previous_commitment
        .as_ref()
        .map(|value| string_to_field(parameters, value))
        .unwrap_or_else(|| FieldElement::zero(parameters.modulus()));
    let pruning = string_to_field(parameters, &witness.pruning_commitment);
    let mut commitments = witness.identity_commitments.clone();
    commitments.extend(witness.tx_commitments.clone());
    commitments.extend(witness.uptime_commitments.clone());
    commitments.extend(witness.consensus_commitments.clone());

    let mut activity = zero.clone();
    for commitment in commitments {
        let element = string_to_field(parameters, &commitment);
        activity = hasher.hash(&[activity.clone(), element, zero.clone()]);
    }

    let state_digest = hasher.hash(&[
        string_to_field(parameters, &witness.state_commitment),
        string_to_field(parameters, &witness.global_state_root),
        string_to_field(parameters, &witness.utxo_root),
        string_to_field(parameters, &witness.reputation_root),
        string_to_field(parameters, &witness.timetoke_root),
        string_to_field(parameters, &witness.zsi_root),
        string_to_field(parameters, &witness.proof_root),
        parameters.element_from_u64(witness.block_height),
    ]);

    hasher.hash(&[previous, state_digest, pruning, activity])
}

fn state_root_for(accounts: &[Account]) -> String {
    let mut sorted = accounts.to_vec();
    sorted.sort_by(|a, b| a.address.cmp(&b.address));
    let mut leaves = sorted
        .iter()
        .map(|account| {
            let bytes = serde_json::to_vec(account).expect("serialize account");
            <[u8; 32]>::from(Blake2sHasher::hash(bytes.as_slice()))
        })
        .collect::<Vec<_>>();
    hex::encode(compute_merkle_root(&mut leaves))
}

fn merkle_root(hashes: &[String]) -> String {
    let mut leaves = hashes
        .iter()
        .map(|hash| hex_to_array::<32>(hash))
        .collect::<Vec<_>>();
    hex::encode(compute_merkle_root(&mut leaves))
}

fn domain_hash(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(label.len() + bytes.len());
    data.extend_from_slice(label);
    data.extend_from_slice(bytes);
    Blake2sHasher::hash(&data).into()
}

fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    domain_hash(b"rpp-zsi-node", &data)
}

fn derive_index(wallet_addr: &str) -> u64 {
    let hash: [u8; 32] = Blake2sHasher::hash(wallet_addr.as_bytes()).into();
    u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) as u64
}

fn hex_to_array<const N: usize>(value: &str) -> [u8; N] {
    let bytes = hex::decode(value).expect("hex decodes");
    assert_eq!(bytes.len(), N, "hex string must encode {N} bytes");
    let mut array = [0u8; N];
    array.copy_from_slice(&bytes);
    array
}

fn field_to_padded_bytes(value: &FieldElement) -> [u8; 32] {
    let repr = value.to_bytes();
    let mut bytes = [0u8; 32];
    let offset = bytes.len().saturating_sub(repr.len());
    bytes[offset..offset + repr.len()].copy_from_slice(&repr);
    bytes
}
