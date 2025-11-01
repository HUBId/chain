//! Recursive aggregation helper utilities shared between the prover and wallet.

use crate::errors::{ChainError, ChainResult};
use crate::rpp::GlobalStateCommitments;

use crate::stwo::circuit::recursive::{PrefixedDigest, RecursiveCircuit, RecursiveWitness};
use crate::stwo::params::{FieldElement, PoseidonHasher, StarkParameters};
use crate::stwo::proof::{ProofKind, ProofPayload, StarkProof};
use rpp_pruning::{Envelope, DIGEST_LENGTH, DOMAIN_TAG_LENGTH};

/// Snapshot of the ledger commitments that must anchor the recursive witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateCommitmentSnapshot {
    pub global_state_root: String,
    pub utxo_root: String,
    pub reputation_root: String,
    pub timetoke_root: String,
    pub zsi_root: String,
    pub proof_root: String,
}

impl StateCommitmentSnapshot {
    /// Build a snapshot from a ledger commitment bundle.
    pub fn from_commitments(commitments: &GlobalStateCommitments) -> Self {
        Self {
            global_state_root: hex::encode(commitments.global_state_root),
            utxo_root: hex::encode(commitments.utxo_root),
            reputation_root: hex::encode(commitments.reputation_root),
            timetoke_root: hex::encode(commitments.timetoke_root),
            zsi_root: hex::encode(commitments.zsi_root),
            proof_root: hex::encode(commitments.proof_root),
        }
    }

    /// Construct a snapshot from pre-formatted header fields.
    pub fn from_header_fields(
        global_state_root: impl Into<String>,
        utxo_root: impl Into<String>,
        reputation_root: impl Into<String>,
        timetoke_root: impl Into<String>,
        zsi_root: impl Into<String>,
        proof_root: impl Into<String>,
    ) -> Self {
        Self {
            global_state_root: global_state_root.into(),
            utxo_root: utxo_root.into(),
            reputation_root: reputation_root.into(),
            timetoke_root: timetoke_root.into(),
            zsi_root: zsi_root.into(),
            proof_root: proof_root.into(),
        }
    }
}

fn string_to_field(parameters: &StarkParameters, value: &str) -> FieldElement {
    let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
    parameters.element_from_bytes(&bytes)
}

fn ensure_kind(proof: &StarkProof, expected: ProofKind) -> ChainResult<()> {
    if proof.kind != expected {
        return Err(ChainError::Crypto(format!(
            "expected {expected:?} proof but received {actual:?}",
            actual = proof.kind
        )));
    }
    Ok(())
}

fn fold_commitments(
    hasher: &PoseidonHasher,
    parameters: &StarkParameters,
    commitments: &[String],
) -> FieldElement {
    let zero = FieldElement::zero(parameters.modulus());
    let mut accumulator = zero.clone();
    for commitment in commitments {
        let element = string_to_field(parameters, commitment);
        let inputs = vec![accumulator.clone(), element, zero.clone()];
        accumulator = hasher.hash(&inputs);
    }
    accumulator
}

fn fold_pruning_digests(
    hasher: &PoseidonHasher,
    parameters: &StarkParameters,
    binding_digest: &[u8],
    segment_commitments: &[PrefixedDigest],
) -> ChainResult<FieldElement> {
    RecursiveCircuit::fold_pruning_digests(hasher, parameters, binding_digest, segment_commitments)
        .map_err(|err| ChainError::Crypto(err.to_string()))
}

fn envelope_prefixed_commitments(envelope: &Envelope) -> (PrefixedDigest, Vec<PrefixedDigest>) {
    let binding = envelope.binding_digest().prefixed_bytes();
    let mut segments: Vec<_> = envelope
        .segments()
        .iter()
        .map(|segment| {
            (
                segment.segment_index().as_u32(),
                segment.segment_commitment().prefixed_bytes(),
            )
        })
        .collect();
    segments.sort_by_key(|(index, _)| *index);
    let commitments = segments.into_iter().map(|(_, digest)| digest).collect();

    (binding, commitments)
}

fn compute_recursive_commitment(
    parameters: &StarkParameters,
    previous_commitment: Option<&str>,
    identity_commitments: &[String],
    tx_commitments: &[String],
    uptime_commitments: &[String],
    consensus_commitments: &[String],
    state_commitment: &str,
    state_roots: &StateCommitmentSnapshot,
    pruning_binding_digest: &PrefixedDigest,
    pruning_segment_commitments: &[PrefixedDigest],
    block_height: u64,
) -> ChainResult<FieldElement> {
    let hasher = parameters.poseidon_hasher();
    let previous = previous_commitment
        .map(|value| string_to_field(parameters, value))
        .unwrap_or_else(|| FieldElement::zero(parameters.modulus()));

    let mut all_commitments = identity_commitments.to_vec();
    all_commitments.extend_from_slice(tx_commitments);
    all_commitments.extend_from_slice(uptime_commitments);
    all_commitments.extend_from_slice(consensus_commitments);
    let activity_digest = fold_commitments(&hasher, parameters, &all_commitments);
    let pruning_fold = fold_pruning_digests(
        &hasher,
        parameters,
        pruning_binding_digest,
        pruning_segment_commitments,
    )?;
    let state_digest = hasher.hash(&[
        string_to_field(parameters, state_commitment),
        string_to_field(parameters, &state_roots.global_state_root),
        string_to_field(parameters, &state_roots.utxo_root),
        string_to_field(parameters, &state_roots.reputation_root),
        string_to_field(parameters, &state_roots.timetoke_root),
        string_to_field(parameters, &state_roots.zsi_root),
        string_to_field(parameters, &state_roots.proof_root),
        parameters.element_from_u64(block_height),
    ]);

    Ok(hasher.hash(&[previous, state_digest, pruning_fold, activity_digest]))
}

fn extract_previous_commitment(previous: Option<&StarkProof>) -> ChainResult<Option<String>> {
    match previous {
        Some(proof) => {
            ensure_kind(proof, ProofKind::Recursive)?;
            match &proof.payload {
                ProofPayload::Recursive(witness) => Ok(Some(witness.aggregated_commitment.clone())),
                _ => Err(ChainError::Crypto(
                    "previous recursive proof missing recursive payload".into(),
                )),
            }
        }
        None => Ok(None),
    }
}

/// High-level helper that derives recursive witnesses for bundling proofs.
#[derive(Clone, Debug)]
pub struct RecursiveAggregator {
    parameters: StarkParameters,
}

impl RecursiveAggregator {
    /// Instantiate an aggregator for a custom parameter set.
    pub fn new(parameters: StarkParameters) -> Self {
        Self { parameters }
    }

    /// Instantiate an aggregator using the blueprint defaults.
    pub fn with_blueprint() -> Self {
        Self::new(StarkParameters::blueprint_default())
    }

    /// Build the recursive witness combining the supplied proof commitments.
    ///
    /// Pruning commitments are sourced from the provided envelope and
    /// canonicalized by segment index prior to hashing.
    #[allow(clippy::too_many_arguments)]
    pub fn build_witness(
        &self,
        previous_recursive: Option<&StarkProof>,
        identity_proofs: &[StarkProof],
        tx_proofs: &[StarkProof],
        uptime_proofs: &[StarkProof],
        consensus_proofs: &[StarkProof],
        state_proof: &StarkProof,
        pruning_envelope: &Envelope,
        state_roots: &StateCommitmentSnapshot,
        block_height: u64,
    ) -> ChainResult<RecursiveWitness> {
        let previous_commitment = extract_previous_commitment(previous_recursive)?;

        let mut identity_commitments = Vec::with_capacity(identity_proofs.len());
        for proof in identity_proofs {
            ensure_kind(proof, ProofKind::Identity)?;
            identity_commitments.push(proof.commitment.clone());
        }

        let mut tx_commitments = Vec::with_capacity(tx_proofs.len());
        for proof in tx_proofs {
            ensure_kind(proof, ProofKind::Transaction)?;
            tx_commitments.push(proof.commitment.clone());
        }

        let mut uptime_commitments = Vec::with_capacity(uptime_proofs.len());
        for proof in uptime_proofs {
            ensure_kind(proof, ProofKind::Uptime)?;
            uptime_commitments.push(proof.commitment.clone());
        }

        let mut consensus_commitments = Vec::with_capacity(consensus_proofs.len());
        for proof in consensus_proofs {
            ensure_kind(proof, ProofKind::Consensus)?;
            consensus_commitments.push(proof.commitment.clone());
        }

        ensure_kind(state_proof, ProofKind::State)?;
        let (pruning_binding_digest, pruning_segment_commitments) =
            envelope_prefixed_commitments(pruning_envelope);

        let aggregated = compute_recursive_commitment(
            &self.parameters,
            previous_commitment.as_deref(),
            &identity_commitments,
            &tx_commitments,
            &uptime_commitments,
            &consensus_commitments,
            &state_proof.commitment,
            state_roots,
            &pruning_binding_digest,
            &pruning_segment_commitments,
            block_height,
        )?;

        Ok(RecursiveWitness {
            previous_commitment,
            aggregated_commitment: aggregated.to_hex(),
            identity_commitments,
            tx_commitments,
            uptime_commitments,
            consensus_commitments,
            state_commitment: state_proof.commitment.clone(),
            pruning_binding_digest,
            pruning_segment_commitments,
            global_state_root: state_roots.global_state_root.clone(),
            utxo_root: state_roots.utxo_root.clone(),
            reputation_root: state_roots.reputation_root.clone(),
            timetoke_root: state_roots.timetoke_root.clone(),
            zsi_root: state_roots.zsi_root.clone(),
            proof_root: state_roots.proof_root.clone(),
            block_height,
        })
    }

    /// Compute the recursive aggregation commitment without constructing a witness.
    ///
    /// The pruning envelope is canonicalized by segment index before folding the
    /// commitments into the Poseidon accumulator.
    pub fn aggregate_commitment(
        &self,
        previous_commitment: Option<&str>,
        identity_commitments: &[String],
        tx_commitments: &[String],
        uptime_commitments: &[String],
        consensus_commitments: &[String],
        state_commitment: &str,
        state_roots: &StateCommitmentSnapshot,
        pruning_envelope: &Envelope,
        block_height: u64,
    ) -> ChainResult<FieldElement> {
        let (pruning_binding_digest, pruning_segment_commitments) =
            envelope_prefixed_commitments(pruning_envelope);
        compute_recursive_commitment(
            &self.parameters,
            previous_commitment,
            identity_commitments,
            tx_commitments,
            uptime_commitments,
            consensus_commitments,
            state_commitment,
            state_roots,
            &pruning_binding_digest,
            &pruning_segment_commitments,
            block_height,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::{ReputationWeights, Tier};
    use crate::stwo::circuit::consensus::{ConsensusWitness as CircuitConsensusWitness, VotePower};
    use crate::stwo::circuit::identity::IdentityWitness;
    use crate::stwo::circuit::recursive::{
        PrefixedDigest as CircuitPrefixedDigest, RecursiveWitness as CircuitRecursiveWitness,
    };
    use crate::stwo::circuit::state::StateWitness;
    use crate::stwo::circuit::transaction::TransactionWitness;
    use crate::stwo::circuit::uptime::UptimeWitness;
    use crate::stwo::circuit::{ExecutionTrace, TraceSegment};
    use crate::stwo::proof::{
        CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
    };
    use crate::types::{Account, SignedTransaction, Stake, Transaction};
    use rpp_pruning::{
        BlockHeight, Commitment, Envelope, ParameterVersion, ProofSegment, SchemaVersion,
        SegmentIndex, TaggedDigest, COMMITMENT_TAG, DIGEST_LENGTH, DOMAIN_TAG_LENGTH, ENVELOPE_TAG,
        PROOF_SEGMENT_TAG, SNAPSHOT_STATE_TAG,
    };
    use uuid::Uuid;

    fn dummy_trace(parameters: &StarkParameters) -> ExecutionTrace {
        let zero = FieldElement::zero(parameters.modulus());
        let segment = TraceSegment::new("dummy", vec!["value".to_string()], vec![vec![zero]])
            .expect("segment");
        ExecutionTrace::single(segment).expect("trace")
    }

    fn dummy_fri_proof() -> FriProof {
        FriProof::default()
    }

    fn sample_pruning_envelope() -> Envelope {
        let schema = SchemaVersion::new(1);
        let params = ParameterVersion::new(1);
        let snapshot = rpp_pruning::Snapshot::new(
            schema,
            params,
            BlockHeight::new(1),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, [0x11; DIGEST_LENGTH]),
        )
        .expect("snapshot");
        let segment = ProofSegment::new(
            schema,
            params,
            SegmentIndex::new(0),
            BlockHeight::new(1),
            BlockHeight::new(2),
            TaggedDigest::new(PROOF_SEGMENT_TAG, [0x22; DIGEST_LENGTH]),
        )
        .expect("segment");
        let commitment = Commitment::new(
            schema,
            params,
            TaggedDigest::new(COMMITMENT_TAG, [0x33; DIGEST_LENGTH]),
        )
        .expect("commitment");
        Envelope::new(
            schema,
            params,
            snapshot,
            vec![segment],
            commitment,
            TaggedDigest::new(ENVELOPE_TAG, [0x44; DIGEST_LENGTH]),
        )
        .expect("envelope")
    }

    fn make_proof(
        parameters: &StarkParameters,
        kind: ProofKind,
        payload: ProofPayload,
        commitment: String,
    ) -> StarkProof {
        StarkProof {
            kind,
            commitment,
            public_inputs: Vec::new(),
            payload,
            trace: dummy_trace(parameters),
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: dummy_fri_proof(),
        }
    }

    fn sample_transaction_bundle() -> (SignedTransaction, Account, Account) {
        let sender_address = "sender".to_string();
        let receiver_address = "receiver".to_string();
        let payload = Transaction {
            from: sender_address.clone(),
            to: receiver_address.clone(),
            amount: 10,
            fee: 1,
            nonce: 1,
            memo: None,
            timestamp: 1,
        };
        let signed_tx = SignedTransaction {
            id: Uuid::nil(),
            payload,
            signature: "0".repeat(128),
            public_key: "0".repeat(64),
        };

        let sender_account = Account::new(sender_address, 100, Stake::default());
        let receiver_account = Account::new(receiver_address, 0, Stake::default());

        (signed_tx, sender_account, receiver_account)
    }

    fn dummy_transaction_proof(parameters: &StarkParameters, commitment: String) -> StarkProof {
        let (signed_tx, sender_account, receiver_account) = sample_transaction_bundle();
        let witness = TransactionWitness {
            signed_tx,
            sender_account,
            receiver_account: Some(receiver_account),
            required_tier: Tier::Tl0,
            reputation_weights: ReputationWeights::default(),
        };
        make_proof(
            parameters,
            ProofKind::Transaction,
            ProofPayload::Transaction(witness),
            commitment,
        )
    }

    fn dummy_state_proof(parameters: &StarkParameters, commitment: String) -> StarkProof {
        let (signed_tx, sender_account, receiver_account) = sample_transaction_bundle();
        let accounts_before = vec![sender_account.clone(), receiver_account.clone()];
        let witness = StateWitness {
            prev_state_root: "00".repeat(32),
            new_state_root: "11".repeat(32),
            identities: Vec::new(),
            transactions: vec![signed_tx],
            accounts_before,
            accounts_after: vec![sender_account, receiver_account],
            required_tier: Tier::Tl0,
            reputation_weights: ReputationWeights::default(),
        };
        make_proof(
            parameters,
            ProofKind::State,
            ProofPayload::State(witness),
            commitment,
        )
    }

    fn dummy_identity_proof(parameters: &StarkParameters, commitment: String) -> StarkProof {
        let witness = IdentityWitness {
            wallet_pk: "00".repeat(32),
            wallet_addr: "11".repeat(32),
            vrf_tag: "22".repeat(32),
            epoch_nonce: "33".repeat(32),
            state_root: "44".repeat(32),
            identity_root: "55".repeat(32),
            initial_reputation: 0,
            commitment: commitment.clone(),
            identity_leaf: "66".repeat(32),
            identity_path: Vec::new(),
        };
        make_proof(
            parameters,
            ProofKind::Identity,
            ProofPayload::Identity(witness),
            commitment,
        )
    }

    fn dummy_uptime_proof(parameters: &StarkParameters, commitment: String) -> StarkProof {
        let witness = UptimeWitness {
            wallet_address: "wallet".into(),
            node_clock: 10,
            epoch: 1,
            head_hash: "aa".repeat(32),
            window_start: 0,
            window_end: 5,
            commitment: commitment.clone(),
        };
        make_proof(
            parameters,
            ProofKind::Uptime,
            ProofPayload::Uptime(witness),
            commitment,
        )
    }

    fn dummy_consensus_proof(parameters: &StarkParameters, commitment: String) -> StarkProof {
        let vote = VotePower {
            voter: "validator".into(),
            weight: 1,
        };
        let witness = CircuitConsensusWitness {
            block_hash: "bb".repeat(32),
            round: 1,
            epoch: 0,
            slot: 1,
            leader_proposal: "bb".repeat(32),
            quorum_threshold: 1,
            pre_votes: vec![vote.clone()],
            pre_commits: vec![vote.clone()],
            commit_votes: vec![vote],
            quorum_bitmap_root: "bb".repeat(32),
            quorum_signature_root: "cc".repeat(32),
            vrf_outputs: Vec::new(),
            vrf_proofs: Vec::new(),
            witness_commitments: Vec::new(),
            reputation_roots: Vec::new(),
        };
        make_proof(
            parameters,
            ProofKind::Consensus,
            ProofPayload::Consensus(witness),
            commitment,
        )
    }

    fn sample_state_roots(seed: u64) -> StateCommitmentSnapshot {
        let base = seed * 10;
        StateCommitmentSnapshot::from_header_fields(
            format!("{:064x}", base),
            format!("{:064x}", base + 1),
            format!("{:064x}", base + 2),
            format!("{:064x}", base + 3),
            format!("{:064x}", base + 4),
            format!("{:064x}", base + 5),
        )
    }

    fn dummy_recursive_proof(
        parameters: &StarkParameters,
        aggregated_commitment: String,
        previous_commitment: Option<String>,
        identity_commitments: Option<Vec<String>>,
        tx_commitments: Option<Vec<String>>,
        uptime_commitments: Option<Vec<String>>,
        consensus_commitments: Option<Vec<String>>,
        state_commitment: String,
        state_roots: StateCommitmentSnapshot,
        pruning_binding_digest: CircuitPrefixedDigest,
        pruning_segment_commitments: Vec<CircuitPrefixedDigest>,
        block_height: u64,
    ) -> StarkProof {
        let identities =
            identity_commitments.unwrap_or_else(|| vec![aggregated_commitment.clone()]);
        let tx_commitments = tx_commitments.unwrap_or_default();
        let uptime_commitments = uptime_commitments.unwrap_or_default();
        let consensus_commitments = consensus_commitments.unwrap_or_default();
        let witness = CircuitRecursiveWitness {
            previous_commitment,
            aggregated_commitment: aggregated_commitment.clone(),
            identity_commitments: identities,
            tx_commitments,
            uptime_commitments,
            consensus_commitments,
            state_commitment,
            global_state_root: state_roots.global_state_root,
            utxo_root: state_roots.utxo_root,
            reputation_root: state_roots.reputation_root,
            timetoke_root: state_roots.timetoke_root,
            zsi_root: state_roots.zsi_root,
            proof_root: state_roots.proof_root,
            pruning_binding_digest,
            pruning_segment_commitments,
            block_height,
        };
        make_proof(
            parameters,
            ProofKind::Recursive,
            ProofPayload::Recursive(witness),
            aggregated_commitment,
        )
    }

    #[test]
    fn aggregator_builds_recursive_witness_with_expected_commitment() {
        let aggregator = RecursiveAggregator::with_blueprint();
        let params = StarkParameters::blueprint_default();
        let hasher = params.poseidon_hasher();
        let zero = FieldElement::zero(params.modulus());

        let identity_commitments: Vec<String> = (10..=11)
            .map(|idx| {
                hasher
                    .hash(&[params.element_from_u64(idx), zero.clone(), zero.clone()])
                    .to_hex()
            })
            .collect();
        let tx_commitments: Vec<String> = (1..=2)
            .map(|idx| {
                hasher
                    .hash(&[params.element_from_u64(idx), zero.clone(), zero.clone()])
                    .to_hex()
            })
            .collect();
        let uptime_commitments: Vec<String> = (20..=21)
            .map(|idx| {
                hasher
                    .hash(&[params.element_from_u64(idx), zero.clone(), zero.clone()])
                    .to_hex()
            })
            .collect();
        let consensus_commitments: Vec<String> = (30..=31)
            .map(|idx| {
                hasher
                    .hash(&[params.element_from_u64(idx), zero.clone(), zero.clone()])
                    .to_hex()
            })
            .collect();
        let state_commitment = hasher
            .hash(&[params.element_from_u64(99), zero.clone(), zero.clone()])
            .to_hex();
        let state_roots = sample_state_roots(2);

        let pruning_envelope = sample_pruning_envelope();
        let (pruning_binding_digest, pruning_segment_commitments) =
            envelope_prefixed_commitments(&pruning_envelope);

        let previous_identity_commitments = vec![hasher
            .hash(&[params.element_from_u64(8), zero.clone(), zero.clone()])
            .to_hex()];
        let previous_tx_commitments = vec![hasher
            .hash(&[params.element_from_u64(5), zero.clone(), zero.clone()])
            .to_hex()];
        let previous_state_commitment = hasher
            .hash(&[params.element_from_u64(6), zero.clone(), zero.clone()])
            .to_hex();
        let previous_state_roots = sample_state_roots(1);
        let previous_envelope = sample_pruning_envelope();
        let (previous_binding, previous_segments) =
            envelope_prefixed_commitments(&previous_envelope);
        let previous_field = aggregator
            .aggregate_commitment(
                None,
                &previous_identity_commitments,
                &previous_tx_commitments,
                &[],
                &[],
                &previous_state_commitment,
                &previous_state_roots,
                &previous_envelope,
                1,
            )
            .expect("previous aggregate commitment");
        let previous_commitment_hex = previous_field.to_hex();
        let previous_proof = dummy_recursive_proof(
            &params,
            previous_commitment_hex.clone(),
            None,
            Some(previous_identity_commitments.clone()),
            Some(previous_tx_commitments.clone()),
            Some(Vec::new()),
            Some(Vec::new()),
            previous_state_commitment.clone(),
            previous_state_roots.clone(),
            previous_binding,
            previous_segments.clone(),
            1,
        );

        let identity_proofs: Vec<StarkProof> = identity_commitments
            .iter()
            .cloned()
            .map(|commitment| dummy_identity_proof(&params, commitment))
            .collect();
        let tx_proofs: Vec<StarkProof> = tx_commitments
            .iter()
            .cloned()
            .map(|commitment| dummy_transaction_proof(&params, commitment))
            .collect();
        let uptime_proofs: Vec<StarkProof> = uptime_commitments
            .iter()
            .cloned()
            .map(|commitment| dummy_uptime_proof(&params, commitment))
            .collect();
        let consensus_proofs: Vec<StarkProof> = consensus_commitments
            .iter()
            .cloned()
            .map(|commitment| dummy_consensus_proof(&params, commitment))
            .collect();
        let state_proof = dummy_state_proof(&params, state_commitment.clone());
        let witness = aggregator
            .build_witness(
                Some(&previous_proof),
                &identity_proofs,
                &tx_proofs,
                &uptime_proofs,
                &consensus_proofs,
                &state_proof,
                &pruning_envelope,
                &state_roots,
                2,
            )
            .expect("recursive witness");

        assert_eq!(
            witness.previous_commitment,
            Some(previous_commitment_hex.clone())
        );
        let expected = aggregator
            .aggregate_commitment(
                Some(previous_commitment_hex.as_str()),
                &identity_commitments,
                &tx_commitments,
                &uptime_commitments,
                &consensus_commitments,
                &state_commitment,
                &state_roots,
                &pruning_envelope,
                2,
            )
            .expect("aggregate commitment");
        assert_eq!(witness.aggregated_commitment, expected.to_hex());
        assert_eq!(witness.identity_commitments, identity_commitments);
        assert_eq!(witness.tx_commitments, tx_commitments);
        assert_eq!(witness.uptime_commitments, uptime_commitments);
        assert_eq!(witness.consensus_commitments, consensus_commitments);
        assert_eq!(witness.state_commitment, state_commitment);
        assert_eq!(witness.global_state_root, state_roots.global_state_root);
        assert_eq!(witness.utxo_root, state_roots.utxo_root);
        assert_eq!(witness.reputation_root, state_roots.reputation_root);
        assert_eq!(witness.timetoke_root, state_roots.timetoke_root);
        assert_eq!(witness.zsi_root, state_roots.zsi_root);
        assert_eq!(witness.proof_root, state_roots.proof_root);
        assert_eq!(witness.pruning_binding_digest, pruning_binding_digest);
        assert_eq!(
            witness.pruning_segment_commitments,
            pruning_segment_commitments
        );
    }

    #[test]
    fn aggregator_accepts_identity_only_blocks() {
        let aggregator = RecursiveAggregator::with_blueprint();
        let params = StarkParameters::blueprint_default();
        let hasher = params.poseidon_hasher();
        let zero = FieldElement::zero(params.modulus());

        let state_commitment = hasher
            .hash(&[params.element_from_u64(15), zero.clone(), zero.clone()])
            .to_hex();
        let identity_commitment = hasher
            .hash(&[params.element_from_u64(25), zero.clone(), zero.clone()])
            .to_hex();
        let state_roots = sample_state_roots(3);
        let pruning_envelope = sample_pruning_envelope();
        let (pruning_binding_digest, pruning_segment_commitments) =
            envelope_prefixed_commitments(&pruning_envelope);

        let previous_tx_commitments = vec![hasher
            .hash(&[params.element_from_u64(3), zero.clone(), zero.clone()])
            .to_hex()];
        let previous_identity_commitments = vec![identity_commitment.clone()];
        let previous_roots = sample_state_roots(2);
        let previous_envelope = sample_pruning_envelope();
        let (previous_binding, previous_segments) =
            envelope_prefixed_commitments(&previous_envelope);
        let previous_aggregate = aggregator
            .aggregate_commitment(
                None,
                &previous_identity_commitments,
                &previous_tx_commitments,
                &[],
                &[],
                &state_commitment,
                &previous_roots,
                &previous_envelope,
                1,
            )
            .expect("previous aggregate commitment");
        let previous_hex = previous_aggregate.to_hex();
        let previous = dummy_recursive_proof(
            &params,
            previous_hex.clone(),
            None,
            Some(previous_identity_commitments.clone()),
            Some(previous_tx_commitments),
            Some(Vec::new()),
            Some(Vec::new()),
            state_commitment.clone(),
            previous_roots.clone(),
            previous_binding,
            previous_segments.clone(),
            1,
        );

        let state_proof = dummy_state_proof(&params, state_commitment.clone());
        let identity_proof = dummy_identity_proof(&params, identity_commitment.clone());

        let witness = aggregator
            .build_witness(
                Some(&previous),
                &[identity_proof],
                &[],
                &[],
                &[],
                &state_proof,
                &pruning_envelope,
                &state_roots,
                2,
            )
            .expect("recursive witness with identity commitments");

        assert_eq!(witness.previous_commitment, Some(previous_hex.clone()));
        assert_eq!(
            witness.identity_commitments,
            vec![identity_commitment.clone()]
        );
        assert!(witness.tx_commitments.is_empty());
        assert!(witness.uptime_commitments.is_empty());
        assert!(witness.consensus_commitments.is_empty());
        let expected = aggregator
            .aggregate_commitment(
                Some(previous_hex.as_str()),
                &[identity_commitment],
                &[],
                &[],
                &[],
                &state_commitment,
                &state_roots,
                &pruning_envelope,
                2,
            )
            .expect("aggregate commitment");
        assert_eq!(witness.aggregated_commitment, expected.to_hex());
        assert_eq!(witness.state_commitment, state_commitment);
        assert_eq!(witness.global_state_root, state_roots.global_state_root);
        assert_eq!(witness.utxo_root, state_roots.utxo_root);
        assert_eq!(witness.reputation_root, state_roots.reputation_root);
        assert_eq!(witness.timetoke_root, state_roots.timetoke_root);
        assert_eq!(witness.zsi_root, state_roots.zsi_root);
        assert_eq!(witness.proof_root, state_roots.proof_root);
        assert_eq!(witness.pruning_binding_digest, pruning_binding_digest);
        assert_eq!(
            witness.pruning_segment_commitments,
            pruning_segment_commitments
        );
    }

    #[test]
    fn aggregator_canonicalizes_pruning_segments() {
        let aggregator = RecursiveAggregator::with_blueprint();
        let params = StarkParameters::blueprint_default();
        let hasher = params.poseidon_hasher();
        let zero = FieldElement::zero(params.modulus());

        let schema = SchemaVersion::new(1);
        let version = ParameterVersion::new(1);
        let snapshot = rpp_pruning::Snapshot::new(
            schema,
            version,
            BlockHeight::new(1),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, [0x10; DIGEST_LENGTH]),
        )
        .expect("snapshot");
        let later_segment = ProofSegment::new(
            schema,
            version,
            SegmentIndex::new(5),
            BlockHeight::new(1),
            BlockHeight::new(2),
            TaggedDigest::new(PROOF_SEGMENT_TAG, [0x45; DIGEST_LENGTH]),
        )
        .expect("segment high");
        let earlier_segment = ProofSegment::new(
            schema,
            version,
            SegmentIndex::new(3),
            BlockHeight::new(2),
            BlockHeight::new(3),
            TaggedDigest::new(PROOF_SEGMENT_TAG, [0x34; DIGEST_LENGTH]),
        )
        .expect("segment low");
        let commitment = Commitment::new(
            schema,
            version,
            TaggedDigest::new(COMMITMENT_TAG, [0x56; DIGEST_LENGTH]),
        )
        .expect("commitment");
        let envelope = Envelope::new(
            schema,
            version,
            snapshot,
            vec![later_segment, earlier_segment],
            commitment,
            TaggedDigest::new(ENVELOPE_TAG, [0x67; DIGEST_LENGTH]),
        )
        .expect("envelope");

        let (expected_binding, expected_segments) = envelope_prefixed_commitments(&envelope);

        let identity_commitment = hasher
            .hash(&[params.element_from_u64(11), zero.clone(), zero.clone()])
            .to_hex();
        let identity_proof = dummy_identity_proof(&params, identity_commitment.clone());
        let state_commitment = hasher
            .hash(&[params.element_from_u64(21), zero.clone(), zero.clone()])
            .to_hex();
        let state_roots = sample_state_roots(4);
        let state_proof = dummy_state_proof(&params, state_commitment.clone());

        let witness = aggregator
            .build_witness(
                None,
                &[identity_proof],
                &[],
                &[],
                &[],
                &state_proof,
                &envelope,
                &state_roots,
                3,
            )
            .expect("recursive witness with canonical pruning data");

        assert_eq!(witness.pruning_binding_digest, expected_binding);
        assert_eq!(witness.pruning_segment_commitments, expected_segments);

        let aggregated = aggregator
            .aggregate_commitment(
                None,
                &[identity_commitment],
                &[],
                &[],
                &[],
                &state_commitment,
                &state_roots,
                &envelope,
                3,
            )
            .expect("aggregate commitment");
        assert_eq!(witness.aggregated_commitment, aggregated.to_hex());
    }
}
