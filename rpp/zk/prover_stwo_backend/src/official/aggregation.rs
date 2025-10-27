use crate::official::circuit::recursive::PrefixedDigest;
use crate::official::params::{FieldElement, PoseidonHasher, StarkParameters};

/// Snapshot of ledger commitments anchoring the recursive aggregation witness.
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
    /// Construct a snapshot from individual commitment fields.
    #[allow(clippy::too_many_arguments)]
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
    block_height: u64,
) -> FieldElement {
    let hasher = parameters.poseidon_hasher();
    let previous = previous_commitment
        .map(|value| string_to_field(parameters, value))
        .unwrap_or_else(|| FieldElement::zero(parameters.modulus()));

    let mut all_commitments = identity_commitments.to_vec();
    all_commitments.extend_from_slice(tx_commitments);
    all_commitments.extend_from_slice(uptime_commitments);
    all_commitments.extend_from_slice(consensus_commitments);
    let activity_digest = fold_commitments(&hasher, parameters, &all_commitments);

    let pruning_element = parameters.element_from_bytes(pruning_binding_digest);
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

    hasher.hash(&[previous, state_digest, pruning_element, activity_digest])
}

/// Helper responsible for recomputing recursive aggregation commitments.
#[derive(Clone, Debug)]
pub struct RecursiveAggregator {
    parameters: StarkParameters,
}

impl RecursiveAggregator {
    /// Instantiate an aggregator for custom STARK parameters.
    pub fn new(parameters: StarkParameters) -> Self {
        Self { parameters }
    }

    /// Instantiate an aggregator using the blueprint defaults.
    pub fn with_blueprint() -> Self {
        Self::new(StarkParameters::blueprint_default())
    }

    /// Compute the recursive aggregation commitment without constructing a witness,
    /// consuming a typed pruning binding digest rather than a hex-encoded string.
    #[allow(clippy::too_many_arguments)]
    pub fn aggregate_commitment(
        &self,
        previous_commitment: Option<&str>,
        identity_commitments: &[String],
        tx_commitments: &[String],
        uptime_commitments: &[String],
        consensus_commitments: &[String],
        state_commitment: &str,
        state_roots: &StateCommitmentSnapshot,
        /// Prefixed digest binding the pruning segment commitment tree.
        pruning_binding_digest: &PrefixedDigest,
        block_height: u64,
    ) -> FieldElement {
        compute_recursive_commitment(
            &self.parameters,
            previous_commitment,
            identity_commitments,
            tx_commitments,
            uptime_commitments,
            consensus_commitments,
            state_commitment,
            state_roots,
            pruning_binding_digest,
            block_height,
        )
    }
}
