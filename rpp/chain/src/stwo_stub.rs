#![allow(dead_code)]

use rpp_pruning::{DIGEST_LENGTH, DOMAIN_TAG_LENGTH};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::warn;

const STWO_BYPASS_REASON: &str = "prover-stwo feature disabled";

pub mod aggregation {
    use serde::{Deserialize, Serialize};

    use crate::rpp::GlobalStateCommitments;

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct StateCommitmentSnapshot {
        pub global_state_root: String,
        pub utxo_root: String,
        pub reputation_root: String,
        pub timetoke_root: String,
        pub zsi_root: String,
        pub proof_root: String,
    }

    impl StateCommitmentSnapshot {
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
}

pub mod prover {
    use crate::consensus::ConsensusCertificate;
    use crate::errors::{ChainError, ChainResult};
    use crate::proof_system::ProofProver;
    use crate::reputation::{ReputationWeights, Tier};
    use crate::rpp::{GlobalStateCommitments, ProofSystemKind};
    use crate::storage::Storage;
    use crate::types::{
        AttestedIdentityRequest, ChainProof, IdentityGenesis, SignedTransaction, UptimeClaim,
    };
    use rpp_pruning::Envelope;

    use super::params::StarkParameters;

    fn disabled<T>() -> ChainResult<T> {
        warn!(
            target = "runtime.proof.prover",
            backend = "stwo",
            bypass = true,
            reason = STWO_BYPASS_REASON,
            "STWO wallet prover unavailable while feature is disabled"
        );
        Err(ChainError::Crypto(STWO_BYPASS_REASON.into()))
    }

    #[derive(Clone)]
    pub struct WalletProver<'a> {
        pub storage: &'a Storage,
        parameters: StarkParameters,
        minimum_tier: Tier,
        reputation_weights: ReputationWeights,
    }

    impl<'a> WalletProver<'a> {
        pub fn new(storage: &'a Storage) -> Self {
            Self {
                storage,
                parameters: StarkParameters::blueprint_default(),
                minimum_tier: Tier::Tl1,
                reputation_weights: ReputationWeights::default(),
            }
        }

        pub fn with_minimum_tier(mut self, tier: Tier) -> Self {
            self.minimum_tier = tier;
            self
        }

        pub fn with_parameters(mut self, parameters: StarkParameters) -> Self {
            self.parameters = parameters;
            self
        }

        pub fn with_reputation_weights(mut self, weights: ReputationWeights) -> Self {
            self.reputation_weights = weights;
            self
        }

        pub fn parameters(&self) -> &StarkParameters {
            &self.parameters
        }

        pub fn minimum_tier(&self) -> &Tier {
            &self.minimum_tier
        }

        pub fn reputation_weights(&self) -> &ReputationWeights {
            &self.reputation_weights
        }
    }

    impl<'a> ProofProver for WalletProver<'a> {
        type IdentityWitness = crate::stwo::circuit::identity::IdentityWitness;
        type TransactionWitness = crate::stwo::circuit::transaction::TransactionWitness;
        type StateWitness = crate::stwo::circuit::state::StateWitness;
        type PruningWitness = crate::stwo::circuit::pruning::PruningWitness;
        type RecursiveWitness = crate::stwo::circuit::recursive::RecursiveWitness;
        type UptimeWitness = crate::stwo::circuit::uptime::UptimeWitness;
        type ConsensusWitness = crate::stwo::circuit::consensus::ConsensusWitness;

        fn system(&self) -> ProofSystemKind {
            ProofSystemKind::Stwo
        }

        fn build_identity_witness(
            &self,
            _genesis: &IdentityGenesis,
        ) -> ChainResult<Self::IdentityWitness> {
            disabled()
        }

        fn build_transaction_witness(
            &self,
            _tx: &SignedTransaction,
        ) -> ChainResult<Self::TransactionWitness> {
            disabled()
        }

        fn build_state_witness(
            &self,
            _prev_state_root: &str,
            _new_state_root: &str,
            _identities: &[AttestedIdentityRequest],
            _transactions: &[SignedTransaction],
        ) -> ChainResult<Self::StateWitness> {
            disabled()
        }

        fn build_pruning_witness(
            &self,
            _expected_previous_state_root: Option<&str>,
            _previous_identities: &[AttestedIdentityRequest],
            _previous_txs: &[SignedTransaction],
            _pruning: &Envelope,
            _removed: Vec<String>,
        ) -> ChainResult<Self::PruningWitness> {
            disabled()
        }

        fn build_recursive_witness(
            &self,
            _previous_recursive: Option<&ChainProof>,
            _identity_proofs: &[ChainProof],
            _tx_proofs: &[ChainProof],
            _uptime_proofs: &[ChainProof],
            _consensus_proofs: &[ChainProof],
            _state_commitments: &GlobalStateCommitments,
            _state_proof: &ChainProof,
            _pruning_envelope: &Envelope,
            _pruning_proof: &ChainProof,
            _block_height: u64,
        ) -> ChainResult<Self::RecursiveWitness> {
            disabled()
        }

        fn build_uptime_witness(&self, _claim: &UptimeClaim) -> ChainResult<Self::UptimeWitness> {
            disabled()
        }

        fn build_consensus_witness(
            &self,
            _block_hash: &str,
            _certificate: &ConsensusCertificate,
        ) -> ChainResult<Self::ConsensusWitness> {
            disabled()
        }

        fn prove_transaction(
            &self,
            _witness: Self::TransactionWitness,
        ) -> ChainResult<ChainProof> {
            disabled()
        }

        fn prove_identity(
            &self,
            _witness: Self::IdentityWitness,
        ) -> ChainResult<ChainProof> {
            disabled()
        }

        fn prove_state_transition(
            &self,
            _witness: Self::StateWitness,
        ) -> ChainResult<ChainProof> {
            disabled()
        }

        fn prove_pruning(
            &self,
            _witness: Self::PruningWitness,
        ) -> ChainResult<ChainProof> {
            disabled()
        }

        fn prove_recursive(
            &self,
            _witness: Self::RecursiveWitness,
        ) -> ChainResult<ChainProof> {
            disabled()
        }

        fn prove_uptime(
            &self,
            _witness: Self::UptimeWitness,
        ) -> ChainResult<ChainProof> {
            disabled()
        }

        fn prove_consensus(
            &self,
            _witness: Self::ConsensusWitness,
        ) -> ChainResult<ChainProof> {
            disabled()
        }
    }
}

pub mod air {
    #[derive(Clone, Debug, Default)]
    pub struct AirDefinition;

    #[derive(Clone, Debug, Default)]
    pub struct AirColumn;

    #[derive(Clone, Debug, Default)]
    pub struct AirConstraint;

    #[derive(Clone, Debug, Default)]
    pub struct AirExpression;

    #[derive(Clone, Debug, Default)]
    pub struct ConstraintDomain;
}

pub mod params {
    use super::FieldElement;

    #[derive(Clone, Debug, Default)]
    pub struct Modulus;

    #[derive(Clone, Debug, Default)]
    pub struct PoseidonHasher;

    #[derive(Clone, Debug, Default)]
    pub struct StarkParameters;

    impl PoseidonHasher {
        pub fn hash(&self, inputs: &[FieldElement]) -> FieldElement {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            for input in inputs {
                input.hash(&mut hasher);
            }
            let value = hasher.finish();
            let mut bytes = Vec::new();
            for _ in 0..4 {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            FieldElement::from_bytes(&bytes)
        }
    }

    impl StarkParameters {
        pub fn blueprint_default() -> Self {
            Self::default()
        }

        pub fn poseidon_hasher(&self) -> PoseidonHasher {
            PoseidonHasher
        }

        pub fn modulus(&self) -> Modulus {
            Modulus
        }

        pub fn element_from_bytes(&self, bytes: &[u8]) -> FieldElement {
            FieldElement::from_bytes(bytes)
        }

        pub fn element_from_u64(&self, value: u64) -> FieldElement {
            FieldElement::from_bytes(&value.to_be_bytes())
        }

        pub fn element_from_u128(&self, value: u128) -> FieldElement {
            FieldElement::from_bytes(&value.to_be_bytes())
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FieldElement {
    hex: String,
}

impl FieldElement {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            hex: hex::encode(bytes),
        }
    }

    pub fn zero<T>(_modulus: T) -> Self {
        Self {
            hex: String::from("00"),
        }
    }

    pub fn one<T>(_modulus: T) -> Self {
        Self {
            hex: String::from("01"),
        }
    }

    pub fn to_hex(&self) -> String {
        self.hex.clone()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        hex::decode(&self.hex).unwrap_or_default()
    }
}

impl Serialize for FieldElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.hex)
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        Ok(Self { hex })
    }
}

pub mod circuit {
    use serde::{Deserialize, Serialize};

    use crate::reputation::{ReputationWeights, Tier};
    use crate::types::{Account, AttestedIdentityRequest, SignedTransaction};

    use super::params::{Modulus, StarkParameters};
    use super::{FieldElement};

    pub mod consensus {
        use serde::{Deserialize, Serialize};

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct VotePower {
            pub voter: String,
            pub weight: u64,
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ConsensusWitness {
            pub block_hash: String,
            pub round: u64,
            pub leader_proposal: String,
            pub quorum_threshold: u64,
            pub pre_votes: Vec<VotePower>,
            pub pre_commits: Vec<VotePower>,
            pub commit_votes: Vec<VotePower>,
            pub vrf_outputs: Vec<String>,
            pub witness_commitments: Vec<String>,
            pub reputation_roots: Vec<String>,
        }

        #[derive(Clone, Debug, Default)]
        pub struct ConsensusCircuit {
            pub witness: ConsensusWitness,
        }

        #[derive(Clone, Debug, Default)]
        pub struct VotePowerAggregator;

        pub use VotePower as VotePowerAlias;
    }

    pub mod identity {
        use serde::{Deserialize, Serialize};

        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub struct IdentityWitness {
            pub wallet_pk: String,
            pub wallet_addr: String,
            pub vrf_tag: String,
            pub epoch_nonce: String,
            pub state_root: String,
            pub identity_root: String,
            pub initial_reputation: i64,
            pub commitment: String,
            pub identity_leaf: String,
            pub identity_path: Vec<String>,
        }

        #[derive(Clone, Debug, Default)]
        pub struct IdentityCircuit {
            pub witness: IdentityWitness,
        }
    }

    pub mod pruning {
        use serde::{Deserialize, Serialize};

        pub type PrefixedDigest = [u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct PruningWitness {
            pub previous_tx_root: String,
            pub pruned_tx_root: String,
            pub original_transactions: Vec<String>,
            pub removed_transactions: Vec<String>,
            #[serde(default, with = "serde_prefixed_digest_hex")]
            pub pruning_binding_digest: PrefixedDigest,
            #[serde(default, with = "serde_prefixed_digest_vec_hex")]
            pub pruning_segment_commitments: Vec<PrefixedDigest>,
            pub pruning_fold: String,
        }

        #[derive(Clone, Debug, Default)]
        pub struct PruningCircuit {
            pub witness: PruningWitness,
        }

        mod serde_prefixed_digest_hex {
            use super::PrefixedDigest;
            use hex;
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S>(value: &PrefixedDigest, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&hex::encode(value))
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<PrefixedDigest, D::Error>
            where
                D: Deserializer<'de>,
            {
                let encoded = String::deserialize(deserializer)?;
                let bytes = hex::decode(&encoded).map_err(D::Error::custom)?;
                let expected = DOMAIN_TAG_LENGTH + DIGEST_LENGTH;
                if bytes.len() != expected {
                    return Err(D::Error::custom(format!(
                        "invalid prefixed digest length: expected {expected} bytes, found {}",
                        bytes.len()
                    )));
                }
                let mut digest = [0u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];
                digest.copy_from_slice(&bytes);
                Ok(digest)
            }
        }

        mod serde_prefixed_digest_vec_hex {
            use super::PrefixedDigest;
            use hex;
            use serde::de::{SeqAccess, Visitor};
            use serde::ser::SerializeSeq;
            use serde::{Deserialize, Deserializer, Serializer};
            use std::fmt;

            pub fn serialize<S>(values: &Vec<PrefixedDigest>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(&hex::encode(value))?;
                }
                seq.end()
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PrefixedDigest>, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct PrefixedDigestVecVisitor;

                impl<'de> Visitor<'de> for PrefixedDigestVecVisitor {
                    type Value = Vec<PrefixedDigest>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("a sequence of hex-encoded prefixed digests")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: SeqAccess<'de>,
                    {
                        let mut values = Vec::new();
                        while let Some(encoded) = seq.next_element::<String>()? {
                            let bytes = hex::decode(&encoded).map_err(A::Error::custom)?;
                            let expected = DOMAIN_TAG_LENGTH + DIGEST_LENGTH;
                            if bytes.len() != expected {
                                return Err(A::Error::custom(format!(
                                    "invalid prefixed digest length: expected {expected} bytes, found {}",
                                    bytes.len()
                                )));
                            }
                            let mut digest = [0u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];
                            digest.copy_from_slice(&bytes);
                            values.push(digest);
                        }
                        Ok(values)
                    }
                }

                deserializer.deserialize_seq(PrefixedDigestVecVisitor)
            }
        }
    }

    pub mod recursive {
        use serde::{Deserialize, Serialize};

        pub type PrefixedDigest = [u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct RecursiveWitness {
            pub previous_commitment: Option<String>,
            pub aggregated_commitment: String,
            pub identity_commitments: Vec<String>,
            pub tx_commitments: Vec<String>,
            pub uptime_commitments: Vec<String>,
            pub consensus_commitments: Vec<String>,
            pub state_commitment: String,
            pub global_state_root: String,
            pub utxo_root: String,
            pub reputation_root: String,
            pub timetoke_root: String,
            pub zsi_root: String,
            pub proof_root: String,
            #[serde(default, with = "serde::prefixed_digest")]
            pub pruning_binding_digest: PrefixedDigest,
            #[serde(default, with = "serde::prefixed_digest_vec")]
            pub pruning_segment_commitments: Vec<PrefixedDigest>,
            pub block_height: u64,
        }

        #[derive(Clone, Debug, Default)]
        pub struct RecursiveCircuit {
            pub witness: RecursiveWitness,
        }

        mod serde {
            use super::PrefixedDigest;
            use hex; // ensure hex crate available
            use serde::de::{SeqAccess, Visitor};
            use serde::ser::SerializeSeq;
            use serde::{Deserialize, Deserializer, Serializer};
            use std::fmt;

            const EXPECTED_LENGTH: usize = DOMAIN_TAG_LENGTH + DIGEST_LENGTH;

            fn decode_prefixed_digest(bytes: &[u8]) -> Result<PrefixedDigest, String> {
                if bytes.len() != EXPECTED_LENGTH {
                    return Err(format!(
                        "invalid digest length: expected {} bytes, found {}",
                        EXPECTED_LENGTH,
                        bytes.len()
                    ));
                }
                let mut digest = [0u8; EXPECTED_LENGTH];
                digest.copy_from_slice(bytes);
                Ok(digest)
            }

            pub mod prefixed_digest {
                use super::*;

                pub fn serialize<S>(value: &PrefixedDigest, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    serializer.serialize_str(&hex::encode(value))
                }

                pub fn deserialize<'de, D>(deserializer: D) -> Result<PrefixedDigest, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    let encoded = String::deserialize(deserializer)?;
                    let bytes = hex::decode(&encoded)
                        .map_err(|err| D::Error::custom(err.to_string()))?;
                    decode_prefixed_digest(&bytes).map_err(D::Error::custom)
                }
            }

            pub mod prefixed_digest_vec {
                use super::*;

                pub fn serialize<S>(values: &Vec<PrefixedDigest>, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    let mut seq = serializer.serialize_seq(Some(values.len()))?;
                    for value in values {
                        seq.serialize_element(&hex::encode(value))?;
                    }
                    seq.end()
                }

                pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PrefixedDigest>, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    struct PrefixedDigestVecVisitor;

                    impl<'de> Visitor<'de> for PrefixedDigestVecVisitor {
                        type Value = Vec<PrefixedDigest>;

                        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                            formatter.write_str("a sequence of hex-encoded prefixed digests")
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                        where
                            A: SeqAccess<'de>,
                        {
                            let mut values = Vec::new();
                            while let Some(encoded) = seq.next_element::<String>()? {
                                let bytes = hex::decode(&encoded)
                                    .map_err(|err| A::Error::custom(err.to_string()))?;
                                let digest = decode_prefixed_digest(&bytes)
                                    .map_err(A::Error::custom)?;
                                values.push(digest);
                            }
                            Ok(values)
                        }
                    }

                    deserializer.deserialize_seq(PrefixedDigestVecVisitor)
                }
            }
        }
    }

    pub mod state {
        use serde::{Deserialize, Serialize};

        use crate::reputation::{ReputationWeights, Tier};
        use crate::types::{Account, AttestedIdentityRequest, SignedTransaction};

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct StateWitness {
            pub prev_state_root: String,
            pub new_state_root: String,
            pub identities: Vec<AttestedIdentityRequest>,
            pub transactions: Vec<SignedTransaction>,
            pub accounts_before: Vec<Account>,
            pub accounts_after: Vec<Account>,
            pub required_tier: Tier,
            pub reputation_weights: ReputationWeights,
        }

        #[derive(Clone, Debug, Default)]
        pub struct StateCircuit {
            pub witness: StateWitness,
        }
    }

    pub mod transaction {
        use serde::{Deserialize, Serialize};

        use crate::reputation::{ReputationWeights, Tier};
        use crate::types::{Account, SignedTransaction};

        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct TransactionWitness {
            pub signed_tx: SignedTransaction,
            pub sender_account: Account,
            pub receiver_account: Option<Account>,
            pub required_tier: Tier,
            pub reputation_weights: ReputationWeights,
        }

        #[derive(Clone, Debug, Default)]
        pub struct TransactionCircuit {
            pub witness: TransactionWitness,
        }
    }

    pub mod uptime {
        use serde::{Deserialize, Serialize};

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct UptimeWitness {
            pub wallet_address: String,
            pub node_clock: u64,
            pub epoch: u64,
            pub head_hash: String,
            pub window_start: u64,
            pub window_end: u64,
            pub commitment: String,
        }

        #[derive(Clone, Debug, Default)]
        pub struct UptimeCircuit {
            pub witness: UptimeWitness,
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TraceSegment {
        pub name: String,
        pub columns: Vec<String>,
        pub rows: Vec<Vec<FieldElement>>,
    }

    impl TraceSegment {
        pub fn new(
            name: impl Into<String>,
            columns: Vec<String>,
            rows: Vec<Vec<FieldElement>>,
        ) -> Result<Self, super::CircuitError> {
            if columns.is_empty() {
                return Err(super::CircuitError::InvalidWitness(
                    "trace segment requires at least one column".into(),
                ));
            }
            Ok(Self {
                name: name.into(),
                columns,
                rows,
            })
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ExecutionTrace {
        pub segments: Vec<TraceSegment>,
    }

    impl ExecutionTrace {
        pub fn from_segments(segments: Vec<TraceSegment>) -> Result<Self, super::CircuitError> {
            if segments.is_empty() {
                return Err(super::CircuitError::InvalidWitness(
                    "execution trace must contain at least one segment".into(),
                ));
            }
            Ok(Self { segments })
        }

        pub fn single(segment: TraceSegment) -> Result<Self, super::CircuitError> {
            Self::from_segments(vec![segment])
        }
    }

    #[derive(Clone, Debug, thiserror::Error)]
    pub enum CircuitError {
        #[error("constraint violation: {0}")]
        ConstraintViolation(String),
        #[error("invalid witness data: {0}")]
        InvalidWitness(String),
        #[error("unsupported operation: {0}")]
        Unsupported(&'static str),
    }

    pub trait StarkCircuit {
        fn name(&self) -> &'static str;
        fn evaluate_constraints(&self) -> Result<(), CircuitError>;
        fn generate_trace(&self, _parameters: &StarkParameters) -> Result<ExecutionTrace, CircuitError>;
        fn define_air(
            &self,
            _parameters: &StarkParameters,
            _trace: &ExecutionTrace,
        ) -> Result<crate::stwo::air::AirDefinition, CircuitError>;
        fn verify_air(
            &self,
            _parameters: &StarkParameters,
            _trace: &ExecutionTrace,
        ) -> Result<(), CircuitError> {
            Ok(())
        }
    }

    pub fn string_to_field(parameters: &StarkParameters, value: &str) -> FieldElement {
        let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
        parameters.element_from_bytes(&bytes)
    }

    pub use consensus::{ConsensusCircuit, ConsensusWitness, VotePower};
    pub use identity::{IdentityCircuit, IdentityWitness};
    pub use pruning::{PruningCircuit, PruningWitness};
    pub use recursive::{RecursiveCircuit, RecursiveWitness};
    pub use state::{StateCircuit, StateWitness};
    pub use transaction::{TransactionCircuit, TransactionWitness};
    pub use uptime::{UptimeCircuit, UptimeWitness};
}

pub mod conversions {
    use super::FieldElement;

    pub fn field_to_base(value: &FieldElement) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = value.to_bytes();
        let copy_len = bytes.len().min(out.len());
        out[..copy_len].copy_from_slice(&bytes[..copy_len]);
        out
    }

    pub fn field_to_secure(value: &FieldElement) -> Vec<u8> {
        field_to_base(value).to_vec()
    }
}

pub mod official_adapter {
    use crate::stwo::air::AirDefinition;
    use crate::stwo::circuit::ExecutionTrace;
    use crate::stwo::params::StarkParameters;

    #[derive(Clone, Debug, Default)]
    pub struct BlueprintComponent<'a> {
        _marker: std::marker::PhantomData<&'a ()>,
    }

    impl<'a> BlueprintComponent<'a> {
        pub fn new(
            _air: &AirDefinition,
            _trace: &ExecutionTrace,
            _params: &StarkParameters,
        ) -> Result<Self, &'static str> {
            Ok(Self { _marker: PhantomData })
        }
    }

    pub trait Component {}

    pub trait ComponentProver<T> {}

    impl<'a> Component for BlueprintComponent<'a> {}

    impl<'a, T> ComponentProver<T> for BlueprintComponent<'a> {}

    pub type ColumnVec<T> = Vec<T>;
    pub type TreeVec<T> = Vec<T>;
}

pub mod fri {
    use super::air::AirDefinition;
    use super::circuit::ExecutionTrace;
    use super::params::StarkParameters;
    use super::proof::{CommitmentSchemeProofData, FriProof};

    #[derive(Clone, Debug)]
    pub struct FriProver<'a> {
        _marker: std::marker::PhantomData<&'a StarkParameters>,
    }

    impl<'a> FriProver<'a> {
        pub fn new(_parameters: &'a StarkParameters) -> Self {
            Self { _marker: std::marker::PhantomData }
        }

        pub fn prove(
            &self,
            _air: &AirDefinition,
            _trace: &ExecutionTrace,
            _public_inputs: &[super::FieldElement],
        ) -> FriProverOutput {
            FriProverOutput {
                commitment_proof: CommitmentSchemeProofData::default(),
                fri_proof: FriProof::default(),
            }
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct FriProverOutput {
        pub commitment_proof: CommitmentSchemeProofData,
        pub fri_proof: FriProof,
    }
}

pub mod proof {
    use serde::{Deserialize, Serialize};

    use super::circuit::{ExecutionTrace, RecursiveWitness};
    use super::params::{PoseidonHasher, StarkParameters};
    use super::FieldElement;

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
    pub struct CommitmentSchemeProofData {
        pub encoded: Vec<u8>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
    pub struct FriProof {
        pub encoded: Vec<u8>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub enum ProofKind {
        Transaction,
        State,
        Pruning,
        Recursive,
        Identity,
        Uptime,
        Consensus,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum ProofPayload {
        Transaction(crate::stwo::circuit::TransactionWitness),
        State(crate::stwo::circuit::StateWitness),
        Pruning(crate::stwo::circuit::PruningWitness),
        Recursive(crate::stwo::circuit::RecursiveWitness),
        Identity(crate::stwo::circuit::IdentityWitness),
        Uptime(crate::stwo::circuit::UptimeWitness),
        Consensus(crate::stwo::circuit::ConsensusWitness),
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StarkProof {
        pub kind: ProofKind,
        pub commitment: String,
        pub public_inputs: Vec<String>,
        pub payload: ProofPayload,
        pub trace: ExecutionTrace,
        pub commitment_proof: CommitmentSchemeProofData,
        pub fri_proof: FriProof,
    }

    impl StarkProof {
        pub fn new(
            kind: ProofKind,
            payload: ProofPayload,
            public_inputs: Vec<FieldElement>,
            trace: ExecutionTrace,
            commitment_proof: CommitmentSchemeProofData,
            fri_proof: FriProof,
            hasher: &PoseidonHasher,
        ) -> Self {
            let commitment = hasher.hash(&public_inputs).to_hex();
            let public_inputs = public_inputs
                .into_iter()
                .map(FieldElement::to_hex)
                .collect();
            Self {
                kind,
                commitment,
                public_inputs,
                payload,
                trace,
                commitment_proof,
                fri_proof,
            }
        }

        pub fn with_blueprint_hasher(
            kind: ProofKind,
            payload: ProofPayload,
            inputs: Vec<FieldElement>,
            trace: ExecutionTrace,
            commitment_proof: CommitmentSchemeProofData,
            fri_proof: FriProof,
        ) -> Self {
            let params = StarkParameters::blueprint_default();
            let hasher = params.poseidon_hasher();
            Self::new(
                kind,
                payload,
                inputs,
                trace,
                commitment_proof,
                fri_proof,
                &hasher,
            )
        }
    }
}

pub mod verifier {
    use crate::errors::ChainResult;
    use crate::proof_system::ProofVerifier;
    use crate::rpp::ProofSystemKind;
    use crate::stwo::aggregation::StateCommitmentSnapshot;
    use crate::types::ChainProof;
    use rpp_pruning::Envelope;

    use super::params::StarkParameters;
    use super::proof::StarkProof;

    fn bypass_warn(operation: &str) {
        warn!(
            target = "runtime.proof.bypass",
            operation,
            backend = "stwo",
            bypass = true,
            reason = STWO_BYPASS_REASON,
            "accepting proof via STWO bypass"
        );
    }

    #[derive(Clone, Default)]
    pub struct NodeVerifier {
        _parameters: StarkParameters,
    }

    impl NodeVerifier {
        pub fn new() -> Self {
            Self {
                _parameters: StarkParameters::blueprint_default(),
            }
        }

        pub fn with_parameters(parameters: StarkParameters) -> Self {
            Self {
                _parameters: parameters,
            }
        }

        pub fn verify_transaction_proof(&self, _proof: &StarkProof) -> ChainResult<()> {
            bypass_warn("transaction");
            Ok(())
        }

        pub fn verify_bundle(
            &self,
            _identity_proofs: &[ChainProof],
            _tx_proofs: &[ChainProof],
            _uptime_proofs: &[ChainProof],
            _consensus_proofs: &[ChainProof],
            _state_proof: &ChainProof,
            _pruning_proof: &ChainProof,
            _pruning_envelope: &Envelope,
            _recursive_proof: &ChainProof,
            _state_commitments: &StateCommitmentSnapshot,
            _expected_previous_commitment: Option<&str>,
        ) -> ChainResult<String> {
            bypass_warn("block-bundle");
            Ok("stwo-bypass".to_string())
        }
    }

    impl ProofVerifier for NodeVerifier {
        fn system(&self) -> ProofSystemKind {
            ProofSystemKind::Stwo
        }

        fn verify_transaction(&self, _proof: &ChainProof) -> ChainResult<()> {
            bypass_warn("transaction");
            Ok(())
        }

        fn verify_identity(&self, _proof: &ChainProof) -> ChainResult<()> {
            bypass_warn("identity");
            Ok(())
        }

        fn verify_state(&self, _proof: &ChainProof) -> ChainResult<()> {
            bypass_warn("state");
            Ok(())
        }

        fn verify_pruning(&self, _proof: &ChainProof) -> ChainResult<()> {
            bypass_warn("pruning");
            Ok(())
        }

        fn verify_recursive(&self, _proof: &ChainProof) -> ChainResult<()> {
            bypass_warn("recursive");
            Ok(())
        }

        fn verify_uptime(&self, _proof: &ChainProof) -> ChainResult<()> {
            bypass_warn("uptime");
            Ok(())
        }

        fn verify_consensus(&self, _proof: &ChainProof) -> ChainResult<()> {
            bypass_warn("consensus");
            Ok(())
        }
    }
}
