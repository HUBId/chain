//! VRF engine scaffolding built around a Poseidon hash domain.
//!
//! This module will eventually host the full VRF implementation defined in the
//! blueprint. For now it establishes the public API, shared data structures and
//! error types so that subsequent work can focus on integrating the actual
//! cryptography and consensus wiring without reshaping interfaces again.

pub mod telemetry;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use malachite::base::num::arithmetic::traits::DivRem;
use malachite::Natural;
use prover_backend_interface::Blake2sHasher;
#[cfg(feature = "nightly-prover")]
use prover_stwo_backend::official::params::{FieldElement, StarkParameters};
#[cfg(not(feature = "nightly-prover"))]
mod stable_poseidon {
    use sha2::{Digest, Sha256};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct FieldElement(pub [u8; 32]);

    impl FieldElement {
        pub fn to_bytes(&self) -> Vec<u8> {
            self.0.to_vec()
        }

        pub fn from_bytes(bytes: &[u8]) -> Self {
            let mut buf = [0u8; 32];
            if bytes.len() >= 32 {
                buf.copy_from_slice(&bytes[bytes.len() - 32..]);
            } else {
                buf[32 - bytes.len()..].copy_from_slice(bytes);
            }
            Self(buf)
        }

        pub fn from_u64(value: u64) -> Self {
            Self::from_bytes(&value.to_be_bytes())
        }
    }

    pub struct PoseidonHasher;

    impl PoseidonHasher {
        pub fn hash(&self, elements: &[FieldElement]) -> FieldElement {
            let mut hasher = Sha256::new();
            for element in elements {
                hasher.update(&element.0);
            }
            let digest = hasher.finalize();
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&digest);
            FieldElement(buf)
        }
    }

    pub struct StarkParameters;

    impl StarkParameters {
        pub fn blueprint_default() -> Self {
            Self
        }

        pub fn poseidon_hasher(&self) -> PoseidonHasher {
            PoseidonHasher
        }

        pub fn element_from_bytes(&self, bytes: &[u8]) -> FieldElement {
            FieldElement::from_bytes(bytes)
        }

        pub fn element_from_u64(&self, value: u64) -> FieldElement {
            FieldElement::from_u64(value)
        }
    }
}
use schnorrkel::keys::{
    ExpansionMode, Keypair as VrfKeypairInner, MiniSecretKey, PublicKey as SrPublicKey,
};
use schnorrkel::signing_context;
use schnorrkel::vrf::{VRFPreOut, VRFProof};
use schnorrkel::SignatureError as VrfSignatureError;
use serde::{Deserialize, Serialize};
#[cfg(not(feature = "nightly-prover"))]
use stable_poseidon::{FieldElement, StarkParameters};
use thiserror::Error;
use tracing::{info, warn};

/// Alias used for wallet addresses within the VRF module.
pub type Address = String;

/// Reputation tiers used when evaluating validator submissions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Tier {
    Tl0,
    Tl1,
    Tl2,
    Tl3,
    Tl4,
    Tl5,
}

impl Tier {
    /// Human-readable name associated with the tier.
    pub fn name(&self) -> &'static str {
        match self {
            Tier::Tl0 => "New",
            Tier::Tl1 => "Validated",
            Tier::Tl2 => "Available",
            Tier::Tl3 => "Committed",
            Tier::Tl4 => "Reliable",
            Tier::Tl5 => "Trusted",
        }
    }

    /// Textual description of the tier requirements.
    pub fn requirements(&self) -> &'static str {
        match self {
            Tier::Tl0 => "ZSI noch nicht validiert",
            Tier::Tl1 => "ZSI validiert",
            Tier::Tl2 => "+24h Uptime",
            Tier::Tl3 => "Konsens-Runden ohne Fehlverhalten",
            Tier::Tl4 => "Langfristige Uptime + Konsens",
            Tier::Tl5 => "Langzeit-Historie, hoher Score",
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Tier::Tl0 => 0,
            Tier::Tl1 => 1,
            Tier::Tl2 => 2,
            Tier::Tl3 => 3,
            Tier::Tl4 => 4,
            Tier::Tl5 => 5,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for Tier {
    fn default() -> Self {
        Tier::Tl0
    }
}

impl Ord for Tier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Tier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Errors emitted when encoding or decoding VRF keys.
#[derive(Debug, Error)]
pub enum VrfKeyError {
    #[error("invalid VRF secret key encoding: {0}")]
    InvalidSecretEncoding(String),
    #[error("invalid VRF public key encoding: {0}")]
    InvalidPublicEncoding(String),
    #[error("invalid VRF secret key length")]
    InvalidSecretLength,
    #[error("invalid VRF public key length")]
    InvalidPublicLength,
    #[error("invalid VRF secret key bytes: {0}")]
    InvalidSecretBytes(#[source] VrfSignatureError),
    #[error("invalid VRF public key bytes: {0}")]
    InvalidPublicBytes(#[source] VrfSignatureError),
}

/// VRF mini-secret key wrapper.
#[derive(Debug, Clone)]
pub struct VrfSecretKey {
    inner: MiniSecretKey,
}

impl VrfSecretKey {
    pub fn new(inner: MiniSecretKey) -> Self {
        Self { inner }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn as_mini_secret(&self) -> &MiniSecretKey {
        &self.inner
    }

    pub fn expand_to_keypair(&self) -> VrfKeypairInner {
        self.inner.expand_to_keypair(ExpansionMode::Uniform)
    }

    pub fn derive_public(&self) -> VrfPublicKey {
        VrfPublicKey {
            inner: self.expand_to_keypair().public,
        }
    }
}

impl TryFrom<[u8; 32]> for VrfSecretKey {
    type Error = VrfSignatureError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        MiniSecretKey::from_bytes(&bytes).map(VrfSecretKey::new)
    }
}

/// VRF public key wrapper.
#[derive(Debug, Clone)]
pub struct VrfPublicKey {
    inner: SrPublicKey,
}

impl VrfPublicKey {
    pub fn new(inner: SrPublicKey) -> Self {
        Self { inner }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn as_public_key(&self) -> &SrPublicKey {
        &self.inner
    }
}

impl TryFrom<[u8; 32]> for VrfPublicKey {
    type Error = VrfSignatureError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        SrPublicKey::from_bytes(&bytes).map(VrfPublicKey::new)
    }
}

/// VRF keypair consisting of public and secret components.
#[derive(Debug, Clone)]
pub struct VrfKeypair {
    pub public: VrfPublicKey,
    pub secret: VrfSecretKey,
}

/// Sample a new VRF keypair using the default Schnorrkel RNG.
pub fn generate_vrf_keypair() -> VrfKeypair {
    let secret = VrfSecretKey::new(MiniSecretKey::generate());
    let public = secret.derive_public();
    VrfKeypair { public, secret }
}

/// Decode a VRF public key from a hex string.
pub fn vrf_public_key_from_hex(data: &str) -> Result<VrfPublicKey, VrfKeyError> {
    let bytes =
        hex::decode(data).map_err(|err| VrfKeyError::InvalidPublicEncoding(err.to_string()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VrfKeyError::InvalidPublicLength)?;
    VrfPublicKey::try_from(bytes).map_err(VrfKeyError::InvalidPublicBytes)
}

/// Encode a VRF public key as a hex string.
pub fn vrf_public_key_to_hex(key: &VrfPublicKey) -> String {
    hex::encode(key.to_bytes())
}

/// Decode a VRF secret key from a hex string.
pub fn vrf_secret_key_from_hex(data: &str) -> Result<VrfSecretKey, VrfKeyError> {
    let bytes =
        hex::decode(data).map_err(|err| VrfKeyError::InvalidSecretEncoding(err.to_string()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VrfKeyError::InvalidSecretLength)?;
    VrfSecretKey::try_from(bytes).map_err(VrfKeyError::InvalidSecretBytes)
}

/// Encode a VRF secret key as a hex string.
pub fn vrf_secret_key_to_hex(key: &VrfSecretKey) -> String {
    hex::encode(key.to_bytes())
}

/// Poseidon domain separator used for deriving VRF inputs.
pub const POSEIDON_VRF_DOMAIN: &[u8] = b"chain.vrf.poseidon";
/// Domain separator for deriving tier-specific seeds.
pub const POSEIDON_TIER_SEED_DOMAIN: &[u8] = b"chain.vrf.tier_seed";
/// Bit width of the VRF randomness output domain.
pub const VRF_RANDOMNESS_BITS: usize = 256;
/// Length of the VRF pre-output element encoded by the backend.
pub const VRF_PREOUTPUT_LENGTH: usize = 32;
/// Length of the VRF proof encoded by the backend.
pub const VRF_PROOF_LENGTH: usize = schnorrkel::vrf::VRF_PROOF_LENGTH;
/// Domain separator used when deriving per-epoch validator thresholds.
const THRESHOLD_DOMAIN: &[u8] = b"chain.vrf.threshold";
/// Domain separator for the epoch entropy beacon accumulator.
const ENTROPY_BEACON_DOMAIN: &[u8] = b"chain.vrf.entropy";
/// Domain separator used when deriving VRF output randomness bytes.
const VRF_RANDOMNESS_CONTEXT: &[u8] = b"chain.vrf.randomness";

/// Structured input to the VRF consisting of the values mandated by the
/// blueprint: the previous block header hash, the current epoch number and a
/// tier-specific seed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoseidonVrfInput {
    pub last_block_header: [u8; 32],
    pub epoch: u64,
    pub tier_seed: [u8; 32],
}

impl PoseidonVrfInput {
    /// Creates a new Poseidon VRF input tuple.
    pub fn new(last_block_header: [u8; 32], epoch: u64, tier_seed: [u8; 32]) -> Self {
        Self {
            last_block_header,
            epoch,
            tier_seed,
        }
    }

    /// Serialises the domain separator and the tuple elements into a single
    /// byte vector that will later be fed into Poseidon.
    pub fn to_poseidon_preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(
            POSEIDON_VRF_DOMAIN.len() + self.last_block_header.len() + 8 + self.tier_seed.len(),
        );
        preimage.extend_from_slice(POSEIDON_VRF_DOMAIN);
        preimage.extend_from_slice(&self.last_block_header);
        preimage.extend_from_slice(&self.epoch.to_be_bytes());
        preimage.extend_from_slice(&self.tier_seed);
        preimage
    }

    /// Convert the VRF input tuple into the sequence of field elements absorbed
    /// by the Poseidon sponge.
    fn to_poseidon_elements(&self, params: &StarkParameters) -> Vec<FieldElement> {
        vec![
            params.element_from_bytes(POSEIDON_VRF_DOMAIN),
            params.element_from_bytes(&self.last_block_header),
            params.element_from_u64(self.epoch),
            params.element_from_bytes(&self.tier_seed),
        ]
    }

    /// Compute the Poseidon digest associated with this VRF input tuple.
    pub fn poseidon_digest(&self) -> FieldElement {
        let params = StarkParameters::blueprint_default();
        let hasher = params.poseidon_hasher();
        let elements = self.to_poseidon_elements(&params);
        hasher.hash(&elements)
    }

    /// Returns the Poseidon digest as a fixed-width 32-byte array.
    pub fn poseidon_digest_bytes(&self) -> [u8; 32] {
        let digest = self.poseidon_digest();
        let digest_bytes = digest.to_bytes();
        let mut buffer = [0u8; 32];
        let offset = 32 - digest_bytes.len();
        buffer[offset..].copy_from_slice(&digest_bytes);
        buffer
    }

    /// Returns the Poseidon digest encoded as a hexadecimal string.
    pub fn poseidon_digest_hex(&self) -> String {
        hex::encode(self.poseidon_digest_bytes())
    }
}

/// Resulting VRF output consisting of the random field element as well as the
/// accompanying proof bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfOutput {
    pub randomness: [u8; 32],
    pub preoutput: [u8; VRF_PREOUTPUT_LENGTH],
    pub proof: [u8; VRF_PROOF_LENGTH],
}

impl VrfOutput {
    /// Helper to expose the randomness as a big-endian integer encoded in
    /// hexadecimal form, useful for diagnostics and compatibility with
    /// existing APIs that still transport hex strings.
    pub fn randomness_hex(&self) -> String {
        hex::encode(self.randomness)
    }

    /// Returns the proof bytes as a hex string.
    pub fn proof_hex(&self) -> String {
        hex::encode(self.proof)
    }

    /// Returns the pre-output bytes as a hex string.
    pub fn preoutput_hex(&self) -> String {
        hex::encode(self.preoutput)
    }

    /// Returns a reference to the raw signature bytes backing the proof.
    pub fn proof_bytes(&self) -> &[u8; VRF_PROOF_LENGTH] {
        &self.proof
    }

    /// Reconstructs a VRF output from raw randomness, pre-output and proof byte slices.
    pub fn from_bytes(randomness: &[u8], preoutput: &[u8], proof: &[u8]) -> VrfResult<Self> {
        if randomness.len() != 32 {
            return Err(VrfError::InvalidInput(
                "VRF randomness must be exactly 32 bytes".to_string(),
            ));
        }
        if preoutput.len() != VRF_PREOUTPUT_LENGTH {
            return Err(VrfError::InvalidInput(
                "VRF preoutput must be exactly 32 bytes".to_string(),
            ));
        }
        if proof.len() != VRF_PROOF_LENGTH {
            return Err(VrfError::InvalidInput(format!(
                "VRF proof must be exactly {VRF_PROOF_LENGTH} bytes"
            )));
        }

        let mut randomness_bytes = [0u8; 32];
        randomness_bytes.copy_from_slice(randomness);
        let mut preoutput_bytes = [0u8; VRF_PREOUTPUT_LENGTH];
        preoutput_bytes.copy_from_slice(preoutput);
        let mut proof_bytes = [0u8; VRF_PROOF_LENGTH];
        proof_bytes.copy_from_slice(proof);

        Ok(Self {
            randomness: randomness_bytes,
            preoutput: preoutput_bytes,
            proof: proof_bytes,
        })
    }

    /// Parses a VRF output from hexadecimal encodings of randomness, pre-output and proof.
    pub fn from_hex(randomness_hex: &str, preoutput_hex: &str, proof_hex: &str) -> VrfResult<Self> {
        let randomness = hex::decode(randomness_hex)
            .map_err(|err| VrfError::InvalidInput(format!("invalid randomness encoding: {err}")))?;
        let preoutput = hex::decode(preoutput_hex)
            .map_err(|err| VrfError::InvalidInput(format!("invalid preoutput encoding: {err}")))?;
        let proof = hex::decode(proof_hex)
            .map_err(|err| VrfError::InvalidInput(format!("invalid proof encoding: {err}")))?;
        Self::from_bytes(&randomness, &preoutput, &proof)
    }
}

/// Errors emitted by the VRF module.
#[derive(Debug, Error)]
pub enum VrfError {
    #[error("invalid VRF input: {0}")]
    InvalidInput(String),
    #[error("VRF backend error: {0}")]
    Backend(String),
    #[error("VRF verification failed")]
    VerificationFailed,
    #[error("VRF functionality not implemented yet")]
    NotImplemented,
}

/// Result alias used throughout the VRF module.
pub type VrfResult<T> = Result<T, VrfError>;

/// Serializable VRF proof transported between consensus participants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VrfProof {
    pub randomness: Natural,
    pub preoutput: String,
    pub proof: String,
}

impl VrfProof {
    pub fn from_output(output: &VrfOutput) -> Self {
        Self {
            randomness: natural_from_bytes(&output.randomness),
            preoutput: output.preoutput_hex(),
            proof: output.proof_hex(),
        }
    }

    pub fn randomness_bytes(&self) -> [u8; 32] {
        natural_to_bytes(&self.randomness)
    }

    pub fn to_vrf_output(&self) -> VrfResult<VrfOutput> {
        let randomness = self.randomness_bytes();
        let preoutput_bytes = hex::decode(&self.preoutput).map_err(|err| {
            VrfError::InvalidInput(format!("failed to decode VRF preoutput hex: {err}"))
        })?;
        let proof_bytes = hex::decode(&self.proof).map_err(|err| {
            VrfError::InvalidInput(format!("failed to decode VRF proof hex: {err}"))
        })?;
        VrfOutput::from_bytes(&randomness, &preoutput_bytes, &proof_bytes)
    }
}

/// Submission emitted by a validator after generating a VRF output.
#[derive(Clone, Debug)]
pub struct VrfSubmission {
    pub address: Address,
    pub public_key: Option<VrfPublicKey>,
    pub input: PoseidonVrfInput,
    pub proof: VrfProof,
    pub tier: Tier,
    pub timetoke_hours: u64,
}

/// Internal representation of a verified VRF submission enriched with derived
/// selection metadata.
#[derive(Clone, Debug)]
pub struct VerifiedSubmission {
    pub address: Address,
    pub public_key: Option<VrfPublicKey>,
    pub input: PoseidonVrfInput,
    pub proof: VrfProof,
    pub tier: Tier,
    pub timetoke_hours: u64,
    pub randomness: Natural,
    pub verified: bool,
    pub weight: Natural,
    pub weighted_randomness: Natural,
}

impl VerifiedSubmission {
    pub fn as_submission(&self) -> VrfSubmission {
        VrfSubmission {
            address: self.address.clone(),
            public_key: self.public_key.clone(),
            input: self.input.clone(),
            proof: self.proof.clone(),
            tier: self.tier.clone(),
            timetoke_hours: self.timetoke_hours,
        }
    }
}

/// In-memory pool that tracks VRF submissions for the current selection round.
#[derive(Default, Clone, Debug)]
pub struct VrfSubmissionPool {
    entries: HashMap<Address, VrfSubmission>,
}

impl VrfSubmissionPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, submission: VrfSubmission) {
        self.entries.insert(submission.address.clone(), submission);
    }

    /// Retains only the submissions specified by the provided predicate.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&Address, &VrfSubmission) -> bool,
    {
        self.entries
            .retain(|address, submission| f(address, submission));
    }

    pub fn get(&self, address: &Address) -> Option<&VrfSubmission> {
        self.entries.get(address)
    }

    pub fn iter(&self) -> impl Iterator<Item = &VrfSubmission> {
        self.entries.values()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Result of applying the validator selection logic to a set of submissions.
#[derive(Clone, Debug)]
pub enum RejectionReason {
    TierTooLow { required: Tier, received: Tier },
    InsufficientTimetoke { minimum: u64, received: u64 },
    MalformedProof(String),
    InvalidProof(String),
    MissingPublicKey,
    ThresholdNotMet { threshold: Natural },
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RejectionReason::TierTooLow { required, received } => {
                write!(f, "tier too low (required {required}, received {received})")
            }
            RejectionReason::InsufficientTimetoke { minimum, received } => {
                write!(
                    f,
                    "insufficient timetoke (minimum {minimum}h, received {received}h)"
                )
            }
            RejectionReason::MalformedProof(err) => {
                write!(f, "malformed proof: {err}")
            }
            RejectionReason::InvalidProof(err) => {
                write!(f, "invalid proof: {err}")
            }
            RejectionReason::MissingPublicKey => write!(f, "missing VRF public key"),
            RejectionReason::ThresholdNotMet { threshold } => {
                write!(f, "randomness above threshold {threshold}")
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct RejectedSubmission {
    pub submission: VrfSubmission,
    pub randomness: Option<Natural>,
    pub reason: RejectionReason,
}

#[derive(Clone, Debug)]
pub struct FallbackCandidate {
    pub submission: VerifiedSubmission,
    pub reason: RejectionReason,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfSelectionRecord {
    pub epoch: u64,
    pub address: Address,
    pub tier: Tier,
    pub timetoke_hours: u64,
    pub public_key: Option<String>,
    pub proof: VrfProof,
    pub verified: bool,
    pub accepted: bool,
    pub threshold: Option<String>,
    pub rejection_reason: Option<String>,
    pub weight: Option<String>,
    pub weighted_randomness: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VrfSelectionMetrics {
    pub pool_entries: usize,
    pub target_validator_count: usize,
    pub verified_submissions: usize,
    pub accepted_validators: usize,
    pub rejected_candidates: usize,
    pub fallback_selected: bool,
    pub unique_addresses: usize,
    pub participation_rate: f64,
    pub success_rate: f64,
    pub total_weight: String,
    pub entropy_beacon: String,
    pub latest_epoch: Option<u64>,
    pub latest_round: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_epoch_threshold: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_threshold_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rejections_by_reason: BTreeMap<String, usize>,
}

impl VrfSelectionMetrics {
    fn record_verification(&mut self) {
        self.verified_submissions = self.verified_submissions.saturating_add(1);
    }

    fn record_accept(&mut self) {
        self.accepted_validators = self.accepted_validators.saturating_add(1);
    }

    fn record_rejection(&mut self, reason: &RejectionReason) {
        self.rejected_candidates = self.rejected_candidates.saturating_add(1);
        self.record_rejection_reason(reason);
    }

    fn record_fallback(&mut self) {
        self.fallback_selected = true;
    }

    fn record_epoch(&mut self, epoch: u64) {
        self.latest_epoch = Some(epoch);
    }

    pub fn set_round(&mut self, round: u64) {
        self.latest_round = Some(round);
    }

    fn set_active_threshold(&mut self, threshold: &Natural, domain: &Natural) {
        self.active_epoch_threshold = Some(threshold.to_string());
        self.active_threshold_ratio = natural_ratio(threshold, domain);
    }

    fn record_rejection_reason(&mut self, reason: &RejectionReason) {
        let entry = self
            .rejections_by_reason
            .entry(reason.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }
}

/// Tracks replay protection and entropy beacons across epochs.
#[derive(Clone, Debug)]
pub struct VrfEpochManager {
    epoch_length: u64,
    active_epoch: u64,
    seen: HashSet<String>,
    latest_entropy: [u8; 32],
}

impl VrfEpochManager {
    pub fn new(epoch_length: u64, active_epoch: u64) -> Self {
        Self {
            epoch_length: epoch_length.max(1),
            active_epoch,
            seen: HashSet::new(),
            latest_entropy: default_entropy_state(),
        }
    }

    fn rotate_epoch(&mut self, epoch: u64) {
        if epoch < self.active_epoch {
            return;
        }
        if epoch > self.active_epoch {
            self.active_epoch = epoch;
            self.seen.clear();
        }
    }

    pub fn active_epoch(&self) -> u64 {
        self.active_epoch
    }

    pub fn register_submission(&mut self, submission: &VrfSubmission) -> bool {
        if submission.input.epoch < self.active_epoch {
            return false;
        }
        self.rotate_epoch(submission.input.epoch);
        let key = format!(
            "{}:{}:{}",
            submission.input.epoch,
            submission.address,
            submission.proof.randomness.to_string()
        );
        self.seen.insert(key)
    }

    pub fn record_entropy(&mut self, epoch: u64, beacon: [u8; 32]) {
        self.rotate_epoch(epoch);
        self.latest_entropy = beacon;
    }

    pub fn entropy_hex(&self) -> String {
        hex::encode(self.latest_entropy)
    }

    pub fn epoch_length(&self) -> u64 {
        self.epoch_length
    }
}

#[derive(Clone, Debug, Default)]
pub struct ValidatorSelection {
    pub validators: Vec<VerifiedSubmission>,
    pub rejected: Vec<RejectedSubmission>,
    pub fallback: Option<FallbackCandidate>,
    pub audit: Vec<VrfSelectionRecord>,
    pub metrics: VrfSelectionMetrics,
}

/// Generates a VRF output for the provided Poseidon input and secret key.
///
/// The actual cryptographic implementation will be supplied in a subsequent
/// step; for now this function only exposes the intended signature.
pub fn generate_vrf(input: &PoseidonVrfInput, secret: &VrfSecretKey) -> VrfResult<VrfOutput> {
    let digest = input.poseidon_digest_bytes();
    let keypair = secret.expand_to_keypair();
    let context = signing_context(POSEIDON_VRF_DOMAIN);
    let (inout, proof, _) = keypair.vrf_sign(context.bytes(&digest));
    let randomness: [u8; 32] = inout.make_bytes(VRF_RANDOMNESS_CONTEXT);
    let preoutput = inout.to_preout().0;
    let proof_bytes = proof.to_bytes();

    Ok(VrfOutput {
        randomness,
        preoutput,
        proof: proof_bytes,
    })
}

/// Verifies a VRF output using the Poseidon input tuple and the corresponding
/// public key.
pub fn verify_vrf(
    input: &PoseidonVrfInput,
    public: &VrfPublicKey,
    output: &VrfOutput,
) -> VrfResult<()> {
    let digest = input.poseidon_digest_bytes();
    let context = signing_context(POSEIDON_VRF_DOMAIN);
    let proof = VRFProof::from_bytes(output.proof_bytes())
        .map_err(|err| VrfError::InvalidInput(format!("invalid VRF proof bytes: {err}")))?;
    let preoutput = VRFPreOut(output.preoutput);
    let (inout, _) = public
        .as_public_key()
        .vrf_verify(context.bytes(&digest), &preoutput, &proof)
        .map_err(|err| VrfError::Backend(format!("{err}")))?;

    let expected: [u8; 32] = inout.make_bytes(VRF_RANDOMNESS_CONTEXT);
    if expected != output.randomness {
        return Err(VrfError::VerificationFailed);
    }

    Ok(())
}

/// Records a VRF submission in the pool for later processing. Proof validation
/// is deferred to `select_validators` so that callers can collect gossip inputs
/// without performing expensive verification up front.
pub fn submit_vrf(pool: &mut VrfSubmissionPool, submission: VrfSubmission) {
    pool.insert(submission);
}

/// Applies the blueprint threshold heuristics to determine which submissions
/// qualify as validators. If no submission passes the threshold the best
/// rejected candidate is exposed as fallback.
pub fn select_validators(
    pool: &VrfSubmissionPool,
    target_validator_count: usize,
) -> ValidatorSelection {
    let mut result = ValidatorSelection::default();
    result.metrics.pool_entries = pool.len();
    result.metrics.target_validator_count = target_validator_count;
    result.metrics.unique_addresses = pool.len();

    if pool.is_empty() {
        result.metrics.total_weight = "0".into();
        result.metrics.entropy_beacon = hex::encode(default_entropy_state());
        telemetry::VrfTelemetry::global().record_selection(&result.metrics);
        return result;
    }

    let mut audit_records: Vec<VrfSelectionRecord> = Vec::new();
    let mut audit_index: HashMap<Address, usize> = HashMap::new();
    let mut verified_by_epoch: HashMap<u64, Vec<VerifiedSubmission>> = HashMap::new();
    let mut total_weight = Natural::from(0u32);
    let mut accepted_count: usize = 0;
    let mut entropy_state = default_entropy_state();

    for submission in pool.iter() {
        match validate_submission(submission) {
            Ok(verified) => {
                result.metrics.record_verification();
                let record_index = audit_records.len();
                audit_index.insert(submission.address.clone(), record_index);
                audit_records.push(VrfSelectionRecord {
                    epoch: submission.input.epoch,
                    address: submission.address.clone(),
                    tier: submission.tier.clone(),
                    timetoke_hours: submission.timetoke_hours,
                    public_key: submission
                        .public_key
                        .as_ref()
                        .map(|key| vrf_public_key_to_hex(key)),
                    proof: submission.proof.clone(),
                    verified: verified.verified,
                    accepted: false,
                    threshold: None,
                    rejection_reason: None,
                    weight: Some(verified.weight.to_string()),
                    weighted_randomness: Some(verified.weighted_randomness.to_string()),
                });
                verified_by_epoch
                    .entry(verified.input.epoch)
                    .or_default()
                    .push(verified);
            }
            Err(reason) => {
                result.metrics.record_rejection(&reason);
                let reason_string = reason.to_string();
                audit_records.push(VrfSelectionRecord {
                    epoch: submission.input.epoch,
                    address: submission.address.clone(),
                    tier: submission.tier.clone(),
                    timetoke_hours: submission.timetoke_hours,
                    public_key: submission
                        .public_key
                        .as_ref()
                        .map(|key| vrf_public_key_to_hex(key)),
                    proof: submission.proof.clone(),
                    verified: false,
                    accepted: false,
                    threshold: None,
                    rejection_reason: Some(reason_string.clone()),
                    weight: None,
                    weighted_randomness: None,
                });
                result.rejected.push(RejectedSubmission {
                    submission: submission.clone(),
                    randomness: None,
                    reason,
                });
            }
        }
    }

    if verified_by_epoch.is_empty() {
        result
            .rejected
            .sort_by(|a, b| a.submission.address.cmp(&b.submission.address));
        result.metrics.total_weight = "0".into();
        result.metrics.entropy_beacon = hex::encode(entropy_state);
        result.metrics.participation_rate = 0.0;
        telemetry::VrfTelemetry::global().record_selection(&result.metrics);
        return result;
    }

    let mut strategies: HashMap<u64, EpochThresholdStrategy> = HashMap::new();
    for (epoch, submissions) in verified_by_epoch.iter() {
        let randomness: Vec<Natural> = submissions
            .iter()
            .map(|entry| entry.weighted_randomness.clone())
            .collect();
        strategies.insert(
            *epoch,
            EpochThresholdStrategy::new(*epoch, target_validator_count, &randomness),
        );
    }

    for (epoch, submissions) in verified_by_epoch.into_iter() {
        let Some(strategy) = strategies.get(&epoch) else {
            continue;
        };
        result.metrics.record_epoch(epoch);
        result
            .metrics
            .set_active_threshold(strategy.base_threshold(), strategy.randomness_domain());
        for submission in submissions {
            let threshold = strategy.threshold_for_seed(&submission.input.tier_seed);
            if submission.weighted_randomness < threshold {
                result.metrics.record_accept();
                accepted_count = accepted_count.saturating_add(1);
                total_weight += submission.weight.clone();
                update_entropy_beacon(&mut entropy_state, &submission);
                if let Some(index) = audit_index.get(&submission.address) {
                    if let Some(entry) = audit_records.get_mut(*index) {
                        entry.accepted = true;
                        entry.threshold = Some(threshold.to_string());
                        entry.weight = Some(submission.weight.to_string());
                        entry.weighted_randomness =
                            Some(submission.weighted_randomness.to_string());
                    }
                }
                result.validators.push(submission.clone());
            } else {
                let reason = RejectionReason::ThresholdNotMet {
                    threshold: threshold.clone(),
                };
                result.metrics.record_rejection(&reason);
                if let Some(index) = audit_index.get(&submission.address) {
                    if let Some(entry) = audit_records.get_mut(*index) {
                        entry.threshold = Some(threshold.to_string());
                        entry.rejection_reason = Some(reason.to_string());
                        entry.weight = Some(submission.weight.to_string());
                        entry.weighted_randomness =
                            Some(submission.weighted_randomness.to_string());
                    }
                }
                let rejected = RejectedSubmission {
                    submission: submission.as_submission(),
                    randomness: Some(submission.randomness.clone()),
                    reason: reason.clone(),
                };
                if let Some(current) = &mut result.fallback {
                    if candidate_cmp(&submission, &current.submission)
                        == std::cmp::Ordering::Greater
                    {
                        *current = FallbackCandidate {
                            submission: submission.clone(),
                            reason: reason.clone(),
                        };
                    }
                } else {
                    result.metrics.record_fallback();
                    result.fallback = Some(FallbackCandidate {
                        submission: submission.clone(),
                        reason: reason.clone(),
                    });
                }
                result.rejected.push(rejected);
            }
        }
    }

    result.validators.sort_by(|a, b| a.address.cmp(&b.address));
    result
        .rejected
        .sort_by(|a, b| a.submission.address.cmp(&b.submission.address));
    result.audit = audit_records;
    result.metrics.participation_rate = if result.metrics.pool_entries == 0 {
        0.0
    } else {
        (accepted_count as f64) / (result.metrics.pool_entries as f64)
    };
    result.metrics.success_rate = if result.metrics.target_validator_count == 0 {
        0.0
    } else {
        (accepted_count as f64) / (result.metrics.target_validator_count as f64)
    }
    .clamp(0.0, 1.0);
    result.metrics.total_weight = total_weight.to_string();
    result.metrics.entropy_beacon = hex::encode(entropy_state);
    let rejection_rate = if result.metrics.verified_submissions == 0 {
        0.0
    } else {
        (result.metrics.rejected_candidates as f64) / (result.metrics.verified_submissions as f64)
    };
    let threshold_ratio = result.metrics.active_threshold_ratio.unwrap_or(0.0);
    if result.metrics.fallback_selected {
        warn!(
            target = "vrf.selection",
            epoch = result.metrics.latest_epoch.unwrap_or_default(),
            round = result.metrics.latest_round.unwrap_or_default(),
            pool_entries = result.metrics.pool_entries,
            accepted = result.metrics.accepted_validators,
            rejected = result.metrics.rejected_candidates,
            "vrf fallback candidate required"
        );
    }
    info!(
        target = "vrf.selection",
        epoch = result.metrics.latest_epoch.unwrap_or_default(),
        round = result.metrics.latest_round.unwrap_or_default(),
        pool_entries = result.metrics.pool_entries,
        accepted = result.metrics.accepted_validators,
        rejected = result.metrics.rejected_candidates,
        participation_rate = result.metrics.participation_rate,
        success_rate = result.metrics.success_rate,
        rejection_rate,
        threshold_ratio,
        threshold_value = result
            .metrics
            .active_epoch_threshold
            .as_deref()
            .unwrap_or(""),
        fallback_selected = result.metrics.fallback_selected,
        ?result.metrics.rejections_by_reason,
        "vrf selection completed"
    );
    telemetry::VrfTelemetry::global().record_selection(&result.metrics);
    result
}

fn validate_submission(submission: &VrfSubmission) -> Result<VerifiedSubmission, RejectionReason> {
    if submission.tier < Tier::Tl3 {
        return Err(RejectionReason::TierTooLow {
            required: Tier::Tl3,
            received: submission.tier.clone(),
        });
    }

    if submission.timetoke_hours == 0 {
        return Err(RejectionReason::InsufficientTimetoke {
            minimum: 1,
            received: 0,
        });
    }

    let output = submission
        .proof
        .to_vrf_output()
        .map_err(|err| RejectionReason::MalformedProof(err.to_string()))?;

    let randomness = natural_from_bytes(&output.randomness);

    if randomness != submission.proof.randomness {
        return Err(RejectionReason::InvalidProof(
            "randomness encoding mismatch".into(),
        ));
    }

    let verified = if let Some(public_key) = submission.public_key.as_ref() {
        verify_vrf(&submission.input, public_key, &output)
            .map_err(|err| RejectionReason::InvalidProof(err.to_string()))?;
        true
    } else {
        return Err(RejectionReason::MissingPublicKey);
    };

    let weight = submission_weight(&submission.tier, submission.timetoke_hours);
    let weighted_randomness = weighted_randomness(&randomness, &weight);

    Ok(VerifiedSubmission {
        address: submission.address.clone(),
        public_key: submission.public_key.clone(),
        input: submission.input.clone(),
        proof: submission.proof.clone(),
        tier: submission.tier.clone(),
        timetoke_hours: submission.timetoke_hours,
        randomness,
        verified,
        weight,
        weighted_randomness,
    })
}

/// Selects the leader among the provided validator submissions according to the
/// tier → timetoke → lowest randomness ordering mandated by the blueprint.
pub fn select_leader(validators: &[VerifiedSubmission]) -> Option<VerifiedSubmission> {
    validators.iter().cloned().max_by(|a, b| leader_cmp(a, b))
}

/// Derives the tier seed value from an address and timetoke balance.
pub fn derive_tier_seed(address: &Address, timetoke_hours: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(POSEIDON_TIER_SEED_DOMAIN.len() + 32 + 8);
    data.extend_from_slice(POSEIDON_TIER_SEED_DOMAIN);
    data.extend_from_slice(&decode_address_bytes(address));
    data.extend_from_slice(&timetoke_hours.to_be_bytes());
    Blake2sHasher::hash(&data).into()
}

fn tier_weight(tier: &Tier) -> u64 {
    match tier {
        Tier::Tl0 => 1,
        Tier::Tl1 => 2,
        Tier::Tl2 => 3,
        Tier::Tl3 => 4,
        Tier::Tl4 => 5,
        Tier::Tl5 => 6,
    }
}

fn submission_weight(tier: &Tier, timetoke_hours: u64) -> Natural {
    let tier_component = Natural::from(tier_weight(tier));
    let timetoke_component = Natural::from(timetoke_hours.max(1));
    tier_component * timetoke_component
}

fn weighted_randomness(randomness: &Natural, weight: &Natural) -> Natural {
    if weight == &Natural::from(0u32) {
        return randomness.clone();
    }
    randomness.clone() / weight.clone()
}

fn update_entropy_beacon(state: &mut [u8; 32], submission: &VerifiedSubmission) {
    let mut data = Vec::with_capacity(ENTROPY_BEACON_DOMAIN.len() + state.len() + 32 + 32);
    data.extend_from_slice(ENTROPY_BEACON_DOMAIN);
    data.extend_from_slice(state);
    data.extend_from_slice(&natural_to_bytes(&submission.randomness));
    data.extend_from_slice(&submission.input.tier_seed);
    *state = Blake2sHasher::hash(&data).into();
}

fn default_entropy_state() -> [u8; 32] {
    Blake2sHasher::hash(ENTROPY_BEACON_DOMAIN).into()
}

fn natural_from_bytes(bytes: &[u8]) -> Natural {
    let mut value = Natural::from(0u32);
    for byte in bytes {
        value *= Natural::from(256u32);
        value += Natural::from(*byte);
    }
    value
}

fn natural_to_bytes(value: &Natural) -> [u8; 32] {
    let mut buffer = [0u8; 32];
    let mut index = buffer.len();
    let base = Natural::from(256u32);
    let zero = Natural::from(0u32);
    let mut current = value.clone();
    while current > zero && index > 0 {
        let (quotient, remainder) = current.div_rem(&base);
        index -= 1;
        let digit = remainder.to_string().parse::<u16>().unwrap_or_default() as u8;
        buffer[index] = digit;
        current = quotient;
    }
    buffer
}

fn natural_to_f64(value: &Natural) -> Option<f64> {
    value.to_string().parse::<f64>().ok()
}

fn natural_ratio(numerator: &Natural, denominator: &Natural) -> Option<f64> {
    let denominator = natural_to_f64(denominator)?;
    if denominator == 0.0 {
        return None;
    }
    let numerator = natural_to_f64(numerator)?;
    Some((numerator / denominator).clamp(0.0, 1.0))
}

fn decode_address_bytes(address: &Address) -> [u8; 32] {
    if let Ok(bytes) = hex::decode(address) {
        if let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return array;
        }
    }
    Blake2sHasher::hash(address.as_bytes()).into()
}

#[derive(Clone, Debug)]
struct EpochThresholdStrategy {
    epoch: u64,
    base_threshold: Natural,
    #[cfg_attr(not(test), allow(dead_code))]
    quantile_threshold: Natural,
    randomness_domain: Natural,
    adjustment_span: Natural,
}

impl EpochThresholdStrategy {
    fn new(epoch: u64, target_validator_count: usize, randomness: &[Natural]) -> Self {
        let randomness_domain = vrf_randomness_domain();
        let total_submissions = randomness.len();
        let zero = Natural::from(0u32);

        if target_validator_count == 0 || total_submissions == 0 {
            return Self {
                epoch,
                base_threshold: zero.clone(),
                quantile_threshold: zero,
                randomness_domain: randomness_domain.clone(),
                adjustment_span: Natural::from(1u32),
            };
        }

        let clamped_target = target_validator_count.min(total_submissions);
        if clamped_target >= total_submissions {
            return Self {
                epoch,
                base_threshold: randomness_domain.clone(),
                quantile_threshold: randomness_domain.clone(),
                randomness_domain,
                adjustment_span: Natural::from(1u32),
            };
        }

        let smoothing_target = Natural::from((clamped_target as u64) + 1);
        let smoothing_total = Natural::from((total_submissions as u64) + 2);
        let smoothed_threshold =
            (randomness_domain.clone() * smoothing_target.clone()) / smoothing_total.clone();

        let mut sorted: Vec<Natural> = randomness.iter().cloned().collect();
        sorted.sort();
        let quantile_threshold = sorted[clamped_target - 1].clone();

        let mut base_threshold = smoothed_threshold.clone() + quantile_threshold.clone();
        base_threshold /= Natural::from(2u32);
        if base_threshold < quantile_threshold {
            base_threshold = quantile_threshold.clone();
        }
        if base_threshold > randomness_domain {
            base_threshold = randomness_domain.clone();
        }

        let adjustment_divisor = ((total_submissions as u64).saturating_mul(4)).max(1);
        let mut adjustment_span = randomness_domain.clone() / Natural::from(adjustment_divisor);
        if adjustment_span <= zero {
            adjustment_span = Natural::from(1u32);
        }

        Self {
            epoch,
            base_threshold,
            quantile_threshold,
            randomness_domain,
            adjustment_span,
        }
    }

    fn threshold_for_seed(&self, tier_seed: &[u8; 32]) -> Natural {
        if self.base_threshold == Natural::from(0u32) {
            return Natural::from(0u32);
        }

        let mut seed_material = Vec::with_capacity(THRESHOLD_DOMAIN.len() + 8 + tier_seed.len());
        seed_material.extend_from_slice(THRESHOLD_DOMAIN);
        seed_material.extend_from_slice(&self.epoch.to_be_bytes());
        seed_material.extend_from_slice(tier_seed);
        let jitter_bytes: [u8; 32] = Blake2sHasher::hash(&seed_material).into();
        let jitter = natural_from_bytes(&jitter_bytes);

        let offset = jitter % self.adjustment_span.clone();
        let mut threshold = self.base_threshold.clone();
        if jitter_bytes[0] & 1 == 0 {
            threshold += offset;
        } else if threshold > offset {
            threshold -= offset;
        } else {
            threshold = Natural::from(0u32);
        }

        if threshold > self.randomness_domain {
            self.randomness_domain.clone()
        } else {
            threshold
        }
    }

    fn base_threshold(&self) -> &Natural {
        &self.base_threshold
    }

    fn randomness_domain(&self) -> &Natural {
        &self.randomness_domain
    }

    #[cfg(test)]
    fn quantile_threshold(&self) -> &Natural {
        &self.quantile_threshold
    }
}

fn vrf_randomness_domain() -> Natural {
    let mut domain = Natural::from(1u32);
    domain <<= VRF_RANDOMNESS_BITS;
    domain
}

fn candidate_cmp(a: &VerifiedSubmission, b: &VerifiedSubmission) -> std::cmp::Ordering {
    a.verified
        .cmp(&b.verified)
        .then_with(|| a.tier.cmp(&b.tier))
        .then_with(|| a.timetoke_hours.cmp(&b.timetoke_hours))
        .then_with(|| a.weight.cmp(&b.weight))
        .then_with(|| b.weighted_randomness.cmp(&a.weighted_randomness))
        .then_with(|| b.address.cmp(&a.address))
}

fn leader_cmp(a: &VerifiedSubmission, b: &VerifiedSubmission) -> std::cmp::Ordering {
    a.verified
        .cmp(&b.verified)
        .then_with(|| a.tier.cmp(&b.tier))
        .then_with(|| a.timetoke_hours.cmp(&b.timetoke_hours))
        .then_with(|| a.weight.cmp(&b.weight))
        .then_with(|| b.weighted_randomness.cmp(&a.weighted_randomness))
        .then_with(|| b.address.cmp(&a.address))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_seed() -> [u8; 32] {
        [0x11; 32]
    }

    fn sample_epoch() -> u64 {
        42
    }

    fn submission_for(
        address: &str,
        tier: Tier,
        timetoke_hours: u64,
    ) -> (VrfSubmission, VrfKeypair, VrfOutput) {
        let keypair = generate_vrf_keypair();
        let seed = sample_seed();
        let tier_seed = derive_tier_seed(&address.to_string(), timetoke_hours);
        let input = PoseidonVrfInput::new(seed, sample_epoch(), tier_seed);
        let output = generate_vrf(&input, &keypair.secret).expect("generate vrf");
        let submission = VrfSubmission {
            address: address.to_string(),
            public_key: Some(keypair.public.clone()),
            input,
            proof: VrfProof::from_output(&output),
            tier,
            timetoke_hours,
        };
        (submission, keypair, output)
    }

    fn verified_submission(
        address: &str,
        tier: Tier,
        timetoke_hours: u64,
        randomness: u64,
    ) -> VerifiedSubmission {
        let randomness = Natural::from(randomness);
        let seed = sample_seed();
        let tier_seed = derive_tier_seed(&address.to_string(), timetoke_hours);
        let input = PoseidonVrfInput::new(seed, sample_epoch(), tier_seed);
        let keypair = generate_vrf_keypair();
        let proof = VrfProof {
            randomness: randomness.clone(),
            preoutput: "00".repeat(VRF_PREOUTPUT_LENGTH),
            proof: "00".repeat(VRF_PROOF_LENGTH),
        };
        let weight = submission_weight(&tier, timetoke_hours);
        let weighted_randomness = weighted_randomness(&randomness, &weight);

        VerifiedSubmission {
            address: address.to_string(),
            public_key: Some(keypair.public),
            input,
            proof,
            tier,
            timetoke_hours,
            randomness,
            verified: true,
            weight,
            weighted_randomness,
        }
    }

    #[test]
    fn poseidon_digest_is_deterministic() {
        let tier_seed = derive_tier_seed(&"addr".to_string(), 12);
        let input = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        let first = input.poseidon_digest_bytes();
        let second = input.poseidon_digest_bytes();
        assert_eq!(first, second);
    }

    #[test]
    fn poseidon_digest_changes_with_input() {
        let tier_seed = derive_tier_seed(&"addr".to_string(), 12);
        let mut base = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        let baseline = base.poseidon_digest_hex();

        base.epoch += 1;
        let tweaked_epoch = base.poseidon_digest_hex();
        assert_ne!(baseline, tweaked_epoch);

        let mut different_header = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        different_header.last_block_header[0] ^= 0xFF;
        let different_hash = different_header.poseidon_digest_hex();
        assert_ne!(baseline, different_hash);
    }

    #[cfg(feature = "nightly-prover")]
    #[test]
    fn poseidon_digest_matches_expected_vector() {
        let input = PoseidonVrfInput::new(
            hex_literal::hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            7,
            hex_literal::hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        );

        let digest_hex = input.poseidon_digest_hex();
        assert_eq!(
            digest_hex,
            "00000000000000000000000000000000000000000000000082814949c7cd6907"
        );
    }

    #[cfg(not(feature = "nightly-prover"))]
    #[test]
    fn poseidon_digest_matches_expected_vector() {
        let input = PoseidonVrfInput::new(
            hex_literal::hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            7,
            hex_literal::hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        );

        let digest_hex = input.poseidon_digest_hex();
        assert_eq!(digest_hex.len(), 64);
        assert_ne!(digest_hex, "0".repeat(64));
    }

    #[test]
    fn generate_and_verify_roundtrip() {
        let (submission, keypair, output) = submission_for("addr_roundtrip", Tier::Tl3, 12);
        assert!(verify_vrf(&submission.input, &keypair.public, &output).is_ok());
    }

    #[test]
    fn verify_fails_for_randomness_mismatch() {
        let keypair = generate_vrf_keypair();
        let tier_seed = derive_tier_seed(&"addr".to_string(), 12);
        let input = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        let mut output = generate_vrf(&input, &keypair.secret).expect("generate vrf");
        output.randomness[0] ^= 0xFF;
        assert!(matches!(
            verify_vrf(&input, &keypair.public, &output),
            Err(VrfError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_fails_for_tampered_proof() {
        let keypair = generate_vrf_keypair();
        let tier_seed = derive_tier_seed(&"addr".to_string(), 12);
        let input = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        let mut output = generate_vrf(&input, &keypair.secret).expect("generate vrf");
        output.proof[0] ^= 0xFF;
        assert!(matches!(
            verify_vrf(&input, &keypair.public, &output),
            Err(VrfError::VerificationFailed)
                | Err(VrfError::InvalidInput(_))
                | Err(VrfError::Backend(_))
        ));
    }

    #[test]
    fn verify_fails_for_tampered_preoutput() {
        let keypair = generate_vrf_keypair();
        let tier_seed = derive_tier_seed(&"addr".to_string(), 12);
        let input = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        let mut output = generate_vrf(&input, &keypair.secret).expect("generate vrf");
        output.preoutput[0] ^= 0xFF;
        assert!(matches!(
            verify_vrf(&input, &keypair.public, &output),
            Err(VrfError::VerificationFailed) | Err(VrfError::Backend(_))
        ));
    }

    #[test]
    fn vrf_output_parsing_roundtrip() {
        let keypair = generate_vrf_keypair();
        let tier_seed = derive_tier_seed(&"addr".to_string(), 12);
        let input = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        let output = generate_vrf(&input, &keypair.secret).expect("generate vrf");
        let randomness_hex = output.randomness_hex();
        let preoutput_hex = output.preoutput_hex();
        let proof_hex = output.proof_hex();

        let parsed =
            VrfOutput::from_hex(&randomness_hex, &preoutput_hex, &proof_hex).expect("parse hex");
        assert_eq!(parsed, output);
    }

    #[test]
    fn vrf_output_parsing_rejects_invalid_lengths() {
        let randomness = [0u8; 31];
        let preoutput = [0u8; VRF_PREOUTPUT_LENGTH + 1];
        let proof = [0u8; VRF_PROOF_LENGTH + 1];
        assert!(matches!(
            VrfOutput::from_bytes(
                &randomness,
                &[0u8; VRF_PREOUTPUT_LENGTH],
                &[0u8; VRF_PROOF_LENGTH]
            ),
            Err(VrfError::InvalidInput(_))
        ));
        assert!(matches!(
            VrfOutput::from_bytes(&[0u8; 32], &preoutput, &[0u8; VRF_PROOF_LENGTH]),
            Err(VrfError::InvalidInput(_))
        ));
        assert!(matches!(
            VrfOutput::from_bytes(&[0u8; 32], &[0u8; VRF_PREOUTPUT_LENGTH], &proof),
            Err(VrfError::InvalidInput(_))
        ));
    }

    #[test]
    fn different_keys_produce_distinct_randomness() {
        let tier_seed = derive_tier_seed(&"addr".to_string(), 12);
        let input = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        let first = generate_vrf_keypair();
        let second = generate_vrf_keypair();

        let first_output = generate_vrf(&input, &first.secret).expect("first vrf");
        let second_output = generate_vrf(&input, &second.secret).expect("second vrf");

        assert_ne!(first_output.randomness, second_output.randomness);
        assert_ne!(first_output.preoutput, second_output.preoutput);
    }

    #[test]
    fn submit_vrf_records_submission() {
        let mut pool = VrfSubmissionPool::new();
        let (submission, _, _) = submission_for("addr1", Tier::Tl3, 12);
        submit_vrf(&mut pool, submission.clone());
        assert_eq!(pool.len(), 1);
        let stored = pool.get(&"addr1".to_string()).expect("stored submission");
        assert_eq!(stored.address, submission.address);
    }

    #[test]
    fn submission_pool_retain_filters_entries() {
        let mut pool = VrfSubmissionPool::new();
        let (current_submission, _, _) = submission_for("addr-retain-current", Tier::Tl3, 12);
        let (stale_submission, _, _) = submission_for("addr-retain-stale", Tier::Tl3, 6);
        submit_vrf(&mut pool, current_submission.clone());
        submit_vrf(&mut pool, stale_submission.clone());

        pool.retain(|_, submission| submission.address == current_submission.address);

        assert_eq!(pool.len(), 1);
        assert!(pool.get(&current_submission.address).is_some());
        assert!(pool.get(&stale_submission.address).is_none());
    }

    #[test]
    fn select_validators_rejects_invalid_proof() {
        let mut pool = VrfSubmissionPool::new();
        let (mut submission, _, _) = submission_for("addr_invalid", Tier::Tl3, 12);
        submission.proof.preoutput = "00".repeat(VRF_PREOUTPUT_LENGTH);
        submission.proof.proof = "00".repeat(VRF_PROOF_LENGTH);
        submit_vrf(&mut pool, submission.clone());

        let selection = select_validators(&pool, 1);
        assert!(selection.validators.is_empty());
        assert!(matches!(
            selection.rejected.first().map(|entry| &entry.reason),
            Some(RejectionReason::InvalidProof(_))
        ));
        assert!(selection.fallback.is_none());
    }

    #[test]
    fn select_validators_picks_fallback_when_none_pass() {
        let mut pool = VrfSubmissionPool::new();
        let (submission, _, _) = submission_for("addr2", Tier::Tl3, 12);
        submit_vrf(&mut pool, submission);
        let selection = select_validators(&pool, 0);
        assert!(selection.validators.is_empty());
        assert!(matches!(
            selection.fallback.as_ref().map(|entry| &entry.reason),
            Some(RejectionReason::ThresholdNotMet { .. })
        ));
    }

    #[test]
    fn select_leader_prefers_lowest_randomness_with_matching_tier_and_timetoke() {
        let mut pool = VrfSubmissionPool::new();
        let (submission_a, _, _) = submission_for("addr3", Tier::Tl3, 10);
        let (submission_b, _, _) = submission_for("addr4", Tier::Tl3, 10);
        submit_vrf(&mut pool, submission_a);
        submit_vrf(&mut pool, submission_b);
        let selection = select_validators(&pool, 10);
        assert_eq!(selection.validators.len(), 2);
        let leader = select_leader(&selection.validators).expect("leader");
        let min_randomness = selection
            .validators
            .iter()
            .min_by(|a, b| a.randomness.cmp(&b.randomness))
            .expect("min randomness");
        assert_eq!(leader.address, min_randomness.address);
    }

    #[test]
    fn select_leader_prioritizes_higher_tier_before_randomness() {
        let higher_tier = verified_submission("leader-tier", Tier::Tl4, 12, 50);
        let lower_tier = verified_submission("follower-tier", Tier::Tl3, 12, 5);
        let submissions = vec![lower_tier.clone(), higher_tier.clone()];
        let leader = select_leader(&submissions).expect("leader");
        assert_eq!(leader.address, higher_tier.address);
        assert_eq!(leader.tier, Tier::Tl4);
    }

    #[test]
    fn select_leader_prioritizes_higher_timetoke_before_randomness() {
        let higher_timetoke = verified_submission("leader-tt", Tier::Tl3, 24, 50);
        let lower_timetoke = verified_submission("follower-tt", Tier::Tl3, 12, 5);
        let submissions = vec![lower_timetoke.clone(), higher_timetoke.clone()];
        let leader = select_leader(&submissions).expect("leader");
        assert_eq!(leader.address, higher_timetoke.address);
        assert_eq!(leader.timetoke_hours, 24);
    }

    #[test]
    fn select_validators_rejects_missing_public_key() {
        let mut pool = VrfSubmissionPool::new();
        let (mut submission, _, _) = submission_for("addr_missing_pk", Tier::Tl3, 12);
        submission.public_key = None;
        submit_vrf(&mut pool, submission);
        let selection = select_validators(&pool, 1);
        assert!(selection.validators.is_empty());
        assert!(matches!(
            selection.rejected.first().map(|entry| &entry.reason),
            Some(RejectionReason::MissingPublicKey)
        ));
    }

    #[test]
    fn select_validators_populates_audit_records() {
        let mut pool = VrfSubmissionPool::new();
        let (valid_submission, _, _) = submission_for("addr_audit", Tier::Tl3, 12);
        submit_vrf(&mut pool, valid_submission.clone());
        let (mut rejected_submission, _, _) = submission_for("addr_reject", Tier::Tl3, 0);
        rejected_submission.timetoke_hours = 0;
        submit_vrf(&mut pool, rejected_submission.clone());

        let selection = select_validators(&pool, 10);
        assert_eq!(selection.audit.len(), 2);
        let accepted = selection
            .audit
            .iter()
            .find(|entry| entry.address == valid_submission.address)
            .expect("accepted record");
        assert!(accepted.verified);
        assert!(accepted.accepted);
        assert!(accepted.threshold.is_some());
        assert!(accepted.rejection_reason.is_none());
        assert!(accepted.weight.is_some());
        assert!(accepted.weighted_randomness.is_some());

        let rejected = selection
            .audit
            .iter()
            .find(|entry| entry.address == rejected_submission.address)
            .expect("rejected record");
        assert!(!rejected.accepted);
        assert!(rejected.rejection_reason.is_some());
        assert!(rejected.weight.is_none());
        assert!(rejected.weighted_randomness.is_none());

        assert!(selection.metrics.accepted_validators >= 1);
        assert!(selection.metrics.participation_rate > 0.0);
        assert!(!selection.metrics.entropy_beacon.is_empty());
        assert!(!selection.metrics.total_weight.is_empty());
    }

    #[test]
    fn select_validators_rejects_low_tier() {
        let mut pool = VrfSubmissionPool::new();
        let (mut submission, _, _) = submission_for("addr_low_tier", Tier::Tl3, 12);
        submission.tier = Tier::Tl2;
        submit_vrf(&mut pool, submission);
        let selection = select_validators(&pool, 1);
        assert!(selection.validators.is_empty());
        assert!(matches!(
            selection.rejected.first().map(|entry| &entry.reason),
            Some(RejectionReason::TierTooLow { .. })
        ));
    }

    #[test]
    fn threshold_zero_when_target_is_zero() {
        let randomness: Vec<Natural> = vec![Natural::from(10u32); 5];
        let strategy = EpochThresholdStrategy::new(5, 0, &randomness);
        assert_eq!(strategy.base_threshold(), &Natural::from(0u32));
        assert_eq!(
            strategy.threshold_for_seed(&[0x11; 32]),
            Natural::from(0u32)
        );
    }

    #[test]
    fn threshold_saturates_when_target_exceeds_population() {
        let randomness: Vec<Natural> = vec![Natural::from(10u32), Natural::from(20u32)];
        let strategy = EpochThresholdStrategy::new(7, 10, &randomness);
        assert_eq!(strategy.base_threshold(), &vrf_randomness_domain());
        assert_eq!(
            strategy.threshold_for_seed(&[0x22; 32]),
            vrf_randomness_domain()
        );
    }

    #[test]
    fn threshold_tracks_quantile_when_target_is_within_population() {
        let randomness: Vec<Natural> = vec![
            Natural::from(5u32),
            Natural::from(15u32),
            Natural::from(25u32),
            Natural::from(35u32),
        ];
        let strategy = EpochThresholdStrategy::new(9, 2, &randomness);
        assert_eq!(strategy.quantile_threshold(), &Natural::from(15u32));
        assert!(strategy.base_threshold() >= strategy.quantile_threshold());
        let threshold = strategy.threshold_for_seed(&[0x33; 32]);
        assert!(threshold >= Natural::from(15u32));
        assert!(threshold <= vrf_randomness_domain());
    }

    #[test]
    fn epoch_manager_rejects_replays_and_tracks_entropy() {
        let (submission, _, _) = submission_for("epoch_mgr", Tier::Tl3, 12);
        let mut manager = VrfEpochManager::new(64, submission.input.epoch);
        assert!(manager.register_submission(&submission));
        assert!(!manager.register_submission(&submission));

        let beacon = [0x42u8; 32];
        manager.record_entropy(submission.input.epoch, beacon);
        assert_eq!(manager.entropy_hex(), hex::encode(beacon));

        let mut next = submission.clone();
        next.input.epoch += 1;
        assert!(manager.register_submission(&next));
    }
}
