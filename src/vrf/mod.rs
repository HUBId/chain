//! VRF engine scaffolding built around a Poseidon hash domain.
//!
//! This module will eventually host the full VRF implementation defined in the
//! blueprint. For now it establishes the public API, shared data structures and
//! error types so that subsequent work can focus on integrating the actual
//! cryptography and consensus wiring without reshaping interfaces again.

use std::collections::HashMap;
use std::fmt;

use crate::crypto::{VrfPublicKey, VrfSecretKey, vrf_public_key_to_hex};
use crate::errors::ChainError;
use crate::reputation::Tier;
use crate::stwo::params::{FieldElement, StarkParameters};
use crate::types::Address;
use ed25519_dalek::{
    ExpandedSecretKey, PublicKey, SIGNATURE_LENGTH, SecretKey, Signature, Verifier,
};
use malachite::Natural;
use malachite::base::num::arithmetic::traits::DivRem;
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;
use thiserror::Error;

/// Poseidon domain separator used for deriving VRF inputs.
pub const POSEIDON_VRF_DOMAIN: &[u8] = b"chain.vrf.poseidon";
/// Domain separator for deriving tier-specific seeds.
pub const POSEIDON_TIER_SEED_DOMAIN: &[u8] = b"chain.vrf.tier_seed";
/// Bit width of the VRF randomness output domain.
pub const VRF_RANDOMNESS_BITS: usize = 256;
/// Domain separator used when deriving per-epoch validator thresholds.
const THRESHOLD_DOMAIN: &[u8] = b"chain.vrf.threshold";

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
    pub proof: [u8; SIGNATURE_LENGTH],
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

    /// Returns a reference to the raw signature bytes backing the proof.
    pub fn proof_bytes(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.proof
    }

    /// Reconstructs a VRF output from raw randomness and proof byte slices.
    pub fn from_bytes(randomness: &[u8], proof: &[u8]) -> VrfResult<Self> {
        if randomness.len() != 32 {
            return Err(VrfError::InvalidInput(
                "VRF randomness must be exactly 32 bytes".to_string(),
            ));
        }
        if proof.len() != SIGNATURE_LENGTH {
            return Err(VrfError::InvalidInput(format!(
                "VRF proof must be exactly {SIGNATURE_LENGTH} bytes"
            )));
        }

        let mut randomness_bytes = [0u8; 32];
        randomness_bytes.copy_from_slice(randomness);
        let mut proof_bytes = [0u8; SIGNATURE_LENGTH];
        proof_bytes.copy_from_slice(proof);

        Ok(Self {
            randomness: randomness_bytes,
            proof: proof_bytes,
        })
    }

    /// Parses a VRF output from hexadecimal encodings of randomness and proof.
    pub fn from_hex(randomness_hex: &str, proof_hex: &str) -> VrfResult<Self> {
        let randomness = hex::decode(randomness_hex)
            .map_err(|err| VrfError::InvalidInput(format!("invalid randomness encoding: {err}")))?;
        let proof = hex::decode(proof_hex)
            .map_err(|err| VrfError::InvalidInput(format!("invalid proof encoding: {err}")))?;
        Self::from_bytes(&randomness, &proof)
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

impl From<VrfError> for ChainError {
    fn from(err: VrfError) -> Self {
        ChainError::Crypto(err.to_string())
    }
}

/// Serializable VRF proof transported between consensus participants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VrfProof {
    pub randomness: Natural,
    pub proof: String,
}

impl VrfProof {
    pub fn from_output(output: &VrfOutput) -> Self {
        Self {
            randomness: natural_from_bytes(&output.randomness),
            proof: output.proof_hex(),
        }
    }

    pub fn randomness_bytes(&self) -> [u8; 32] {
        natural_to_bytes(&self.randomness)
    }

    pub fn to_vrf_output(&self) -> VrfResult<VrfOutput> {
        let randomness = self.randomness_bytes();
        let proof_bytes = hex::decode(&self.proof).map_err(|err| {
            VrfError::InvalidInput(format!("failed to decode VRF proof hex: {err}"))
        })?;
        VrfOutput::from_bytes(&randomness, &proof_bytes)
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
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VrfSelectionMetrics {
    pub pool_entries: usize,
    pub target_validator_count: usize,
    pub verified_submissions: usize,
    pub accepted_validators: usize,
    pub rejected_candidates: usize,
    pub fallback_selected: bool,
}

impl VrfSelectionMetrics {
    fn record_verification(&mut self) {
        self.verified_submissions = self.verified_submissions.saturating_add(1);
    }

    fn record_accept(&mut self) {
        self.accepted_validators = self.accepted_validators.saturating_add(1);
    }

    fn record_rejection(&mut self) {
        self.rejected_candidates = self.rejected_candidates.saturating_add(1);
    }

    fn record_fallback(&mut self) {
        self.fallback_selected = true;
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
    let secret = SecretKey::from_bytes(&secret.to_bytes())
        .map_err(|err| VrfError::InvalidInput(format!("invalid VRF secret key: {err}")))?;
    let expanded = ExpandedSecretKey::from(&secret);
    let public: PublicKey = (&secret).into();
    let signature = expanded.sign(&digest, &public);
    let proof_bytes = signature.to_bytes();
    let randomness: [u8; 32] = Blake2sHasher::hash(&proof_bytes).into();

    Ok(VrfOutput {
        randomness,
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
    let public = PublicKey::from_bytes(&public.to_bytes())
        .map_err(|err| VrfError::InvalidInput(format!("invalid VRF public key: {err}")))?;
    let signature = Signature::from_bytes(&output.proof)
        .map_err(|err| VrfError::InvalidInput(format!("invalid VRF proof bytes: {err}")))?;

    public
        .verify(&digest, &signature)
        .map_err(|_| VrfError::VerificationFailed)?;

    let expected_randomness: [u8; 32] = Blake2sHasher::hash(&output.proof).into();
    if expected_randomness != output.randomness {
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

    if pool.is_empty() {
        return result;
    }

    let mut audit_records: Vec<VrfSelectionRecord> = Vec::new();
    let mut audit_index: HashMap<Address, usize> = HashMap::new();
    let mut verified_by_epoch: HashMap<u64, Vec<VerifiedSubmission>> = HashMap::new();

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
                });
                verified_by_epoch
                    .entry(verified.input.epoch)
                    .or_default()
                    .push(verified);
            }
            Err(reason) => {
                result.metrics.record_rejection();
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
        return result;
    }

    let mut strategies: HashMap<u64, EpochThresholdStrategy> = HashMap::new();
    for (epoch, submissions) in verified_by_epoch.iter() {
        let randomness: Vec<Natural> = submissions
            .iter()
            .map(|entry| entry.randomness.clone())
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
        for submission in submissions {
            let threshold = strategy.threshold_for_seed(&submission.input.tier_seed);
            if submission.randomness < threshold {
                result.metrics.record_accept();
                if let Some(index) = audit_index.get(&submission.address) {
                    if let Some(entry) = audit_records.get_mut(*index) {
                        entry.accepted = true;
                        entry.threshold = Some(threshold.to_string());
                    }
                }
                result.validators.push(submission.clone());
            } else {
                let reason = RejectionReason::ThresholdNotMet {
                    threshold: threshold.clone(),
                };
                result.metrics.record_rejection();
                if let Some(index) = audit_index.get(&submission.address) {
                    if let Some(entry) = audit_records.get_mut(*index) {
                        entry.threshold = Some(threshold.to_string());
                        entry.rejection_reason = Some(reason.to_string());
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

    Ok(VerifiedSubmission {
        address: submission.address.clone(),
        public_key: submission.public_key.clone(),
        input: submission.input.clone(),
        proof: submission.proof.clone(),
        tier: submission.tier.clone(),
        timetoke_hours: submission.timetoke_hours,
        randomness,
        verified,
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

    #[cfg(test)]
    fn base_threshold(&self) -> &Natural {
        &self.base_threshold
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
        .then_with(|| b.randomness.cmp(&a.randomness))
        .then_with(|| b.address.cmp(&a.address))
}

fn leader_cmp(a: &VerifiedSubmission, b: &VerifiedSubmission) -> std::cmp::Ordering {
    a.verified
        .cmp(&b.verified)
        .then_with(|| a.tier.cmp(&b.tier))
        .then_with(|| a.timetoke_hours.cmp(&b.timetoke_hours))
        .then_with(|| b.randomness.cmp(&a.randomness))
        .then_with(|| b.address.cmp(&a.address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{VrfKeypair, VrfPublicKey, generate_vrf_keypair};

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
        let keypair = generate_vrf_keypair().expect("vrf keypair");
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
        let proof = VrfProof {
            randomness: randomness.clone(),
            proof: "00".repeat(SIGNATURE_LENGTH),
        };

        VerifiedSubmission {
            address: address.to_string(),
            public_key: Some(VrfPublicKey::from([0u8; 32])),
            input,
            proof,
            tier,
            timetoke_hours,
            randomness,
            verified: true,
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

    #[test]
    fn generate_and_verify_roundtrip() {
        let (submission, keypair, output) = submission_for("addr_roundtrip", Tier::Tl3, 12);
        assert!(verify_vrf(&submission.input, &keypair.public, &output).is_ok());
    }

    #[test]
    fn verify_fails_for_randomness_mismatch() {
        let keypair = generate_vrf_keypair().expect("vrf keypair");
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
        let keypair = generate_vrf_keypair().expect("vrf keypair");
        let tier_seed = derive_tier_seed(&"addr".to_string(), 12);
        let input = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        let mut output = generate_vrf(&input, &keypair.secret).expect("generate vrf");
        output.proof[0] ^= 0xFF;
        assert!(matches!(
            verify_vrf(&input, &keypair.public, &output),
            Err(VrfError::VerificationFailed) | Err(VrfError::InvalidInput(_))
        ));
    }

    #[test]
    fn vrf_output_parsing_roundtrip() {
        let keypair = generate_vrf_keypair().expect("vrf keypair");
        let tier_seed = derive_tier_seed(&"addr".to_string(), 12);
        let input = PoseidonVrfInput::new(sample_seed(), sample_epoch(), tier_seed);
        let output = generate_vrf(&input, &keypair.secret).expect("generate vrf");
        let randomness_hex = output.randomness_hex();
        let proof_hex = output.proof_hex();

        let parsed = VrfOutput::from_hex(&randomness_hex, &proof_hex).expect("parse hex");
        assert_eq!(parsed, output);
    }

    #[test]
    fn vrf_output_parsing_rejects_invalid_lengths() {
        let randomness = [0u8; 31];
        let proof = [0u8; SIGNATURE_LENGTH + 1];
        assert!(matches!(
            VrfOutput::from_bytes(&randomness, &[0u8; SIGNATURE_LENGTH]),
            Err(VrfError::InvalidInput(_))
        ));
        assert!(matches!(
            VrfOutput::from_bytes(&[0u8; 32], &proof),
            Err(VrfError::InvalidInput(_))
        ));
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
        submission.proof.proof = "00".repeat(SIGNATURE_LENGTH);
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

        let rejected = selection
            .audit
            .iter()
            .find(|entry| entry.address == rejected_submission.address)
            .expect("rejected record");
        assert!(!rejected.accepted);
        assert!(rejected.rejection_reason.is_some());
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
}
