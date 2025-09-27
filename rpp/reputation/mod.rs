use std::cmp::Ordering;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::rpp::TimetokeRecord;
use crate::types::Address;

use hex;
use serde::de::Error as DeError;
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;
use thiserror::Error;

/// Configuration weights used to evaluate the reputation score. The values
/// mirror the blueprint defaults but can be tuned through governance.
#[derive(Clone, Debug, Serialize)]
pub struct ReputationWeights {
    w_v: f64,
    w_u: f64,
    w_c: f64,
    w_p: f64,
    w_d: f64,
}

/// Errors that can occur when validating [`ReputationWeights`].
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ReputationWeightsError {
    #[error("weight `{field}` must be within [0, 1], got {value}")]
    OutOfRange { field: &'static str, value: f64 },
    #[error("weights must sum to 1.0 within tolerance {tolerance}, got {sum}")]
    NotNormalized { sum: f64, tolerance: f64 },
}

impl ReputationWeights {
    pub const NORMALIZATION_TOLERANCE: f64 = 1e-6;

    pub fn new(
        w_v: f64,
        w_u: f64,
        w_c: f64,
        w_p: f64,
        w_d: f64,
    ) -> Result<Self, ReputationWeightsError> {
        let raw = Self {
            w_v,
            w_u,
            w_c,
            w_p,
            w_d,
        };
        raw.validate()?;
        Ok(raw)
    }

    pub fn validation(&self) -> f64 {
        self.w_v
    }

    pub fn uptime(&self) -> f64 {
        self.w_u
    }

    pub fn consensus(&self) -> f64 {
        self.w_c
    }

    pub fn peer_feedback(&self) -> f64 {
        self.w_p
    }

    pub fn decay(&self) -> f64 {
        self.w_d
    }

    pub fn validate(&self) -> Result<(), ReputationWeightsError> {
        for (field, value) in self.iter() {
            if !(0.0..=1.0).contains(&value) {
                return Err(ReputationWeightsError::OutOfRange { field, value });
            }
        }

        let sum: f64 = self.iter().map(|(_, value)| value).sum();
        if (sum - 1.0).abs() > Self::NORMALIZATION_TOLERANCE {
            return Err(ReputationWeightsError::NotNormalized {
                sum,
                tolerance: Self::NORMALIZATION_TOLERANCE,
            });
        }

        Ok(())
    }

    fn iter(&self) -> impl Iterator<Item = (&'static str, f64)> + '_ {
        [
            ("w_v", self.w_v),
            ("w_u", self.w_u),
            ("w_c", self.w_c),
            ("w_p", self.w_p),
            ("w_d", self.w_d),
        ]
        .into_iter()
    }
}

impl<'de> Deserialize<'de> for ReputationWeights {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawWeights {
            #[serde(alias = "validation")]
            w_v: f64,
            #[serde(alias = "uptime")]
            w_u: f64,
            #[serde(alias = "consensus")]
            w_c: f64,
            #[serde(alias = "peer_feedback")]
            w_p: f64,
            #[serde(alias = "decay")]
            w_d: f64,
        }

        let raw = RawWeights::deserialize(deserializer)?;
        ReputationWeights::new(raw.w_v, raw.w_u, raw.w_c, raw.w_p, raw.w_d).map_err(DeError::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TierThresholds {
    pub tier2_min_uptime_hours: u64,
    pub tier3_min_consensus_success: u64,
    pub tier4_min_consensus_success: u64,
    pub tier5_min_score: f64,
}

impl Default for TierThresholds {
    fn default() -> Self {
        Self {
            tier2_min_uptime_hours: 24,
            tier3_min_consensus_success: 10,
            tier4_min_consensus_success: 100,
            tier5_min_score: 0.75,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationParams {
    pub weights: ReputationWeights,
    pub tier_thresholds: TierThresholds,
    pub decay_interval_secs: u64,
    pub decay_factor: f64,
}

impl Default for ReputationParams {
    fn default() -> Self {
        Self {
            weights: ReputationWeights::default(),
            tier_thresholds: TierThresholds::default(),
            decay_interval_secs: 86_400,
            decay_factor: 0.05,
        }
    }
}

impl ReputationParams {
    pub fn with_weights(weights: ReputationWeights) -> Self {
        Self {
            weights,
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimetokeParams {
    pub minimum_window_secs: u64,
    pub accrual_cap_hours: u64,
    pub decay_interval_secs: u64,
    pub decay_step_hours: u64,
    pub sync_interval_secs: u64,
}

impl Default for TimetokeParams {
    fn default() -> Self {
        Self {
            minimum_window_secs: 3_600,
            accrual_cap_hours: 24 * 30,
            decay_interval_secs: 86_400,
            decay_step_hours: 1,
            sync_interval_secs: 600,
        }
    }
}

impl TimetokeParams {
    pub fn validate_for_accrual(&self) -> bool {
        self.minimum_window_secs > 0 && self.accrual_cap_hours > 0
    }

    pub fn validate_for_decay(&self) -> bool {
        self.decay_interval_secs > 0 && self.decay_step_hours > 0
    }
}

impl Default for ReputationWeights {
    fn default() -> Self {
        Self::new(0.4, 0.2, 0.2, 0.15, 0.05).expect("default weights must be valid")
    }
}

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
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Tier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Tier {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZsiIdentity {
    pub public_key_commitment: String,
    pub validated: bool,
    pub reputation_proof: Option<String>,
}

impl ZsiIdentity {
    pub fn new(public_key_hint: &str) -> Self {
        Self {
            public_key_commitment: Self::commitment_from_hint(public_key_hint),
            validated: false,
            reputation_proof: None,
        }
    }

    pub fn validate(&mut self, proof: &str) {
        self.validated = true;
        self.reputation_proof = Some(proof.to_string());
    }

    pub fn invalidate(&mut self) {
        self.validated = false;
        self.reputation_proof = None;
    }

    pub fn commitment_from_hint(hint: &str) -> String {
        match hex::decode(hint) {
            Ok(bytes) => Self::commitment_from_bytes(&bytes),
            Err(_) => Self::commitment_from_bytes(hint.as_bytes()),
        }
    }

    fn commitment_from_bytes(bytes: &[u8]) -> String {
        hex::encode::<[u8; 32]>(Blake2sHasher::hash(bytes).into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TimetokeBalance {
    pub hours_online: u64,
    pub last_proof_timestamp: u64,
    pub last_decay_timestamp: u64,
    pub last_sync_timestamp: u64,
}

impl TimetokeBalance {
    pub fn record_proof(
        &mut self,
        window_start: u64,
        window_end: u64,
        params: &TimetokeParams,
    ) -> Option<u64> {
        if !params.validate_for_accrual() {
            return None;
        }
        if window_end <= window_start {
            return None;
        }
        if window_end <= self.last_proof_timestamp {
            return None;
        }
        let effective_start = if self.last_proof_timestamp == 0 {
            window_start
        } else {
            window_start.max(self.last_proof_timestamp)
        };
        let duration = window_end.saturating_sub(effective_start);
        if duration < params.minimum_window_secs {
            return None;
        }
        let earned_hours = duration / 3_600;
        if earned_hours == 0 {
            return None;
        }
        let remaining_capacity = params.accrual_cap_hours.saturating_sub(self.hours_online);
        if remaining_capacity == 0 {
            self.last_proof_timestamp = window_end;
            return Some(0);
        }
        let credited_hours = earned_hours.min(remaining_capacity);
        self.hours_online = self.hours_online.saturating_add(credited_hours);
        self.last_proof_timestamp = window_end;
        if self.last_decay_timestamp == 0 {
            self.last_decay_timestamp = window_end;
        }
        Some(credited_hours)
    }

    pub fn debit_penalty(&mut self, penalty_hours: u64) -> u64 {
        let removed = penalty_hours.min(self.hours_online);
        self.hours_online = self.hours_online.saturating_sub(removed);
        removed
    }

    pub fn apply_decay(&mut self, now: u64, params: &TimetokeParams) -> Option<u64> {
        if !params.validate_for_decay() {
            return None;
        }
        if self.last_decay_timestamp == 0 {
            self.last_decay_timestamp = now;
            return None;
        }
        if now <= self.last_decay_timestamp {
            return None;
        }
        let elapsed = now.saturating_sub(self.last_decay_timestamp);
        if elapsed < params.decay_interval_secs {
            return None;
        }
        let periods = elapsed / params.decay_interval_secs;
        if periods == 0 {
            return None;
        }
        let total_decay = params.decay_step_hours.saturating_mul(periods);
        let removed = total_decay.min(self.hours_online);
        if removed == 0 {
            self.last_decay_timestamp = now;
            return None;
        }
        self.hours_online = self.hours_online.saturating_sub(removed);
        self.last_decay_timestamp = now;
        Some(removed)
    }

    pub fn should_sync(&self, now: u64, params: &TimetokeParams) -> bool {
        if params.sync_interval_secs == 0 {
            return false;
        }
        if self.last_sync_timestamp == 0 {
            return self.hours_online > 0;
        }
        now.saturating_sub(self.last_sync_timestamp) >= params.sync_interval_secs
    }

    pub fn mark_synced(&mut self, now: u64) {
        self.last_sync_timestamp = now;
    }

    pub fn merge_snapshot(&mut self, record: &TimetokeRecord) -> bool {
        let remote_hours = record.balance.min(u128::from(u64::MAX)) as u64;
        let mut changed = false;
        if record.last_update > self.last_proof_timestamp
            || (record.last_update == self.last_proof_timestamp && remote_hours > self.hours_online)
        {
            self.hours_online = remote_hours;
            self.last_proof_timestamp = record.last_update;
            changed = true;
        }
        if record.last_sync > self.last_sync_timestamp {
            self.last_sync_timestamp = record.last_sync;
            changed = true;
        }
        if record.last_decay > self.last_decay_timestamp {
            self.last_decay_timestamp = record.last_decay;
            changed = true;
        }
        changed
    }

    pub fn as_record(&self, identity: &Address) -> TimetokeRecord {
        TimetokeRecord {
            identity: identity.clone(),
            balance: self.hours_online as u128,
            epoch_accrual: 0,
            decay_rate: 1.0,
            last_update: self.last_proof_timestamp,
            last_sync: self.last_sync_timestamp,
            last_decay: self.last_decay_timestamp,
        }
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationProfile {
    pub zsi: ZsiIdentity,
    pub timetokes: TimetokeBalance,
    pub consensus_success: u64,
    pub peer_feedback: i64,
    pub last_decay_timestamp: u64,
    pub score: f64,
    pub tier: Tier,
}

impl ReputationProfile {
    pub fn new(identity_hint: &str) -> Self {
        let mut profile = Self {
            zsi: ZsiIdentity::new(identity_hint),
            timetokes: TimetokeBalance::default(),
            consensus_success: 0,
            peer_feedback: 0,
            last_decay_timestamp: current_timestamp(),
            score: 0.0,
            tier: Tier::default(),
        };
        profile.update_tier();
        profile
    }

    /// Marks the profile as having a validated genesis identity while keeping
    /// the reputation state at its neutral origin. This ensures reputation is
    /// always anchored to the genesis proof before any further activity-based
    /// adjustments are accumulated.
    pub fn bind_genesis_identity(&mut self, proof: &str) {
        self.zsi.validate(proof);
        self.timetokes = TimetokeBalance::default();
        self.consensus_success = 0;
        self.peer_feedback = 0;
        self.score = 0.0;
        self.tier = Tier::Tl0;
        self.last_decay_timestamp = current_timestamp();
    }

    pub fn record_online_proof(
        &mut self,
        window_start: u64,
        window_end: u64,
        params: &TimetokeParams,
    ) -> Option<u64> {
        self.timetokes
            .record_proof(window_start, window_end, params)
    }

    pub fn record_consensus_success(&mut self) {
        self.consensus_success = self.consensus_success.saturating_add(1);
    }

    pub fn apply_peer_feedback(&mut self, delta: i64) {
        self.peer_feedback = self.peer_feedback.saturating_add(delta);
    }

    pub fn update_decay_reference(&mut self, timestamp: u64) {
        self.last_decay_timestamp = timestamp;
    }

    fn saturating_curve(value: f64, scale: f64) -> f64 {
        if scale <= 0.0 {
            return 0.0;
        }
        1.0 - (-value / scale).exp()
    }

    fn decay_penalty(&self, now: u64) -> f64 {
        let elapsed = now.saturating_sub(self.last_decay_timestamp);
        Self::saturating_curve(elapsed as f64, 86_400.0 * 7.0)
    }

    pub fn recompute_score(&mut self, weights: &ReputationWeights, now: u64) {
        let params = ReputationParams::with_weights(weights.clone());
        self.recompute_with_params(&params, now);
    }

    pub fn recompute_with_params(&mut self, params: &ReputationParams, now: u64) {
        let weights = &params.weights;
        let v = if self.zsi.validated { 1.0 } else { 0.0 };
        let u = Self::saturating_curve(self.timetokes.hours_online as f64, 24.0);
        let c = Self::saturating_curve(self.consensus_success as f64, 128.0);
        let p = Self::saturating_curve(self.peer_feedback.max(0) as f64, 50.0);
        let decay = self.decay_penalty(now);
        self.score = weights.validation() * v
            + weights.uptime() * u
            + weights.consensus() * c
            + weights.peer_feedback() * p
            - weights.decay() * decay;
        self.score = self.score.clamp(0.0, 1.0);
        self.update_tier_with(&params.tier_thresholds);
    }

    pub fn apply_decay_if_needed(&mut self, params: &ReputationParams, now: u64) -> bool {
        if now <= self.last_decay_timestamp {
            return false;
        }
        let elapsed = now.saturating_sub(self.last_decay_timestamp);
        if elapsed < params.decay_interval_secs {
            return false;
        }
        if params.decay_factor <= 0.0 || self.score <= 0.0 {
            self.last_decay_timestamp = now;
            return false;
        }
        let retained = (1.0 - params.decay_factor).clamp(0.0, 1.0);
        self.score = (self.score * retained).clamp(0.0, 1.0);
        self.last_decay_timestamp = now;
        self.update_tier_with(&params.tier_thresholds);
        true
    }

    pub fn promote_tier(&mut self, target: Tier) {
        if target > self.tier {
            self.tier = target;
        }
    }

    pub fn demote_tier(&mut self, target: Tier) {
        if target < self.tier {
            self.tier = target;
        }
    }

    pub fn apply_slash(&mut self) {
        self.score = 0.0;
        self.tier = Tier::Tl0;
        self.consensus_success = 0;
        self.peer_feedback = 0;
        self.timetokes = TimetokeBalance::default();
    }

    fn update_tier(&mut self) {
        let thresholds = TierThresholds::default();
        self.update_tier_with(&thresholds);
    }

    fn update_tier_with(&mut self, thresholds: &TierThresholds) {
        self.tier = if !self.zsi.validated {
            Tier::Tl0
        } else if self.timetokes.hours_online < thresholds.tier2_min_uptime_hours {
            Tier::Tl1
        } else if self.consensus_success < thresholds.tier3_min_consensus_success {
            Tier::Tl2
        } else if self.consensus_success < thresholds.tier4_min_consensus_success {
            Tier::Tl3
        } else if self.score < thresholds.tier5_min_score {
            Tier::Tl4
        } else {
            Tier::Tl5
        };
    }
}

impl Default for ReputationProfile {
    fn default() -> Self {
        Self::new("default-reputation")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_thresholds() -> TierThresholds {
        TierThresholds {
            tier2_min_uptime_hours: 12,
            tier3_min_consensus_success: 4,
            tier4_min_consensus_success: 7,
            tier5_min_score: 0.8,
        }
    }

    #[test]
    fn record_proof_ignores_overlapping_windows() {
        let mut balance = TimetokeBalance::default();
        let params = TimetokeParams::default();

        let credited = balance.record_proof(0, 7_200, &params);
        assert_eq!(credited, Some(2));
        assert_eq!(balance.hours_online, 2);

        let credited = balance.record_proof(3_600, 10_800, &params);
        assert_eq!(credited, Some(1));
        assert_eq!(balance.hours_online, 3);

        assert_eq!(balance.record_proof(0, 7_200, &params), None);
    }

    #[test]
    fn record_proof_respects_accrual_cap() {
        let mut balance = TimetokeBalance::default();
        let mut params = TimetokeParams::default();
        params.accrual_cap_hours = 5;

        let credited = balance.record_proof(0, 21_600, &params);
        assert_eq!(credited, Some(5));
        assert_eq!(balance.hours_online, 5);

        let credited = balance.record_proof(21_600, 28_800, &params);
        assert_eq!(credited, Some(0));
        assert_eq!(balance.hours_online, 5);
    }

    #[test]
    fn apply_decay_consumes_multiple_intervals() {
        let mut balance = TimetokeBalance {
            hours_online: 10,
            last_proof_timestamp: 3_600,
            last_decay_timestamp: 3_600,
            last_sync_timestamp: 0,
        };
        let mut params = TimetokeParams::default();
        params.decay_interval_secs = 3_600;
        params.decay_step_hours = 2;

        let removed = balance.apply_decay(14_400, &params);
        assert_eq!(removed, Some(6));
        assert_eq!(balance.hours_online, 4);
        assert_eq!(balance.last_decay_timestamp, 14_400);
    }

    #[test]
    fn should_sync_respects_toggle_and_intervals() {
        let mut balance = TimetokeBalance::default();
        let params = TimetokeParams::default();

        assert!(!balance.should_sync(0, &params));

        balance.hours_online = 1;
        assert!(balance.should_sync(0, &params));

        balance.mark_synced(100);
        assert!(!balance.should_sync(100, &params));
        assert!(!balance.should_sync(100 + params.sync_interval_secs - 1, &params));
        assert!(balance.should_sync(100 + params.sync_interval_secs, &params));

        let mut disabled = params.clone();
        disabled.sync_interval_secs = 0;
        assert!(!balance.should_sync(1_000, &disabled));
    }

    #[test]
    fn invalid_parameters_short_circuit_accrual_and_decay() {
        let mut balance = TimetokeBalance::default();
        let mut params = TimetokeParams::default();
        params.minimum_window_secs = 0;
        assert_eq!(balance.record_proof(0, 3_600, &params), None);

        params.minimum_window_secs = 3_600;
        params.accrual_cap_hours = 0;
        assert_eq!(balance.record_proof(0, 7_200, &params), None);

        balance.hours_online = 5;
        balance.last_decay_timestamp = 1;

        let mut decay_params = TimetokeParams::default();
        decay_params.decay_interval_secs = 0;
        assert_eq!(balance.apply_decay(10, &decay_params), None);

        decay_params.decay_interval_secs = 100;
        decay_params.decay_step_hours = 0;
        assert_eq!(balance.apply_decay(200, &decay_params), None);
    }

    #[test]
    fn reputation_weights_reject_negative_components() {
        let err = ReputationWeights::new(-0.1, 0.5, 0.5, 0.1, 0.0).unwrap_err();
        assert!(matches!(
            err,
            ReputationWeightsError::OutOfRange { field: "w_v", .. }
        ));
    }

    #[test]
    fn reputation_weights_require_normalized_sum() {
        let err = ReputationWeights::new(0.5, 0.3, 0.3, 0.1, 0.0).unwrap_err();
        assert!(matches!(err, ReputationWeightsError::NotNormalized { .. }));
    }

    #[test]
    fn reputation_weights_allow_small_rounding_errors() {
        let weights = ReputationWeights::new(0.4000002, 0.1999999, 0.2, 0.15, 0.05).unwrap();
        let sum: f64 = weights.validation()
            + weights.uptime()
            + weights.consensus()
            + weights.peer_feedback()
            + weights.decay();
        assert!((sum - 1.0).abs() < ReputationWeights::NORMALIZATION_TOLERANCE);
    }

    #[test]
    fn weight_overrides_change_scoring_components() {
        let now = 1_000;
        let mut profile = validated_profile();
        profile.timetokes.hours_online = 48;
        profile.consensus_success = 200;
        profile.peer_feedback = 150;
        profile.last_decay_timestamp = now;

        let weights_validation = ReputationWeights::new(1.0, 0.0, 0.0, 0.0, 0.0).unwrap();
        profile.recompute_score(&weights_validation, now);
        assert!((profile.score - 1.0).abs() < 1e-9);

        let weights_peer = ReputationWeights::new(0.0, 0.0, 0.0, 1.0, 0.0).unwrap();
        profile.peer_feedback = 0;
        profile.recompute_score(&weights_peer, now);
        assert!((profile.score - 0.0).abs() < 1e-9);
    }

    fn validated_profile() -> ReputationProfile {
        let mut profile = ReputationProfile::new("validator");
        profile.zsi.validate("proof");
        profile
    }

    #[test]
    fn validation_controls_tier_promotions_and_demotions() {
        let thresholds = base_thresholds();
        let mut profile = validated_profile();
        profile.timetokes.hours_online = thresholds.tier2_min_uptime_hours;
        profile.consensus_success = thresholds.tier4_min_consensus_success;
        profile.score = thresholds.tier5_min_score;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl5);

        profile.zsi.invalidate();
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl0);
    }

    #[test]
    fn uptime_boundary_moves_between_tier1_and_tier2() {
        let thresholds = base_thresholds();
        let mut profile = validated_profile();
        profile.consensus_success = thresholds.tier3_min_consensus_success - 1;
        profile.score = thresholds.tier5_min_score;

        profile.timetokes.hours_online = thresholds.tier2_min_uptime_hours - 1;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl1);

        profile.timetokes.hours_online = thresholds.tier2_min_uptime_hours;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl2);

        profile.timetokes.hours_online = thresholds.tier2_min_uptime_hours - 1;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl1);
    }

    #[test]
    fn consensus_boundary_moves_between_tier2_and_tier3() {
        let thresholds = base_thresholds();
        let mut profile = validated_profile();
        profile.timetokes.hours_online = thresholds.tier2_min_uptime_hours;
        profile.consensus_success = thresholds.tier3_min_consensus_success - 1;
        profile.score = thresholds.tier5_min_score;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl2);

        profile.consensus_success = thresholds.tier3_min_consensus_success;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl3);

        profile.consensus_success = thresholds.tier3_min_consensus_success - 1;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl2);
    }

    #[test]
    fn high_consensus_boundary_moves_between_tier3_and_tier4() {
        let thresholds = base_thresholds();
        let mut profile = validated_profile();
        profile.timetokes.hours_online = thresholds.tier2_min_uptime_hours;
        profile.consensus_success = thresholds.tier4_min_consensus_success - 1;
        profile.score = thresholds.tier5_min_score - 0.01;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl3);

        profile.consensus_success = thresholds.tier4_min_consensus_success;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl4);

        profile.consensus_success = thresholds.tier4_min_consensus_success - 1;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl3);
    }

    #[test]
    fn score_boundary_moves_between_tier4_and_tier5() {
        let thresholds = base_thresholds();
        let mut profile = validated_profile();
        profile.timetokes.hours_online = thresholds.tier2_min_uptime_hours;
        profile.consensus_success = thresholds.tier4_min_consensus_success;

        profile.score = thresholds.tier5_min_score - 0.01;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl4);

        profile.score = thresholds.tier5_min_score;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl5);

        profile.score = thresholds.tier5_min_score - 0.01;
        profile.update_tier_with(&thresholds);
        assert_eq!(profile.tier, Tier::Tl4);
    }
}
