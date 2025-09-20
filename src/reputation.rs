use std::cmp::Ordering;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use hex;
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

/// Configuration weights used to evaluate the reputation score. The values
/// mirror the blueprint defaults but can be tuned through governance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationWeights {
    pub w_v: f64,
    pub w_u: f64,
    pub w_c: f64,
    pub w_p: f64,
    pub w_d: f64,
}

impl Default for ReputationWeights {
    fn default() -> Self {
        Self {
            w_v: 0.4,
            w_u: 0.2,
            w_c: 0.2,
            w_p: 0.15,
            w_d: 0.05,
        }
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
pub struct TimetokeBalance {
    pub hours_online: u64,
    pub last_proof_timestamp: u64,
}

impl TimetokeBalance {
    pub fn record_proof(&mut self, timestamp: u64) {
        if timestamp > self.last_proof_timestamp {
            self.hours_online = self.hours_online.saturating_add(1);
            self.last_proof_timestamp = timestamp;
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
        Self {
            zsi: ZsiIdentity::new(identity_hint),
            timetokes: TimetokeBalance::default(),
            consensus_success: 0,
            peer_feedback: 0,
            last_decay_timestamp: current_timestamp(),
            score: 0.0,
            tier: Tier::default(),
        }
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

    pub fn record_online_proof(&mut self, timestamp: u64) {
        self.timetokes.record_proof(timestamp);
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
        let v = if self.zsi.validated { 1.0 } else { 0.0 };
        let u = Self::saturating_curve(self.timetokes.hours_online as f64, 24.0);
        let c = Self::saturating_curve(self.consensus_success as f64, 128.0);
        let p = Self::saturating_curve(self.peer_feedback.max(0) as f64, 50.0);
        let decay = self.decay_penalty(now);
        self.score = weights.w_v * v + weights.w_u * u + weights.w_c * c + weights.w_p * p
            - weights.w_d * decay;
        self.score = self.score.clamp(0.0, 1.0);
        self.update_tier();
    }

    fn update_tier(&mut self) {
        self.tier = if !self.zsi.validated {
            Tier::Tl0
        } else if self.timetokes.hours_online < 24 {
            Tier::Tl1
        } else if self.consensus_success < 10 {
            Tier::Tl2
        } else if self.consensus_success < 100 {
            Tier::Tl3
        } else if self.score < 0.75 {
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
