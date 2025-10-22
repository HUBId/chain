use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::proof_backend::Blake2sHasher;

/// Reputation tiers exposed by the blueprint implementation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Tl0,
    Tl1,
    Tl2,
    Tl3,
    Tl4,
    Tl5,
}

impl Default for Tier {
    fn default() -> Self {
        Tier::Tl0
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Tier::Tl0 => "TL0",
            Tier::Tl1 => "TL1",
            Tier::Tl2 => "TL2",
            Tier::Tl3 => "TL3",
            Tier::Tl4 => "TL4",
            Tier::Tl5 => "TL5",
        };
        f.write_str(label)
    }
}

/// Weight configuration used when recomputing reputation scores.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReputationWeights {
    validation: f64,
    uptime: f64,
    consensus: f64,
    peer_reports: f64,
    decay: f64,
}

impl ReputationWeights {
    pub fn new(
        validation: f64,
        uptime: f64,
        consensus: f64,
        peer_reports: f64,
        decay: f64,
    ) -> Self {
        Self {
            validation,
            uptime,
            consensus,
            peer_reports,
            decay,
        }
    }

    pub fn validation(&self) -> f64 {
        self.validation
    }

    pub fn uptime(&self) -> f64 {
        self.uptime
    }

    pub fn consensus(&self) -> f64 {
        self.consensus
    }

    pub fn peer_reports(&self) -> f64 {
        self.peer_reports
    }

    pub fn decay(&self) -> f64 {
        self.decay
    }

    pub fn total(&self) -> f64 {
        self.validation + self.uptime + self.consensus + self.peer_reports + self.decay
    }
}

impl Default for ReputationWeights {
    fn default() -> Self {
        // Mirrors the runtime defaults while avoiding the heavy validation
        // logic from the production module.
        Self::new(0.4, 0.2, 0.2, 0.15, 0.05)
    }
}

/// Tracking information for the zero-knowledge identity proof associated with
/// an account.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZeroSyncInfo {
    pub validated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
}

impl ZeroSyncInfo {
    pub fn validate(&mut self, commitment: &str) {
        self.validated = true;
        self.commitment = Some(commitment.to_string());
    }
}

/// Snapshot of the timetoke reputation component used when deriving tiers.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimetokeReputation {
    pub balance: u64,
    pub last_decay_timestamp: u64,
}

impl TimetokeReputation {
    pub fn credit(&mut self, amount: u64) {
        self.balance = self.balance.saturating_add(amount);
    }

    pub fn decay_to(&mut self, timestamp: u64) {
        self.last_decay_timestamp = timestamp;
    }
}

/// Minimal reputation profile required by the official circuits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReputationProfile {
    pub tier: Tier,
    pub score: f64,
    pub last_decay_timestamp: u64,
    pub wallet_commitment: Option<String>,
    pub zsi: ZeroSyncInfo,
    pub timetokes: TimetokeReputation,
}

impl Default for ReputationProfile {
    fn default() -> Self {
        Self {
            tier: Tier::Tl0,
            score: 0.0,
            last_decay_timestamp: 0,
            wallet_commitment: None,
            zsi: ZeroSyncInfo::default(),
            timetokes: TimetokeReputation::default(),
        }
    }
}

impl ReputationProfile {
    /// Construct a profile bound to the provided wallet public key.  The
    /// commitment is derived using the blueprint Blake2s hasher to avoid
    /// relying on the production crypto module.
    pub fn new(wallet_pk_hex: &str) -> Self {
        let mut profile = Self::default();
        if let Ok(bytes) = hex::decode(wallet_pk_hex) {
            let commitment: [u8; 32] = Blake2sHasher::hash(&bytes).into();
            profile.wallet_commitment = Some(hex::encode(commitment));
        } else {
            let commitment: [u8; 32] = Blake2sHasher::hash(wallet_pk_hex.as_bytes()).into();
            profile.wallet_commitment = Some(hex::encode(commitment));
        }
        profile
    }

    /// Recompute the aggregate reputation score.  The blueprint keeps the
    /// logic intentionally simple while preserving the tier transitions
    /// required by the official circuits.
    pub fn recompute_score(&mut self, weights: &ReputationWeights, now: u64) {
        self.last_decay_timestamp = now;
        self.timetokes.decay_to(now);

        if !self.zsi.validated {
            self.score = 0.0;
            self.tier = Tier::Tl0;
            return;
        }

        self.score = weights.total();
        let computed_tier = if self.timetokes.balance >= 72 {
            Tier::Tl3
        } else if self.timetokes.balance >= 24 {
            Tier::Tl2
        } else {
            Tier::Tl1
        };
        if self.tier.cmp(&computed_tier) == Ordering::Less {
            self.tier = computed_tier;
        }
    }

    pub fn update_decay_reference(&mut self, timestamp: u64) {
        self.last_decay_timestamp = timestamp;
        self.timetokes.decay_to(timestamp);
    }
}

/// Helper returning the current UNIX timestamp in seconds.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
