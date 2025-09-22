use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TierLevel {
    Tl0,
    Tl1,
    Tl2,
    Tl3,
    Tl4,
    Tl5,
}

impl Default for TierLevel {
    fn default() -> Self {
        TierLevel::Tl0
    }
}

impl TierLevel {
    pub fn from_reputation(score: f64) -> Self {
        match score {
            s if s >= 5.0 => TierLevel::Tl5,
            s if s >= 4.0 => TierLevel::Tl4,
            s if s >= 3.0 => TierLevel::Tl3,
            s if s >= 2.0 => TierLevel::Tl2,
            s if s >= 1.0 => TierLevel::Tl1,
            _ => TierLevel::Tl0,
        }
    }
}
