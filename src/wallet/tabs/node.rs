use serde::Serialize;

use crate::reputation::Tier;

#[derive(Clone, Debug, Serialize)]
pub struct NodeTabMetrics {
    pub reputation_score: f64,
    pub tier: Tier,
    pub uptime_hours: u64,
    pub latest_block_height: u64,
    pub latest_block_hash: Option<String>,
    pub total_blocks: u64,
}

impl NodeTabMetrics {
    pub fn consensus_health(&self) -> &'static str {
        match self.tier {
            Tier::Tl3 | Tier::Tl4 | Tier::Tl5 => "consensus-active",
            Tier::Tl1 | Tier::Tl2 => "observer",
            Tier::Tl0 => "wallet-only",
        }
    }
}
