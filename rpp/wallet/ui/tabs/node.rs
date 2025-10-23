use serde::Serialize;

use crate::orchestration::PipelineError;
use crate::reputation::Tier;
use crate::storage::ledger::SlashingEvent;

#[derive(Clone, Debug, Serialize)]
pub struct NodeTabMetrics {
    pub reputation_score: f64,
    pub tier: Tier,
    pub uptime_hours: u64,
    pub latest_block_height: u64,
    pub latest_block_hash: Option<String>,
    pub total_blocks: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slashing_alerts: Vec<SlashingEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pipeline_errors: Vec<PipelineError>,
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
