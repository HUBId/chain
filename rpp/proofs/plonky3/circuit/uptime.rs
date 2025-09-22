use serde::{Deserialize, Serialize};

/// Witness representation for the uptime (Timetoke) circuit.
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

impl UptimeWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_address: impl Into<String>,
        node_clock: u64,
        epoch: u64,
        head_hash: impl Into<String>,
        window_start: u64,
        window_end: u64,
        commitment: impl Into<String>,
    ) -> Self {
        Self {
            wallet_address: wallet_address.into(),
            node_clock,
            epoch,
            head_hash: head_hash.into(),
            window_start,
            window_end,
            commitment: commitment.into(),
        }
    }
}
