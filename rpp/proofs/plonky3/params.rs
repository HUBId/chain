use serde::{Deserialize, Serialize};

/// High-level parameters controlling the Plonky3 backend configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plonky3Parameters {
    pub security_bits: u32,
    pub use_gpu_acceleration: bool,
}

impl Default for Plonky3Parameters {
    fn default() -> Self {
        Self {
            security_bits: 128,
            use_gpu_acceleration: false,
        }
    }
}
