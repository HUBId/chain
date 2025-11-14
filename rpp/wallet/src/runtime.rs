#[cfg(feature = "runtime")]
pub mod runtime {
    pub use rpp::runtime::*;
}

#[cfg(not(feature = "runtime"))]
pub mod runtime {
    pub mod config {
        use serde::{Deserialize, Serialize};

        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct QueueWeightsConfig {
            pub priority: f64,
            pub fee: f64,
        }

        impl Default for QueueWeightsConfig {
            fn default() -> Self {
                Self {
                    priority: 0.7,
                    fee: 0.3,
                }
            }
        }
    }

    pub mod node {
        use serde::{Deserialize, Serialize};

        use super::config::QueueWeightsConfig;

        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct MempoolStatus {
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub transactions: Vec<serde_json::Value>,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub identities: Vec<serde_json::Value>,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub votes: Vec<serde_json::Value>,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub uptime_proofs: Vec<serde_json::Value>,
            pub queue_weights: QueueWeightsConfig,
        }

        impl Default for MempoolStatus {
            fn default() -> Self {
                Self {
                    transactions: Vec::new(),
                    identities: Vec::new(),
                    votes: Vec::new(),
                    uptime_proofs: Vec::new(),
                    queue_weights: QueueWeightsConfig::default(),
                }
            }
        }
    }
}
