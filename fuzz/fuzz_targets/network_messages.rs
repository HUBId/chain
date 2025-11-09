#![no_main]

use libfuzzer_sys::fuzz_target;
use rpp_p2p::pipeline::LightClientSync;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NetworkInput {
    #[serde(default)]
    plan: Option<serde_json::Value>,
    #[serde(default)]
    update: Option<serde_json::Value>,
    #[serde(default)]
    chunk: Option<serde_json::Value>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = serde_json::from_slice::<NetworkInput>(data) {
        let mut sync = LightClientSync::default();
        if let Some(plan) = input.plan {
            if let Ok(bytes) = serde_json::to_vec(&plan) {
                let _ = sync.ingest_plan(&bytes);
            }
        }
        if let Some(update) = input.update {
            if let Ok(bytes) = serde_json::to_vec(&update) {
                let _ = sync.ingest_light_client_update(&bytes);
            }
        }
        if let Some(chunk) = input.chunk {
            if let Ok(bytes) = serde_json::to_vec(&chunk) {
                let _ = sync.ingest_chunk(&bytes);
            }
        }
    }
});
