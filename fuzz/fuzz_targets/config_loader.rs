#![no_main]

use libfuzzer_sys::fuzz_target;
use rpp_chain::config::NodeConfig;

fuzz_target!(|data: &[u8]| {
    if let Ok(config) = toml::from_slice::<NodeConfig>(data) {
        let _ = config.validate();
    }
});
