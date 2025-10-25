use super::*;
use crate::config::P2pConfig;
use proptest::prelude::*;
use proptest::string::string_regex;

fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(48);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

prop_compose! {
    fn arb_multiaddr()(port in 1u16..=60_000u16) -> String {
        format!("/ip4/127.0.0.1/tcp/{port}")
    }
}

prop_compose! {
    fn arb_p2p_config()(listen in arb_multiaddr(),
                        bootstrap in prop::collection::vec(arb_multiaddr(), 0..4),
                        heartbeat in 1u64..10_000u64,
                        gossip_enabled in any::<bool>(),
                        rate_limit in 1u64..1_000u64,
                        replay in 1usize..2_048usize) -> P2pConfig {
        let mut config = P2pConfig::default();
        config.listen_addr = listen;
        config.bootstrap_peers = bootstrap;
        config.heartbeat_interval_ms = heartbeat;
        config.gossip_enabled = gossip_enabled;
        config.gossip_rate_limit_per_sec = rate_limit;
        config.replay_window_size = replay;
        config
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn network_config_roundtrip(source in arb_p2p_config()) {
        let derived = NetworkConfig::from_config(&source).expect("valid P2P configuration must parse");
        assert_eq!(derived.listen_addr().to_string(), source.listen_addr);
        assert_eq!(derived.bootstrap_peers().len(), source.bootstrap_peers.len());
        assert_eq!(derived.heartbeat_interval().as_millis(), source.heartbeat_interval_ms as u128);
        assert_eq!(derived.gossip_enabled(), source.gossip_enabled);
        assert_eq!(derived.gossip_rate_limit_per_sec(), source.gossip_rate_limit_per_sec);
        assert_eq!(derived.replay_window_size(), source.replay_window_size);
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn network_config_reports_invalid_multiaddr(addr in string_regex("[a-z0-9]{5,12}").unwrap()) {
        let mut config = P2pConfig::default();
        config.listen_addr = addr.clone();
        match NetworkConfig::from_config(&config) {
            Err(NetworkSetupError::InvalidMultiaddr { addr: seen, .. }) => {
                assert_eq!(seen, addr);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn network_config_reports_invalid_bootstrap(addr in string_regex("[a-z0-9]{5,12}").unwrap()) {
        let mut config = P2pConfig::default();
        config.bootstrap_peers = vec![addr.clone()];
        match NetworkConfig::from_config(&config) {
            Err(NetworkSetupError::InvalidMultiaddr { addr: seen, .. }) => {
                assert_eq!(seen, addr);
            }
            other => panic!("unexpected bootstrap result: {other:?}"),
        }
    }
}
