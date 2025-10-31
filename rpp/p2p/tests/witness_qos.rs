use std::thread;
use std::time::Duration;

use rpp_p2p::vendor::PeerId;
use rpp_p2p::{
    GossipTopic, TopicPriority, TopicQoS, WitnessChannelConfig, WitnessGossipPipelines,
    WitnessPipelineConfig, WitnessPipelineError,
};

#[test]
fn rate_limits_apply_per_channel() {
    let mut pipelines = WitnessGossipPipelines::new(WitnessPipelineConfig {
        proofs: WitnessChannelConfig::new(2, Duration::from_millis(200), 1),
        meta: WitnessChannelConfig::new(2, Duration::from_millis(200), 1),
    });

    let peer = PeerId::random();
    pipelines
        .ingest(GossipTopic::WitnessProofs, peer, b"proof-1".to_vec())
        .expect("first proof allowed");
    let err = pipelines
        .ingest(GossipTopic::WitnessProofs, peer, b"proof-2".to_vec())
        .expect_err("second proof must trigger rate limit");
    assert!(matches!(
        err,
        WitnessPipelineError::RateLimited {
            topic: GossipTopic::WitnessProofs,
            ..
        }
    ));

    thread::sleep(Duration::from_millis(250));
    pipelines
        .ingest(GossipTopic::WitnessProofs, peer, b"proof-2".to_vec())
        .expect("rate limit should reset");
    assert_eq!(pipelines.len(GossipTopic::WitnessProofs), 2);
}

#[test]
fn buffers_are_topic_isolated() {
    let mut pipelines = WitnessGossipPipelines::new(WitnessPipelineConfig {
        proofs: WitnessChannelConfig::new(1, Duration::from_millis(200), 2),
        meta: WitnessChannelConfig::new(2, Duration::from_millis(200), 2),
    });

    let peer = PeerId::random();
    pipelines
        .ingest(GossipTopic::WitnessProofs, peer, b"proof".to_vec())
        .expect("proof queued");
    pipelines
        .ingest(GossipTopic::WitnessMeta, peer, b"meta-1".to_vec())
        .expect("meta queued");
    pipelines
        .ingest(GossipTopic::WitnessMeta, peer, b"meta-2".to_vec())
        .expect("meta queued again");

    // Proof buffer retains the single entry while meta buffer evicts oldest when full.
    assert_eq!(pipelines.len(GossipTopic::WitnessProofs), 1);
    assert_eq!(pipelines.len(GossipTopic::WitnessMeta), 2);
    let proof = pipelines
        .pop(GossipTopic::WitnessProofs)
        .expect("proof available");
    assert_eq!(proof.payload, b"proof".to_vec());
}

#[test]
fn witness_topics_expose_priority_metadata() {
    assert_eq!(
        GossipTopic::WitnessProofs.priority(),
        TopicPriority::Critical
    );
    assert_eq!(GossipTopic::WitnessProofs.qos(), TopicQoS::Throughput);
    assert_eq!(GossipTopic::WitnessMeta.priority(), TopicPriority::High);
    assert_eq!(GossipTopic::Meta.qos(), TopicQoS::Telemetry);
}
