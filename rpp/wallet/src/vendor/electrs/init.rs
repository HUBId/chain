use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

use crate::config::ElectrsConfig;

use super::daemon::{Daemon, DaemonOptions, DaemonP2pOptions};
use super::firewood_adapter::{FirewoodAdapter, RuntimeAdapters};
use super::index::Index;
use super::rpp_ledger::bitcoin::Network as LedgerNetwork;
use super::tracker::{Tracker, TrackerOptions};
use rpp_p2p::GossipTopic;

/// Collection of ready-to-use handles for the Electrs integration.
#[derive(Debug)]
pub struct ElectrsHandles {
    /// Firewood-backed storage adapter.
    pub firewood: FirewoodAdapter,
    /// Runtime-backed daemon (present when the runtime feature gate is enabled).
    pub daemon: Option<Daemon>,
    /// High-level tracker mirroring the runtime node.
    pub tracker: Option<Tracker>,
}

/// Initialise the Electrs integration from configuration.
///
/// The caller provides the configuration, storage locations and optional runtime
/// adapters. Depending on the configured feature gates this routine wires up
/// the Firewood adapter, attaches runtime clients and opens the tracker index.
#[allow(clippy::too_many_arguments)]
pub fn initialize(
    config: &ElectrsConfig,
    firewood_dir: impl AsRef<Path>,
    index_dir: impl AsRef<Path>,
    runtime_adapters: Option<RuntimeAdapters>,
) -> Result<ElectrsHandles> {
    if config.features.tracker && !config.features.runtime {
        return Err(anyhow!(
            "tracker feature requires the runtime feature to be enabled"
        ));
    }

    let firewood_path = firewood_dir.as_ref();
    let index_path = index_dir.as_ref();

    fs::create_dir_all(firewood_path).context("create firewood directory")?;
    fs::create_dir_all(index_path).context("create index directory")?;

    let tracker_topic = parse_gossip_topic(&config.tracker.notifications.topic)
        .context("parse tracker notification topic")?;
    let mut daemon_topics = parse_gossip_topics(&config.p2p.gossip_topics)
        .context("parse daemon gossip topics")?;
    if !daemon_topics.contains(&tracker_topic) {
        daemon_topics.push(tracker_topic);
    }

    let runtime = if config.features.runtime {
        Some(
            runtime_adapters
                .ok_or_else(|| anyhow!("runtime adapters required when runtime feature is enabled"))?,
        )
    } else {
        None
    };

    let firewood = match runtime.as_ref() {
        Some(adapters) => FirewoodAdapter::open_with_runtime(firewood_path, adapters.clone())
            .context("open firewood adapter with runtime")?,
        None => FirewoodAdapter::open(firewood_path).context("open firewood adapter")?,
    };

    let daemon = match runtime.as_ref() {
        Some(adapters) => {
            let firewood = FirewoodAdapter::open_with_runtime(firewood_path, adapters.clone())
                .context("open daemon firewood adapter")?;
            let options = DaemonOptions {
                gossip_topics: daemon_topics,
                p2p: if config.p2p.enabled {
                    Some(DaemonP2pOptions {
                        metrics_endpoint: config.p2p.metrics_endpoint,
                        network_id: config.p2p.network_id.clone(),
                        auth_token: config.p2p.auth_token.clone(),
                    })
                } else {
                    None
                },
            };
            Some(Daemon::with_options(firewood, options).context("initialise daemon")?)
        }
        None => None,
    };

    let tracker = if config.features.tracker {
        let network: LedgerNetwork = config.network.into();
        let index = Index::open(index_path, network).context("open index")?;
        Some(Tracker::with_options(
            index,
            TrackerOptions {
                telemetry_endpoint: config.tracker.telemetry_endpoint,
                subscribe_p2p_notifications: config.tracker.notifications.p2p,
                notification_topic: tracker_topic,
            },
        ))
    } else {
        None
    };

    Ok(ElectrsHandles {
        firewood,
        daemon,
        tracker,
    })
}

fn parse_gossip_topics(values: &[String]) -> Result<Vec<GossipTopic>> {
    let mut topics = Vec::new();
    for value in values {
        let topic = parse_gossip_topic(value)?;
        if !topics.contains(&topic) {
            topics.push(topic);
        }
    }
    if topics.is_empty() {
        topics.push(GossipTopic::Blocks);
    }
    Ok(topics)
}

fn parse_gossip_topic(value: &str) -> Result<GossipTopic> {
    GossipTopic::from_str(value)
        .ok_or_else(|| anyhow!("unsupported gossip topic '{value}'"))
}
