use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

use crate::config::ElectrsConfig;

use super::firewood_adapter::{FirewoodAdapter, RuntimeAdapters};
use super::index::Index;
use super::rpp_ledger::bitcoin::Network as LedgerNetwork;
use super::tracker::Tracker;
use super::Daemon;

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
            Some(Daemon::new(firewood).context("initialise daemon")?)
        }
        None => None,
    };

    let tracker = if config.features.tracker {
        let network: LedgerNetwork = config.network.into();
        let index = Index::open(index_path, network).context("open index")?;
        Some(Tracker::new(index))
    } else {
        None
    };

    Ok(ElectrsHandles {
        firewood,
        daemon,
        tracker,
    })
}
