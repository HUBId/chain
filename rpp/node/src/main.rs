use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(author, version, about = "Run an rpp node worker", long_about = None)]
struct Cli {
    /// Index of the node within the simulation cluster
    #[arg(long)]
    node_index: usize,

    /// Planned runtime for the node in milliseconds
    #[arg(long, default_value_t = 10_000)]
    duration_ms: u64,

    /// Heartbeat period in seconds for liveness reporting
    #[arg(long, default_value_t = 1)]
    heartbeat_secs: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let cli = Cli::parse();

    let mut interval = tokio::time::interval(Duration::from_secs(cli.heartbeat_secs.max(1)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    info!(
        node = cli.node_index,
        duration = cli.duration_ms,
        "node ready"
    );
    let start = Instant::now();

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let elapsed = start.elapsed().as_millis() as u64;
                info!(node = cli.node_index, elapsed_ms = elapsed, "heartbeat");
                if elapsed >= cli.duration_ms {
                    break;
                }
            }
            result = tokio::signal::ctrl_c() => {
                if let Err(err) = result {
                    warn!(node = cli.node_index, "ctrl_c listener failed: {err:?}");
                }
                info!(node = cli.node_index, "shutdown requested");
                break;
            }
        }
    }

    info!(node = cli.node_index, "node exiting");
    Ok(())
}
