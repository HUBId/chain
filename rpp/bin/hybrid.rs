use anyhow::Result;
use clap::Parser;
use rpp_node::{RunArgs, RuntimeMode};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp hybrid runtime", long_about = None)]
struct HybridCli {
    #[command(flatten)]
    args: RunArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = HybridCli::parse();
    let options = cli.args.into_bootstrap_options(RuntimeMode::Hybrid);
    rpp_node::bootstrap(RuntimeMode::Hybrid, options).await
}
