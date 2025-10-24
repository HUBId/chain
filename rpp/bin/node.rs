use anyhow::Result;
use clap::Parser;
use rpp_node::{RunArgs, RuntimeMode};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp node runtime", long_about = None)]
struct NodeCli {
    #[command(flatten)]
    args: RunArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = NodeCli::parse();
    let options = cli.args.into_bootstrap_options(RuntimeMode::Node);
    rpp_node::bootstrap(RuntimeMode::Node, options).await
}
