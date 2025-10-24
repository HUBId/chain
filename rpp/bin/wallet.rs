use anyhow::Result;
use clap::Parser;
use rpp_node::{RunArgs, RuntimeMode};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp wallet runtime", long_about = None)]
struct WalletCli {
    #[command(flatten)]
    args: RunArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = WalletCli::parse();
    let options = cli.args.into_bootstrap_options(RuntimeMode::Wallet);
    rpp_node::bootstrap(RuntimeMode::Wallet, options).await
}
