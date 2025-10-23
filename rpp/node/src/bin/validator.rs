use anyhow::Result;
use clap::Parser;
use rpp_node::{Cli, RuntimeMode};

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    cli.mode = RuntimeMode::Validator;
    rpp_node::run(cli).await
}
