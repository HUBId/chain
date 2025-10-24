use anyhow::Result;
use clap::Parser;
use rpp_node::{RunArgs, RuntimeMode};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp validator runtime", long_about = None)]
struct ValidatorCli {
    #[command(flatten)]
    args: RunArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = ValidatorCli::parse();
    let options = cli.args.into_bootstrap_options(RuntimeMode::Validator);
    rpp_node::bootstrap(RuntimeMode::Validator, options).await
}
