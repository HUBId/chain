use std::process::ExitCode;

use clap::Parser;
use rpp_node::{ConfigurationError, RunArgs, RuntimeMode};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp node runtime", long_about = None)]
struct NodeCli {
    #[command(flatten)]
    args: RunArgs,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = NodeCli::parse();
    let options = cli.args.into_bootstrap_options(RuntimeMode::Node);
    match rpp_node::bootstrap(RuntimeMode::Node, options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => match err.downcast::<ConfigurationError>() {
            Ok(config_err) => {
                eprintln!("Error: {config_err}");
                ExitCode::from(2)
            }
            Err(err) => {
                eprintln!("{err:?}");
                ExitCode::from(1)
            }
        },
    }
}
