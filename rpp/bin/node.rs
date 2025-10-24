use std::process::ExitCode;

use clap::Parser;
use rpp_node::{RuntimeMode, RuntimeOptions};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp node runtime", long_about = None)]
struct NodeCli {
    #[command(flatten)]
    options: RuntimeOptions,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = NodeCli::parse();
    match rpp_node::run(RuntimeMode::Node, cli.options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(err.exit_code() as u8)
        }
    }
}
