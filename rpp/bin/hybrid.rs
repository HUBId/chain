use std::process::ExitCode;

use clap::Parser;
use rpp_node::{RuntimeMode, RuntimeOptions};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp hybrid runtime", long_about = None)]
struct HybridCli {
    #[command(flatten)]
    options: RuntimeOptions,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = HybridCli::parse();
    match rpp_node::run(RuntimeMode::Hybrid, cli.options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(err.exit_code() as u8)
        }
    }
}
