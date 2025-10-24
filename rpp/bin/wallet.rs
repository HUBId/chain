use std::process::ExitCode;

use clap::Parser;
use rpp_node::{RuntimeMode, RuntimeOptions};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp wallet runtime", long_about = None)]
struct WalletCli {
    #[command(flatten)]
    options: RuntimeOptions,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = WalletCli::parse();
    match rpp_node::run(RuntimeMode::Wallet, cli.options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(err.exit_code() as u8)
        }
    }
}
