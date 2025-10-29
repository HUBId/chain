use std::process::ExitCode;

use clap::Parser;
use rpp_node::{RuntimeMode, RuntimeOptions};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp validator runtime", long_about = None)]
struct ValidatorCli {
    #[command(flatten)]
    options: RuntimeOptions,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = ValidatorCli::parse();
    if let Err(err) = rpp_node::ensure_prover_backend(RuntimeMode::Validator) {
        eprintln!("{err}");
        return ExitCode::from(err.exit_code() as u8);
    }

    match rpp_node::run(RuntimeMode::Validator, cli.options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(err.exit_code() as u8)
        }
    }
}
