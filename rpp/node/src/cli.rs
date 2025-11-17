use std::process::ExitCode;

pub use rpp_chain_cli::{CliError, CliResult};

pub async fn run_cli() -> ExitCode {
    rpp_chain_cli::run_cli(|mode, options| crate::run(mode, options)).await
}
