use std::process::ExitCode;

use clap::Parser;
use rpp_node::{RuntimeMode, RuntimeOptions};
use rpp_wallet::cli::wallet::{InitContext, WalletCliError, WalletCommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about = "Run the rpp wallet runtime", long_about = None)]
struct WalletCli {
    #[command(flatten)]
    options: RuntimeOptions,
    #[command(subcommand)]
    command: Option<WalletCommand>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = WalletCli::parse();
    if let Some(command) = cli.command {
        let context = InitContext::new(
            resolve_wallet_config_path(&cli.options),
            cli.options.data_dir.clone(),
        );
        match command.execute(&context).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                report_cli_error(&err);
                ExitCode::FAILURE
            }
        }
    } else {
        match rpp_node::run(RuntimeMode::Wallet, cli.options).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{err}");
                ExitCode::from(err.exit_code() as u8)
            }
        }
    }
}

fn resolve_wallet_config_path(options: &RuntimeOptions) -> Option<PathBuf> {
    if let Some(path) = options.wallet_config.clone() {
        return Some(path);
    }
    RuntimeMode::Wallet
        .default_wallet_config_path()
        .map(PathBuf::from)
}

fn report_cli_error(error: &WalletCliError) {
    match error {
        WalletCliError::RpcError {
            code,
            friendly,
            message,
            json_code,
            details,
        } => {
            let details_fragment = details
                .as_ref()
                .map(|value| format!(" details={value}"))
                .unwrap_or_default();
            eprintln!(
                "wallet RPC error code={} json_code={} friendly={:?} message={:?}{}",
                code, json_code, friendly, message, details_fragment
            );
        }
        other => eprintln!("{other}"),
    }
}
