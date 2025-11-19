use std::process::ExitCode;

use clap::Parser;
use rpp_node::{RuntimeMode, RuntimeOptions};
use rpp_wallet::cli::wallet::{InitContext, WalletCliError, WalletCommand};
use rpp_wallet::crash_reporting::{
    self, CrashReporterConfig, CrashReporterHandle, DEFAULT_SPOOL_BYTES,
};
use rpp_wallet::runtime::config::WalletConfigExt;
use rpp_wallet_interface::runtime_config::WalletConfig as RuntimeWalletConfig;
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
    let _crash_handle = configure_crash_reporting(&cli.options);
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

fn configure_crash_reporting(options: &RuntimeOptions) -> Option<CrashReporterHandle> {
    let config_path = resolve_wallet_config_path(options)?;
    let runtime_config = RuntimeWalletConfig::load(&config_path).unwrap_or_default();
    let telemetry = runtime_config.wallet.telemetry;
    let spool_dir = runtime_config.wallet.engine.data_dir.join("crash_reports");
    let reporter_config = CrashReporterConfig {
        enabled: telemetry.crash_reports,
        endpoint: telemetry.endpoint().map(|value| value.to_string()),
        machine_id_salt: telemetry.machine_id_salt.clone(),
        spool_dir,
        spool_max_bytes: DEFAULT_SPOOL_BYTES,
    };
    crash_reporting::install_global(reporter_config).ok()
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
