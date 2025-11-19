use std::process::ExitCode;

use clap::Parser;
use rpp_node::{PruningCliOverrides, RuntimeMode, RuntimeOptions};
use rpp_wallet::cli::wallet::{InitContext, WalletCliError, WalletCommand};
use rpp_wallet::crash_reporting::{
    self, CrashReporterConfig, CrashReporterHandle, DEFAULT_SPOOL_BYTES,
};
use rpp_wallet::runtime::config::WalletConfigExt;
use rpp_wallet_interface::runtime_config::WalletConfig as RuntimeWalletConfig;
use std::path::{Path, PathBuf};

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
    let mode = resolve_runtime_mode(&cli.options);
    let wallet_config_path = resolve_wallet_config_path(&cli.options, mode);
    let _crash_handle = configure_crash_reporting(wallet_config_path.as_ref());
    if let Some(command) = cli.command {
        let context = InitContext::new(wallet_config_path, cli.options.data_dir.clone());
        match command.execute(&context).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                report_cli_error(&err);
                ExitCode::FAILURE
            }
        }
    } else {
        let mut options = cli.options;
        options.wallet_config = options.wallet_config.or(wallet_config_path);
        match rpp_node::run(mode, options).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{err}");
                ExitCode::from(err.exit_code() as u8)
            }
        }
    }
}

fn configure_crash_reporting(config_path: Option<&PathBuf>) -> Option<CrashReporterHandle> {
    let config_path = config_path?;
    let runtime_config = RuntimeWalletConfig::load(config_path).unwrap_or_default();
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

fn resolve_runtime_mode(options: &RuntimeOptions) -> RuntimeMode {
    if options.with_node {
        return RuntimeMode::Hybrid;
    }

    if wallet_config_requests_hybrid(options) {
        RuntimeMode::Hybrid
    } else {
        RuntimeMode::Wallet
    }
}

fn wallet_config_requests_hybrid(options: &RuntimeOptions) -> bool {
    let Some(path) = resolve_wallet_config_path(options, RuntimeMode::Hybrid) else {
        return false;
    };
    RuntimeWalletConfig::load(&path)
        .map(|config| config.wallet.hybrid.enabled)
        .unwrap_or_default()
}

fn resolve_wallet_config_path(options: &RuntimeOptions, mode: RuntimeMode) -> Option<PathBuf> {
    if let Some(path) = options.wallet_config.clone() {
        return Some(path);
    }

    if mode == RuntimeMode::Hybrid {
        if let Some(path) = options.hybrid_config.clone() {
            return Some(path);
        }
        if let Some(path) = options.config.clone() {
            return Some(path);
        }

        if let Some(default) = RuntimeMode::Hybrid.default_wallet_config_path() {
            return Some(PathBuf::from(default));
        }

        if let Some(default) = RuntimeMode::Hybrid.default_node_config_path() {
            return Some(PathBuf::from(default));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_mode_respects_flag() {
        let mut options = base_runtime_options();
        options.with_node = true;

        assert_eq!(RuntimeMode::Hybrid, resolve_runtime_mode(&options));
    }

    #[test]
    fn runtime_mode_detects_hybrid_config() {
        let mut options = base_runtime_options();
        options.wallet_config = Some(repo_root().join("config/hybrid.toml"));

        assert_eq!(RuntimeMode::Hybrid, resolve_runtime_mode(&options));
    }

    #[test]
    fn wallet_config_path_prefers_hybrid_overrides() {
        let mut options = base_runtime_options();
        let hybrid_path = PathBuf::from("custom/hybrid.toml");
        options.hybrid_config = Some(hybrid_path.clone());

        assert_eq!(
            Some(hybrid_path),
            resolve_wallet_config_path(&options, RuntimeMode::Hybrid)
        );
    }

    fn base_runtime_options() -> RuntimeOptions {
        RuntimeOptions {
            config: None,
            hybrid_config: None,
            wallet_config: None,
            data_dir: None,
            rpc_listen: None,
            rpc_auth_token: None,
            rpc_allowed_origin: None,
            telemetry_endpoint: None,
            telemetry_auth_token: None,
            telemetry_sample_interval: None,
            log_level: None,
            log_json: false,
            dry_run: false,
            write_config: false,
            storage_ring_size: None,
            pruning: PruningCliOverrides::default(),
            with_node: false,
        }
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("workspace root")
            .to_path_buf()
    }
}
