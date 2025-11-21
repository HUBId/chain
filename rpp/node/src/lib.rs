mod feature_guard;
mod pipeline;
mod services;
mod state_sync;
mod telemetry;

pub use rpp_node_runtime_api::{
    BootstrapError, BootstrapErrorKind, BootstrapOptions, BootstrapResult, PruningCliOverrides,
    PruningOverrides, RuntimeMode, RuntimeOptions,
};

pub mod config {
    pub use rpp_node_runtime_api::{PruningCliOverrides, PruningOverrides};
}

use std::convert::Infallible;
use std::env;
use std::fmt;
use std::fs;
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::global;
use opentelemetry::KeyValue;
#[cfg(test)]
use opentelemetry::Value;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{self, BatchConfig, Tracer};
use opentelemetry_sdk::Resource;
use parking_lot::RwLock;
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tracing::field::{Field, Visit};
use tracing::{error, info, info_span, warn, Event, Subscriber};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

use rpp_chain::api::{ApiContext, PruningServiceApi};
use rpp_chain::config::{
    NodeConfig, ReleaseChannel, SecretsBackendConfig, TelemetryConfig, VrfTelemetryThresholds,
    WalletCapabilityHints, WalletConfig, WalletConfigExt, WormExportTargetConfig,
};
use rpp_chain::crypto::{
    generate_vrf_keypair, load_or_generate_keypair, vrf_public_key_to_hex, VrfKeyIdentifier,
};
use rpp_chain::errors::ChainError;
use rpp_chain::node::{Node, NodeHandle, PruningJobStatus};
use rpp_chain::orchestration::PipelineOrchestrator;
use rpp_chain::runtime::{
    init_runtime_metrics, RuntimeMetrics, RuntimeMetricsGuard, TelemetryExporterBuilder,
};
use rpp_chain::storage::Storage;
use rpp_chain::wallet::Wallet;
use storage::{
    detect_io_uring_capability, FileBacked, IoUringCapability, IO_URING_FORCE_UNSUPPORTED_ENV,
};

use crate::pipeline::PipelineHookGuard;
use crate::services::admission_reconciler::{AdmissionReconciler, AdmissionReconcilerSettings};
use crate::services::pruning::PruningService;
use crate::services::snapshot_validator::SnapshotValidator;
use crate::services::uptime::{cadence_from_config, UptimeScheduler};

pub use rpp_chain_cli::{run_cli, CliError, CliResult};
pub use rpp_chain_cli::{
    validator_setup, ValidatorSetupError, ValidatorSetupOptions, ValidatorSetupReport,
    ValidatorSetupTelemetryReport,
};
pub use state_sync::light_client::{
    LightClientVerificationEvent, LightClientVerifier, StateSyncVerificationReport,
    StateSyncVerificationSummary, VerificationError, VerificationErrorKind, VerifiedChunkRange,
};

const WORM_EXPORT_MISCONFIGURED_METRIC: &str = "worm_export_misconfigured_total";
const TELEMETRY_FAILURE_METRIC: &str = "telemetry_otlp_failures_total";

fn record_otlp_failure(sink: &'static str, phase: &'static str) {
    metrics::counter!(TELEMETRY_FAILURE_METRIC, "sink" => sink, "phase" => phase).increment(1);
}

pub fn ensure_prover_backend(mode: RuntimeMode) -> BootstrapResult<()> {
    if matches!(mode, RuntimeMode::Validator | RuntimeMode::Hybrid)
        && cfg!(not(feature = "prover-stwo"))
    {
        let mode_name = mode.as_str();
        return Err(BootstrapError::configuration(anyhow!(
            "the {mode_name} runtime requires the `prover-stwo` feature. rebuild with `cargo build -p rpp-node --release --no-default-features --features prover-stwo` (or replace `prover-stwo` with `prover-stwo-simd` if SIMD acceleration is desired)."
        )));
    }

    Ok(())
}

fn ensure_worm_export_configured(mode: RuntimeMode, config: &NodeConfig) -> BootstrapResult<()> {
    if !mode.includes_node() {
        return Ok(());
    }

    let release_channel = config.rollout.release_channel;
    let production_channel = matches!(
        release_channel,
        ReleaseChannel::Canary | ReleaseChannel::Mainnet
    );

    if !production_channel {
        return Ok(());
    }

    let worm = &config.network.admission.worm_export;
    let mut missing = Vec::new();

    if !worm.enabled {
        missing.push("network.admission.worm_export.enabled".to_string());
    }

    if worm.retention_days == 0 {
        missing.push("network.admission.worm_export.retention_days".to_string());
    }

    match worm.target.as_ref() {
        Some(WormExportTargetConfig::S3 {
            endpoint,
            access_key,
            secret_key,
            ..
        }) => {
            if endpoint
                .as_ref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                missing.push("network.admission.worm_export.target.endpoint".to_string());
            }
            if access_key.trim().is_empty() {
                missing.push("network.admission.worm_export.target.access_key".to_string());
            }
            if secret_key.trim().is_empty() {
                missing.push("network.admission.worm_export.target.secret_key".to_string());
            }
        }
        Some(WormExportTargetConfig::Command { .. }) => {
            missing.push(
                "network.admission.worm_export.target (s3 required for production)".to_string(),
            );
        }
        None => {
            missing.push("network.admission.worm_export.target".to_string());
        }
    }

    if missing.is_empty() {
        return Ok(());
    }

    let missing_display = missing.join(", ");

    metrics::counter!(
        WORM_EXPORT_MISCONFIGURED_METRIC,
        "release_channel" => format!("{release_channel:?}")
    )
    .increment(1);

    error!(
        target = "bootstrap",
        mode = mode.as_str(),
        release_channel = ?release_channel,
        missing = %missing_display,
        "production release requires configured WORM export endpoint, credentials, and retention"
    );

    Err(BootstrapError::configuration(anyhow!(
        "production release channel {:?} requires configuring network.admission.worm_export (missing: {missing_display})",
        release_channel
    )))
}

pub async fn run(mode: RuntimeMode, mut options: RuntimeOptions) -> BootstrapResult<()> {
    ensure_prover_backend(mode)?;

    let bootstrap_mode = mode;
    let dry_run = options.dry_run;
    let bootstrap_options = options.into_bootstrap_options(mode);

    if dry_run {
        bootstrap(bootstrap_mode, bootstrap_options).await
    } else {
        let handle =
            tokio::spawn(async move { bootstrap(bootstrap_mode, bootstrap_options).await });

        match handle.await {
            Ok(result) => result,
            Err(join_err) => {
                if join_err.is_panic() {
                    let message = panic_payload_to_string(join_err.into_panic());
                    Err(BootstrapError::runtime(anyhow!(
                        "runtime panicked: {message}"
                    )))
                } else {
                    Err(BootstrapError::runtime(anyhow!(
                        "runtime task failed: {join_err}"
                    )))
                }
            }
        }
    }
}

pub async fn bootstrap(mode: RuntimeMode, options: BootstrapOptions) -> BootstrapResult<()> {
    if !options.dry_run {
        if let Ok(request) = env::var("RPP_NODE_TEST_FAILURE_MODE") {
            match request.as_str() {
                "startup" => {
                    return Err(BootstrapError::startup(anyhow!(
                        "simulated pipeline startup failure"
                    )));
                }
                "panic" => {
                    panic!("simulated panic requested via RPP_NODE_TEST_FAILURE_MODE");
                }
                _ => {}
            }
        }
    }

    let mut node_bundle =
        load_node_configuration(mode, &options).map_err(BootstrapError::configuration)?;
    if let Some(bundle) = node_bundle.as_mut() {
        apply_overrides(&mut bundle.value, &options);
    }
    if let Some(bundle) = node_bundle.as_ref() {
        bundle
            .value
            .validate()
            .map_err(BootstrapError::configuration)?;
    }
    if let Some(bundle) = node_bundle.as_ref() {
        ensure_worm_export_configured(mode, &bundle.value)?;
    }
    let mut wallet_bundle =
        load_wallet_configuration(mode, &options).map_err(BootstrapError::configuration)?;

    if let Some(bundle) = wallet_bundle.as_mut() {
        if let Some(origin) = options.rpc_allowed_origin.as_ref() {
            let origin = origin.trim();
            if origin.is_empty() {
                bundle.value.wallet.rpc.allowed_origin = None;
            } else {
                bundle.value.wallet.rpc.allowed_origin = Some(origin.to_string());
            }
        }
    }

    ensure_listener_conflicts(mode, node_bundle.as_ref(), wallet_bundle.as_ref())
        .map_err(BootstrapError::configuration)?;

    if let Some(bundle) = wallet_bundle.as_ref() {
        bundle
            .value
            .validate_for_mode(mode, node_bundle.as_ref().map(|bundle| &bundle.value))
            .map_err(BootstrapError::configuration)?;
    }

    ensure_capabilities_supported(node_bundle.as_ref(), wallet_bundle.as_ref())?;

    let node_metadata = node_bundle
        .as_ref()
        .and_then(|bundle| bundle.metadata.as_ref().cloned());
    let wallet_metadata = wallet_bundle
        .as_ref()
        .and_then(|bundle| bundle.metadata.as_ref().cloned());
    let storage_ring_size = node_bundle
        .as_ref()
        .map(|bundle| u64::from(bundle.value.storage.ring_size));

    let mut default_config = None;
    let tracing_config = if let Some(bundle) = node_bundle.as_ref() {
        &bundle.value
    } else {
        default_config = Some(NodeConfig::default());
        default_config.as_ref().unwrap()
    };

    let config_source = node_metadata
        .as_ref()
        .map(|metadata| metadata.source.as_str())
        .unwrap_or_else(|| {
            if mode.includes_node() {
                ConfigSource::Default.as_str()
            } else {
                "none"
            }
        });

    tracing_config
        .rollout
        .telemetry
        .validate()
        .map_err(BootstrapError::configuration)?;

    let telemetry = init_tracing(
        tracing_config,
        node_metadata.as_ref(),
        options.log_level.clone(),
        options.log_json,
        mode,
        config_source,
        options.dry_run,
    )
    .with_context(|| "failed to initialise logging")
    .map_err(BootstrapError::startup)?;

    let runtime_metrics = telemetry
        .as_ref()
        .map(|handles| Arc::clone(&handles.runtime_metrics))
        .unwrap_or_else(RuntimeMetrics::noop);
    let _telemetry_guard = telemetry.map(|handles| handles.guard);

    if mode.includes_node() {
        ensure_io_uring_support(tracing_config.storage.ring_size)?;
    }

    info!(
        target = "bootstrap",
        mode = mode.as_str(),
        config_source = config_source,
        dry_run = options.dry_run,
        storage_io_uring_ring_entries = tracing_config.storage.ring_size,
        "bootstrap configuration resolved"
    );

    if let Some(metadata) = node_metadata.as_ref() {
        info!(
            target = "config",
            role = "node",
            source = metadata.source.as_str(),
            path = %metadata.path.display(),
            "resolved node configuration"
        );
    }
    if let Some(metadata) = wallet_metadata.as_ref() {
        info!(
            target = "config",
            role = "wallet",
            source = metadata.source.as_str(),
            path = %metadata.path.display(),
            "resolved wallet configuration"
        );
    }
    if let Some(bundle) = wallet_bundle.as_ref() {
        let rpc = &bundle.value.wallet.rpc;
        let auth = &bundle.value.wallet.auth;
        let budgets = &bundle.value.wallet.budgets;
        let rescan = &bundle.value.wallet.rescan;
        info!(
            target = "config",
            role = "wallet",
            listen = %rpc.listen,
            auth_enabled = auth.enabled,
            allowed_origin = rpc.allowed_origin.as_deref(),
            rpc_requests_per_minute = rpc.requests_per_minute,
            submit_budget_per_minute = budgets.submit_transaction_per_minute,
            proof_budget_per_minute = budgets.proof_generation_per_minute,
            pipeline_depth = budgets.pipeline_depth,
            rescan_auto_trigger = rescan.auto_trigger,
            rescan_chunk_size = rescan.chunk_size,
            rescan_lookback_blocks = rescan.lookback_blocks,
            "resolved wallet service parameters"
        );
    }

    if options.write_config {
        if let Some(bundle) = node_bundle.as_ref() {
            let override_path = node_metadata
                .as_ref()
                .map(|metadata| metadata.path.as_path());
            persist_node_config(mode, &bundle.value, override_path)
                .map_err(BootstrapError::configuration)?;
        }
    }

    if options.dry_run {
        macro_rules! log_dry_run {
            ($ring:expr) => {
                info!(
                    mode = %mode.as_str(),
                    node_config = node_metadata
                        .as_ref()
                        .map(|metadata| metadata.path.display().to_string()),
                    node_config_source = node_metadata
                        .as_ref()
                        .map(|metadata| metadata.source.as_str()),
                    wallet_config = wallet_metadata
                        .as_ref()
                        .map(|metadata| metadata.path.display().to_string()),
                    wallet_config_source = wallet_metadata
                        .as_ref()
                        .map(|metadata| metadata.source.as_str()),
                    storage_io_uring_ring_entries = $ring,
                    "dry run completed"
                );
            };
        }
        match storage_ring_size {
            Some(ring) => log_dry_run!(ring),
            None => log_dry_run!(tracing::field::Empty),
        }
        return Ok(());
    }

    let runtime_mode = Arc::new(RwLock::new(mode));
    let mut node_handle: Option<NodeHandle> = None;
    let mut node_runtime: Option<JoinHandle<()>> = None;
    let mut pruning_service: Option<PruningService> = None;
    let mut admission_reconciler: Option<AdmissionReconciler> = None;
    let mut uptime_service: Option<UptimeScheduler> = None;
    let mut snapshot_validator: Option<SnapshotValidator> = None;
    let mut pruning_api: Option<Arc<dyn PruningServiceApi>> = None;
    let mut pruning_status_stream: Option<watch::Receiver<Option<PruningJobStatus>>> = None;
    let mut rpc_auth: Option<String> = None;
    let mut rpc_auth_required = false;
    let mut rpc_origin: Option<String> = None;
    let mut rpc_requests_per_minute: Option<NonZeroU64> = None;
    let mut orchestrator_instance: Option<Arc<PipelineOrchestrator>> = None;
    let mut uptime_cadence: Option<Duration> = None;
    let mut vrf_thresholds: Option<VrfTelemetryThresholds> = None;

    let node_rpc_addr = node_bundle
        .as_ref()
        .map(|bundle| bundle.value.network.rpc.listen);
    let wallet_rpc_addr = wallet_bundle
        .as_ref()
        .map(|bundle| bundle.value.wallet.rpc.listen);

    if let Some(bundle) = node_bundle.take() {
        let config = bundle.value;
        let preview_node = Node::new(config.clone(), Arc::clone(&runtime_metrics))
            .context("failed to build node with the provided configuration")
            .map_err(BootstrapError::startup)?;
        info!(
            address = %preview_node.handle().address(),
            "node initialised"
        );
        drop(preview_node);

        let (handle, runtime) = NodeHandle::start(config.clone(), Arc::clone(&runtime_metrics))
            .await
            .context("failed to start node runtime")
            .map_err(BootstrapError::startup)?;

        info!(address = %handle.address(), "node runtime started");

        let service = PruningService::start(handle.clone(), &config);
        let status_rx = service.subscribe_status();
        let api_handle = service.handle();
        pruning_status_stream = Some(status_rx);
        pruning_api = Some(Arc::new(api_handle) as Arc<dyn PruningServiceApi>);
        pruning_service = Some(service);

        let reconciler_settings = AdmissionReconcilerSettings::from_config(&config);
        let reconciler = AdmissionReconciler::start(
            handle.clone(),
            config.network.admission.policy_path.clone(),
            reconciler_settings,
        );
        admission_reconciler = Some(reconciler);

        let validator = SnapshotValidator::start(&config);
        snapshot_validator = Some(validator);

        info!(
            target = "rpc",
            listen = %config.network.rpc.listen,
            "rpc endpoint configured"
        );
        if config.rollout.telemetry.enabled {
            let http_endpoint = config
                .rollout
                .telemetry
                .http_endpoint
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if let Some(endpoint) = config
                .rollout
                .telemetry
                .endpoint
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                info!(
                    target = "telemetry",
                    otlp_endpoint = %endpoint,
                    http_endpoint,
                    sample_interval_secs = config.rollout.telemetry.sample_interval_secs,
                    "telemetry endpoints configured"
                );
            } else {
                info!(
                    target = "telemetry",
                    http_endpoint,
                    sample_interval_secs = config.rollout.telemetry.sample_interval_secs,
                    "telemetry enabled without explicit endpoint"
                );
            }
        } else {
            info!(target = "telemetry", "telemetry disabled");
        }
        info!(
            target = "p2p",
            listen_addr = %config.network.p2p.listen_addr,
            "p2p endpoint configured"
        );
        rpc_auth = config.network.rpc.auth_token.clone();
        rpc_auth_required = config.network.rpc.require_auth;
        rpc_origin = config.network.rpc.allowed_origin.clone();
        if config.network.limits.per_ip_token_bucket.enabled {
            rpc_requests_per_minute = NonZeroU64::new(
                config
                    .network
                    .limits
                    .per_ip_token_bucket
                    .replenish_per_minute,
            );
        }

        let p2p_handle = handle.p2p_handle();
        let (orchestrator, shutdown_rx) = PipelineOrchestrator::new(handle.clone(), p2p_handle);
        let orchestrator = Arc::new(orchestrator);
        orchestrator.spawn(shutdown_rx);
        info!("pipeline orchestrator started");
        _pipeline_hooks = Some(pipeline::install_hooks(Arc::clone(&orchestrator)));
        orchestrator_instance = Some(orchestrator.clone());

        uptime_cadence = Some(cadence_from_config(&config));
        vrf_thresholds = Some(config.rollout.telemetry.vrf_thresholds.clone());
        node_handle = Some(handle);
        node_runtime = Some(runtime);
    }

    let mut wallet_instance: Option<Arc<Wallet>> = None;
    let mut _pipeline_hooks: Option<PipelineHookGuard> = None;
    if let Some(bundle) = wallet_bundle {
        let wallet_config = bundle.value;
        wallet_config
            .ensure_directories()
            .map_err(|err| BootstrapError::startup(anyhow!(err)))?;

        let storage = if let Some(handle) = node_handle.as_ref() {
            handle.storage()
        } else {
            Storage::open(&wallet_config.data_dir.join("db"))
                .map_err(|err| BootstrapError::startup(anyhow!(err)))?
        };
        let keypair = load_or_generate_keypair(&wallet_config.wallet.keys.key_path)
            .map_err(|err| BootstrapError::startup(anyhow!(err)))?;
        let wallet = Arc::new(Wallet::new(storage, keypair, Arc::clone(&runtime_metrics)));
        wallet_instance = Some(wallet);

        if uptime_service.is_none() {
            if let (Some(handle), Some(cadence), Some(wallet_arc)) = (
                node_handle.as_ref(),
                uptime_cadence,
                wallet_instance.as_ref(),
            ) {
                let thresholds = vrf_thresholds.clone().unwrap_or_default();
                let scheduler = UptimeScheduler::start(
                    handle.clone(),
                    Arc::clone(wallet_arc),
                    cadence,
                    thresholds,
                );
                uptime_service = Some(scheduler);
            }
        }

        if rpc_auth.is_none() && wallet_config.wallet.auth.enabled {
            rpc_auth = wallet_config.wallet.auth.token.clone();
        }
        if wallet_config.wallet.auth.enabled {
            rpc_auth_required = true;
        }
        if rpc_origin.is_none() {
            rpc_origin = wallet_config.wallet.rpc.allowed_origin.clone();
        }
        if rpc_requests_per_minute.is_none() {
            rpc_requests_per_minute = wallet_config
                .wallet
                .rpc
                .requests_per_minute
                .and_then(NonZeroU64::new);
        }
    }

    if let Some(wallet) = &wallet_instance {
        info!(address = %wallet.address(), "wallet runtime initialised");
    }

    let wallet_runtime_active = wallet_instance.is_some();
    let mut server_tasks: JoinSet<(PipelineRole, Result<(), anyhow::Error>)> = JoinSet::new();
    let mut active_pipelines: Vec<PipelineHandle> = Vec::new();

    if let Some(addr) = node_rpc_addr {
        let role = PipelineRole::Node;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let context = ApiContext::new(
            Arc::clone(&runtime_mode),
            node_handle.clone(),
            wallet_instance.clone(),
            orchestrator_instance.clone(),
            rpc_requests_per_minute,
            rpc_auth_required || rpc_auth.is_some(),
            pruning_status_stream.clone(),
            pruning_api.clone(),
            false,
        );
        let auth_token = rpc_auth.clone();
        let allowed_origin = rpc_origin.clone();
        let limits = config.network.limits.clone();
        let tls = config.network.tls.clone();

        server_tasks.spawn(async move {
            let shutdown = async move {
                let _ = shutdown_rx.await;
            };
            let result = rpp_chain::api::serve_with_shutdown(
                context,
                addr,
                auth_token,
                allowed_origin,
                limits,
                tls,
                shutdown,
                Some(ready_tx),
            )
            .await
            .map_err(|err| anyhow!(err));
            (role, result)
        });

        match ready_rx.await {
            Ok(Ok(())) => {
                info!(
                    target = "pipeline",
                    pipeline = role.as_str(),
                    listen = %addr,
                    "pipeline=\"{}\" started",
                    role.as_str()
                );
            }
            Ok(Err(err)) => {
                return Err(BootstrapError::startup(anyhow!(err)));
            }
            Err(err) => {
                return Err(BootstrapError::startup(anyhow!(err)));
            }
        }

        active_pipelines.push(PipelineHandle {
            shutdown: Some(shutdown_tx),
        });
    }

    if let (Some(wallet_addr), Some(wallet)) = (wallet_rpc_addr, wallet_instance.as_ref()) {
        let role = PipelineRole::Wallet;
        info!(target = "rpc", listen = %wallet_addr, "wallet rpc endpoint configured");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let context = ApiContext::new(
            Arc::clone(&runtime_mode),
            node_handle.clone(),
            Some(Arc::clone(wallet)),
            orchestrator_instance.clone(),
            rpc_requests_per_minute,
            rpc_auth_required || rpc_auth.is_some(),
            pruning_status_stream.clone(),
            pruning_api.clone(),
            wallet_runtime_active,
        );
        let auth_token = rpc_auth.clone();
        let allowed_origin = rpc_origin.clone();
        let limits = config.network.limits.clone();
        let tls = config.network.tls.clone();

        server_tasks.spawn(async move {
            let shutdown = async move {
                let _ = shutdown_rx.await;
            };
            let result = rpp_chain::api::serve_with_shutdown(
                context,
                wallet_addr,
                auth_token,
                allowed_origin,
                limits,
                tls,
                shutdown,
                Some(ready_tx),
            )
            .await
            .map_err(|err| anyhow!(err));
            (role, result)
        });

        match ready_rx.await {
            Ok(Ok(())) => {
                info!(
                    target = "pipeline",
                    pipeline = role.as_str(),
                    listen = %wallet_addr,
                    "pipeline=\"{}\" started",
                    role.as_str()
                );
            }
            Ok(Err(err)) => {
                return Err(BootstrapError::startup(anyhow!(err)));
            }
            Err(err) => {
                return Err(BootstrapError::startup(anyhow!(err)));
            }
        }

        active_pipelines.push(PipelineHandle {
            shutdown: Some(shutdown_tx),
        });
    }

    if active_pipelines.is_empty() {
        return Err(BootstrapError::configuration(anyhow!(
            "no runtime role selected"
        )));
    }

    let mut shutdown_future: Option<Pin<Box<dyn Future<Output = ShutdownOutcome> + Send>>> =
        match (node_handle.clone(), node_runtime) {
            (Some(handle), Some(runtime)) => Some(Box::pin(wait_for_node_shutdown(
                handle,
                runtime,
                pruning_service.take(),
                uptime_service.take(),
                admission_reconciler.take(),
                snapshot_validator.take(),
            )) as _),
            _ => Some(Box::pin(wait_for_signal_shutdown()) as _),
        };

    let mut shutdown_result: Option<ShutdownOutcome> = None;
    let mut pipeline_error: Option<anyhow::Error> = None;
    let mut shutting_down = false;

    loop {
        if shutting_down {
            break;
        }

        if let Some(fut) = shutdown_future.as_mut() {
            tokio::select! {
                biased;
                result = server_tasks.join_next(), if !server_tasks.is_empty() => {
                    if let Some(task) = result {
                        match task {
                            Ok((role, Ok(()))) => {
                                if !shutting_down {
                                    pipeline_error = Some(anyhow!(
                                        "{} pipeline terminated unexpectedly",
                                        role.as_str()
                                    ));
                                    shutting_down = true;
                                }
                            }
                            Ok((_, Err(err))) => {
                                pipeline_error = Some(err);
                                shutting_down = true;
                            }
                            Err(err) => {
                                pipeline_error = Some(anyhow!(err));
                                shutting_down = true;
                            }
                        }
                    }
                }
                outcome = fut => {
                    shutdown_result = Some(outcome);
                    shutting_down = true;
                    shutdown_future = None;
                }
            }
        } else if !server_tasks.is_empty() {
            if let Some(task) = server_tasks.join_next().await {
                match task {
                    Ok((role, Ok(()))) => {
                        if !shutting_down {
                            pipeline_error = Some(anyhow!(
                                "{} pipeline terminated unexpectedly",
                                role.as_str()
                            ));
                            shutting_down = true;
                        }
                    }
                    Ok((_, Err(err))) => {
                        pipeline_error = Some(err);
                        shutting_down = true;
                    }
                    Err(err) => {
                        pipeline_error = Some(anyhow!(err));
                        shutting_down = true;
                    }
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    for handle in &mut active_pipelines {
        if let Some(tx) = handle.shutdown.take() {
            let _ = tx.send(());
        }
    }

    while let Some(task) = server_tasks.join_next().await {
        match task {
            Ok((_, Ok(()))) => {}
            Ok((_, Err(err))) => {
                if pipeline_error.is_none() {
                    pipeline_error = Some(err);
                }
            }
            Err(err) => {
                if pipeline_error.is_none() {
                    pipeline_error = Some(anyhow!(err));
                }
            }
        }
    }

    if let Some(err) = pipeline_error {
        return Err(BootstrapError::runtime(err));
    }

    let outcome = shutdown_result.unwrap_or(ShutdownOutcome::Clean);

    match outcome {
        ShutdownOutcome::Clean => Ok(()),
        ShutdownOutcome::Errored(err) => Err(BootstrapError::runtime(err)),
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send + 'static>) -> String {
    if let Ok(message) = payload.downcast::<String>() {
        *message
    } else if let Ok(message) = payload.downcast::<&'static str>() {
        (*message).to_string()
    } else {
        "unknown panic".to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigSource {
    CommandLine,
    Environment,
    Default,
}

impl ConfigSource {
    fn as_str(&self) -> &'static str {
        match self {
            ConfigSource::CommandLine => "cli",
            ConfigSource::Environment => "env",
            ConfigSource::Default => "default",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            ConfigSource::CommandLine => "the command line",
            ConfigSource::Environment => "the RPP_CONFIG environment variable",
            ConfigSource::Default => "the default search path",
        }
    }
}

#[derive(Clone)]
struct ConfigMetadata {
    path: PathBuf,
    source: ConfigSource,
}

impl ConfigMetadata {
    fn new(path: PathBuf, source: ConfigSource) -> Self {
        Self { path, source }
    }
}

#[derive(Clone)]
struct ResolvedConfigPath {
    path: PathBuf,
    source: ConfigSource,
}

impl ResolvedConfigPath {
    fn into_metadata(self) -> ConfigMetadata {
        ConfigMetadata::new(self.path, self.source)
    }
}

#[derive(Clone, Copy, Debug)]
enum ConfigRole {
    Node,
    Wallet,
}

impl ConfigRole {
    fn as_str(&self) -> &'static str {
        match self {
            ConfigRole::Node => "node",
            ConfigRole::Wallet => "wallet",
        }
    }
}

#[derive(Debug)]
pub enum ConfigurationError {
    Missing {
        role: ConfigRole,
        path: PathBuf,
        source: ConfigSource,
        suggestion: Option<String>,
    },
    Conflict {
        message: String,
    },
}

impl ConfigurationError {
    fn missing(
        role: ConfigRole,
        path: PathBuf,
        source: ConfigSource,
        template: Option<&'static str>,
    ) -> Self {
        let suggestion = template.map(|default| format!("cp {default} {}", path.display()));
        Self::Missing {
            role,
            path,
            source,
            suggestion,
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing {
                role,
                path,
                source,
                suggestion,
            } => {
                let base = format!(
                    "{} configuration not found at {} (resolved from {})",
                    role.as_str(),
                    path.display(),
                    source.description()
                );

                if let Some(suggestion) = suggestion {
                    write!(
                        f,
                        "{}; copy the default template with `{}`",
                        base, suggestion
                    )
                } else {
                    write!(f, "{}", base)
                }
            }
            Self::Conflict { message } => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for ConfigurationError {}

#[derive(Clone)]
struct ConfigBundle<T> {
    value: T,
    metadata: Option<ConfigMetadata>,
    capabilities: CapabilityHints,
}

#[derive(Clone, Default)]
struct CapabilityHints {
    wallet: Option<WalletCapabilityHints>,
}

impl CapabilityHints {
    fn for_wallet(hints: WalletCapabilityHints) -> Self {
        Self {
            wallet: Some(hints),
        }
    }

    fn wallet(&self) -> Option<&WalletCapabilityHints> {
        self.wallet.as_ref()
    }
}

fn ensure_listener_conflicts(
    mode: RuntimeMode,
    node_bundle: Option<&ConfigBundle<NodeConfig>>,
    wallet_bundle: Option<&ConfigBundle<WalletConfig>>,
) -> Result<()> {
    if !(mode.includes_node() && mode.includes_wallet()) {
        return Ok(());
    }

    let Some(node_bundle) = node_bundle else {
        return Ok(());
    };
    let Some(wallet_bundle) = wallet_bundle else {
        return Ok(());
    };

    let node_metadata = node_bundle.metadata.as_ref();
    let wallet_metadata = wallet_bundle.metadata.as_ref();
    let mut conflicts = Vec::new();

    let node_rpc = node_bundle.value.network.rpc.listen;
    let wallet_rpc = wallet_bundle.value.wallet.rpc.listen;
    if node_rpc.port() != 0
        && wallet_rpc.port() != 0
        && node_rpc.port() == wallet_rpc.port()
        && (node_rpc.ip() == wallet_rpc.ip()
            || node_rpc.ip().is_unspecified()
            || wallet_rpc.ip().is_unspecified())
    {
        let node_key = describe_config_key(ConfigRole::Node, node_metadata, "network.rpc.listen");
        let wallet_key =
            describe_config_key(ConfigRole::Wallet, wallet_metadata, "wallet.rpc.listen");
        conflicts.push(format!(
            "{wallet_key} ({wallet_rpc}) conflicts with {node_key} ({node_rpc}); update the configuration to use distinct addresses"
        ));
    }

    if let Some(port) = extract_tcp_port(&node_bundle.value.network.p2p.listen_addr) {
        if port != 0 && port == wallet_rpc.port() {
            let node_key =
                describe_config_key(ConfigRole::Node, node_metadata, "network.p2p.listen_addr");
            let wallet_key =
                describe_config_key(ConfigRole::Wallet, wallet_metadata, "wallet.rpc.listen");
            conflicts.push(format!(
                "{wallet_key} ({wallet_rpc}) reuses TCP port {port}, which is already reserved by {node_key} ({})",
                node_bundle.value.network.p2p.listen_addr
            ));
        }
    }

    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(
            ConfigurationError::conflict(format!("listener conflict: {}", conflicts.join("; ")))
                .into(),
        )
    }
}

fn describe_config_key(role: ConfigRole, metadata: Option<&ConfigMetadata>, key: &str) -> String {
    match metadata {
        Some(metadata) => format!(
            "{} configuration ({}::{key})",
            role.as_str(),
            metadata.path.display()
        ),
        None => format!("{} configuration (defaults::{key})", role.as_str()),
    }
}

fn extract_tcp_port(multiaddr: &str) -> Option<u16> {
    let mut parts = multiaddr.split('/').filter(|segment| !segment.is_empty());
    while let Some(protocol) = parts.next() {
        let value = parts.next();
        if protocol.eq_ignore_ascii_case("tcp") {
            if let Some(port) = value {
                if let Ok(port) = port.parse::<u16>() {
                    return Some(port);
                }
            }
        }
    }
    None
}

#[derive(Debug)]
enum ShutdownEvent {
    Runtime(std::result::Result<(), JoinError>),
    CtrlC(std::io::Result<()>),
    #[cfg(unix)]
    SigTerm(Option<i32>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PipelineRole {
    Node,
    Wallet,
}

impl PipelineRole {
    fn as_str(&self) -> &'static str {
        match self {
            PipelineRole::Node => "node",
            PipelineRole::Wallet => "wallet",
        }
    }
}

struct PipelineHandle {
    shutdown: Option<oneshot::Sender<()>>,
}

#[derive(Debug)]
enum ShutdownOutcome {
    Clean,
    Errored(anyhow::Error),
}

async fn wait_for_node_shutdown(
    handle: NodeHandle,
    mut runtime: JoinHandle<()>,
    pruning: Option<PruningService>,
    mut uptime: Option<UptimeScheduler>,
    admission_reconciler: Option<AdmissionReconciler>,
    snapshot_validator: Option<SnapshotValidator>,
) -> ShutdownOutcome {
    tokio::pin!(runtime);

    let shutdown_event = {
        #[cfg(unix)]
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(err) => {
                    return ShutdownOutcome::Errored(err.into());
                }
            };

        tokio::select! {
            result = &mut runtime => ShutdownEvent::Runtime(result),
            result = tokio::signal::ctrl_c() => ShutdownEvent::CtrlC(result),
            #[cfg(unix)]
            result = sigterm.recv() => ShutdownEvent::SigTerm(result),
        }
    };

    let mut runtime_result: Option<std::result::Result<(), JoinError>> = None;

    match shutdown_event {
        ShutdownEvent::Runtime(result) => {
            runtime_result = Some(result);
            if let Err(err) = handle.stop().await {
                error!(?err, "failed to stop node runtime after completion");
                return ShutdownOutcome::Errored(err.into());
            }
        }
        ShutdownEvent::CtrlC(result) => {
            match result {
                Ok(()) => info!("received ctrl_c signal"),
                Err(err) => warn!(?err, "failed to listen for ctrl_c"),
            }
            if let Err(err) = handle.stop().await {
                error!(?err, "failed to stop node runtime");
                return ShutdownOutcome::Errored(err.into());
            }
            runtime_result = Some((&mut runtime).await);
        }
        #[cfg(unix)]
        ShutdownEvent::SigTerm(result) => {
            match result {
                Some(_) => info!("received termination signal"),
                None => warn!("termination signal stream closed"),
            }
            if let Err(err) = handle.stop().await {
                error!(?err, "failed to stop node runtime");
                return ShutdownOutcome::Errored(err.into());
            }
            runtime_result = Some((&mut runtime).await);
        }
    }

    if let Some(service) = &pruning {
        service.shutdown().await;
    }
    if let Some(service) = uptime.as_ref() {
        service.shutdown().await;
    }
    if let Some(service) = admission_reconciler.as_ref() {
        service.shutdown().await;
    }
    if let Some(service) = snapshot_validator.as_ref() {
        service.shutdown().await;
    }

    match runtime_result {
        Some(Ok(())) => {
            info!("node runtime exited cleanly");
            ShutdownOutcome::Clean
        }
        Some(Err(err)) => {
            let error = anyhow::Error::from(err);
            error!(?error, "node runtime join failed");
            ShutdownOutcome::Errored(error)
        }
        None => ShutdownOutcome::Clean,
    }
}

async fn wait_for_signal_shutdown() -> ShutdownOutcome {
    #[cfg(unix)]
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(signal) => signal,
        Err(err) => return ShutdownOutcome::Errored(err.into()),
    };

    let shutdown_event = tokio::select! {
        result = tokio::signal::ctrl_c() => ShutdownEvent::CtrlC(result),
        #[cfg(unix)]
        result = sigterm.recv() => ShutdownEvent::SigTerm(result),
    };

    match shutdown_event {
        ShutdownEvent::CtrlC(result) => match result {
            Ok(()) => info!("received ctrl_c signal"),
            Err(err) => warn!(?err, "failed to listen for ctrl_c"),
        },
        #[cfg(unix)]
        ShutdownEvent::SigTerm(result) => match result {
            Some(_) => info!("received termination signal"),
            None => warn!("termination signal stream closed"),
        },
        ShutdownEvent::Runtime(_) => {}
    }

    ShutdownOutcome::Clean
}

fn load_node_configuration(
    mode: RuntimeMode,
    options: &BootstrapOptions,
) -> Result<Option<ConfigBundle<NodeConfig>>> {
    if !mode.includes_node() {
        return Ok(None);
    }

    let Some(resolved) = resolve_node_config_path(mode, options) else {
        return Ok(None);
    };

    if !resolved.path.exists() {
        let error = ConfigurationError::missing(
            ConfigRole::Node,
            resolved.path.clone(),
            resolved.source,
            mode.default_node_config_path(),
        );
        return Err(error.into());
    }

    let display_path = resolved.path.display().to_string();
    let config = NodeConfig::load(&resolved.path)
        .with_context(|| format!("failed to load configuration from {display_path}"))?;

    Ok(Some(ConfigBundle {
        value: config,
        metadata: Some(resolved.into_metadata()),
        capabilities: CapabilityHints::default(),
    }))
}

fn load_wallet_configuration(
    mode: RuntimeMode,
    options: &BootstrapOptions,
) -> Result<Option<ConfigBundle<WalletConfig>>> {
    if !mode.includes_wallet() {
        return Ok(None);
    }

    let Some(resolved) = resolve_wallet_config_path(mode, options) else {
        return Ok(None);
    };

    if !resolved.path.exists() {
        let error = ConfigurationError::missing(
            ConfigRole::Wallet,
            resolved.path.clone(),
            resolved.source,
            mode.default_wallet_config_path(),
        );
        return Err(error.into());
    }

    let display_path = resolved.path.display().to_string();
    let (config, capabilities) = WalletConfig::load_with_capabilities(&resolved.path)
        .map_err(|err| anyhow!(err))
        .with_context(|| format!("failed to load configuration from {display_path}"))?;

    Ok(Some(ConfigBundle {
        value: config,
        metadata: Some(resolved.into_metadata()),
        capabilities: CapabilityHints::for_wallet(capabilities),
    }))
}

fn resolve_node_config_path(
    mode: RuntimeMode,
    options: &BootstrapOptions,
) -> Option<ResolvedConfigPath> {
    resolve_config_path(options.node_config.clone(), mode.default_node_config_path())
}

fn resolve_wallet_config_path(
    mode: RuntimeMode,
    options: &BootstrapOptions,
) -> Option<ResolvedConfigPath> {
    resolve_config_path(
        options.wallet_config.clone(),
        mode.default_wallet_config_path(),
    )
}

fn resolve_config_path(
    cli_path: Option<PathBuf>,
    default_path: Option<&'static str>,
) -> Option<ResolvedConfigPath> {
    let env_path = env_config_path();

    resolve_config_from_sources([
        cli_path.map(|path| (path, ConfigSource::CommandLine)),
        env_path.map(|path| (path, ConfigSource::Environment)),
        default_path.map(|path| (PathBuf::from(path), ConfigSource::Default)),
    ])
}

fn env_config_path() -> Option<PathBuf> {
    let raw = std::env::var("RPP_CONFIG").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn resolve_config_from_sources(
    sources: impl IntoIterator<Item = Option<(PathBuf, ConfigSource)>>,
) -> Option<ResolvedConfigPath> {
    for candidate in sources {
        if let Some((path, source)) = candidate {
            return Some(ResolvedConfigPath { path, source });
        }
    }

    None
}

fn apply_overrides(config: &mut NodeConfig, options: &BootstrapOptions) {
    if let Some(dir) = options.data_dir.as_ref() {
        config.data_dir = dir.clone();
    }
    if let Some(addr) = options.rpc_listen {
        config.network.rpc.listen = addr;
    }
    if let Some(token) = options.rpc_auth_token.as_ref() {
        let token = token.trim();
        if token.is_empty() {
            config.network.rpc.auth_token = None;
        } else {
            config.network.rpc.auth_token = Some(token.to_string());
        }
    }
    if let Some(origin) = options.rpc_allowed_origin.as_ref() {
        let origin = origin.trim();
        if origin.is_empty() {
            config.network.rpc.allowed_origin = None;
        } else {
            config.network.rpc.allowed_origin = Some(origin.to_string());
        }
    }
    if let Some(endpoint) = options.telemetry_endpoint.as_ref() {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            config.rollout.telemetry.endpoint = None;
            config.rollout.telemetry.enabled = false;
        } else {
            config.rollout.telemetry.endpoint = Some(endpoint.to_string());
            config.rollout.telemetry.enabled = true;
        }
    }
    if let Some(auth) = options.telemetry_auth_token.as_ref() {
        let token = auth.trim();
        if token.is_empty() {
            config.rollout.telemetry.auth_token = None;
        } else {
            config.rollout.telemetry.auth_token = Some(token.to_string());
        }
    }
    if let Some(interval) = options.telemetry_sample_interval {
        config.rollout.telemetry.sample_interval_secs = interval;
        if config.rollout.telemetry.endpoint.is_some() {
            config.rollout.telemetry.enabled = true;
        }
    }
    if let Some(ring_size) = options.storage_ring_size {
        config.storage.ring_size = ring_size;
    }
    if let Some(cadence) = options.pruning.cadence_secs {
        if cadence == 0 {
            warn!("ignoring pruning cadence override of zero seconds");
        } else {
            config.pruning.cadence_secs = cadence;
        }
    }
    if let Some(retention) = options.pruning.retention_depth {
        if retention == 0 {
            warn!("ignoring pruning retention override of zero");
        } else {
            config.pruning.retention_depth = retention;
        }
    }
    if let Some(paused) = options.pruning.emergency_pause {
        config.pruning.emergency_pause = paused;
    }
}

fn persist_node_config(
    mode: RuntimeMode,
    config: &NodeConfig,
    override_path: Option<&Path>,
) -> Result<()> {
    let path = if let Some(path) = override_path {
        path.to_path_buf()
    } else {
        PathBuf::from(format!("{}.toml", mode.as_str()))
    };

    let resolved = if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .context("failed to resolve current working directory")?
            .join(path)
    };

    config
        .save(&resolved)
        .with_context(|| format!("failed to persist configuration to {}", resolved.display()))?;
    info!(path = %resolved.display(), "persisted node configuration");
    Ok(())
}

fn ensure_capabilities_supported(
    node_bundle: Option<&ConfigBundle<NodeConfig>>,
    wallet_bundle: Option<&ConfigBundle<WalletConfig>>,
) -> BootstrapResult<()> {
    let mut errors = Vec::new();

    if let Some(bundle) = node_bundle {
        errors.extend(node_capability_errors(&bundle.value));
    }

    if let Some(bundle) = wallet_bundle {
        errors.extend(wallet_capability_errors(
            &bundle.value,
            bundle.capabilities.wallet(),
        ));
    }

    if errors.is_empty() {
        return Ok(());
    }

    let message = errors.join("; ");
    Err(BootstrapError::configuration(ChainError::Config(message)))
}

fn ensure_io_uring_support(ring_size: u32) -> BootstrapResult<()> {
    let entries = NonZeroU32::new(ring_size)
        .unwrap_or_else(|| NonZeroU32::new(FileBacked::DEFAULT_RING_ENTRIES).expect("non-zero"));
    let capability = detect_io_uring_capability(entries);
    handle_io_uring_capability(capability, ring_size)
}

fn handle_io_uring_capability(
    capability: IoUringCapability,
    ring_size: u32,
) -> BootstrapResult<()> {
    match capability {
        IoUringCapability::Supported => Ok(()),
        IoUringCapability::Disabled { reason } => {
            warn!(
                target = "storage",
                storage_io_uring_ring_entries = ring_size,
                %reason,
                "io-uring unavailable; using synchronous file I/O"
            );
            Ok(())
        }
        IoUringCapability::Unsupported { reason } => {
            warn!(
                target = "storage",
                storage_io_uring_ring_entries = ring_size,
                %reason,
                "io-uring is enabled but unsupported on this kernel"
            );
            Err(BootstrapError::startup(ChainError::Config(format!(
                "io-uring support requested but unavailable: {reason}"
            ))))
        }
    }
}

fn node_capability_errors(config: &NodeConfig) -> Vec<String> {
    let mut errors = Vec::new();

    if config.rollout.feature_gates.recursive_proofs
        && !cfg!(any(
            feature = "prover-mock",
            feature = "prover-stwo",
            feature = "backend-plonky3",
            feature = "backend-rpp-stark",
        ))
    {
        errors.push(
            "rollout.feature_gates.recursive_proofs requires compiling with at least one proof backend (`prover-mock`, `prover-stwo`, `backend-plonky3`, or `backend-rpp-stark`)"
                .to_string(),
        );
    }

    errors
}

fn wallet_capability_errors(
    config: &WalletConfig,
    hints: Option<&WalletCapabilityHints>,
) -> Vec<String> {
    let mut errors = Vec::new();

    if config.gui.security_controls_enabled && !cfg!(feature = "wallet_rpc_mtls") {
        errors.push(wallet_rpc_mtls_disabled_message(
            "wallet.gui.security_controls_enabled",
        ));
    }

    if !cfg!(feature = "vendor_electrs")
        && hints.map_or(false, WalletCapabilityHints::electrs_requested)
    {
        errors.push(wallet_electrs_disabled_message());
    }

    errors
}

fn wallet_rpc_mtls_disabled_message(scope: &str) -> String {
    format!(
        "{scope} requires compiling with the `wallet_rpc_mtls` feature; rebuild this binary to configure wallet RPC security"
    )
}

fn wallet_electrs_disabled_message() -> String {
    "wallet.electrs requires compiling with the `vendor_electrs` feature; rebuild this binary with vendor support to enable the Electrs integration".to_string()
}

fn init_tracing(
    config: &NodeConfig,
    metadata: Option<&ConfigMetadata>,
    log_level: Option<String>,
    _json: bool,
    mode: RuntimeMode,
    config_source: &str,
    dry_run: bool,
) -> Result<Option<TelemetryHandles>> {
    let level = log_level.or_else(|| std::env::var("RUST_LOG").ok());
    let filter = match level {
        Some(level) => match EnvFilter::try_new(level) {
            Ok(filter) => filter,
            Err(err) => {
                eprintln!("invalid log level override ({err}), falling back to info");
                EnvFilter::new("info")
            }
        },
        None => EnvFilter::new("info"),
    };

    let telemetry_config = resolved_telemetry_config(config)?;
    metrics::gauge!("firewood.storage.io_uring_ring_entries").set(config.storage.ring_size as f64);
    let prometheus_listen = telemetry_config.metrics.listen.map(|addr| addr.to_string());
    let prometheus_listen_field = prometheus_listen.as_deref();
    let prometheus_auth = telemetry_config.metrics.auth_token.is_some();

    let instance_id = resolve_instance_id(metadata, mode);
    let redact_logs = telemetry_config.redact_logs;
    let fmt_layer = || structured_log_layer(mode, config_source, &instance_id, redact_logs);

    if dry_run {
        tracing_subscriber::registry()
            .with(filter.clone())
            .with(fmt_layer())
            .try_init()?;

        let telemetry_span = info_span!(
            "node.telemetry.init",
            service.name = "rpp",
            service.component = "rpp-node",
            rpp.mode = mode.as_str(),
            rpp.config_source = config_source,
            instance.id = instance_id.as_str(),
            otlp_enabled = false,
            prometheus_listen = prometheus_listen_field,
            prometheus_auth = prometheus_auth,
            dry_run = true,
            mode = mode.as_str(),
            config_source = config_source,
            storage_io_uring_ring_entries = config.storage.ring_size
        );
        let _span_guard = telemetry_span.enter();
        let metrics_endpoint = TelemetryExporterBuilder::new(&telemetry_config)
            .http_endpoint()
            .map(str::to_string);
        info!(
            target = "telemetry",
            service.name = "rpp",
            service.component = "rpp-node",
            rpp.mode = mode.as_str(),
            rpp.config_source = config_source,
            instance.id = instance_id.as_str(),
            otlp_enabled = false,
            dry_run = true,
            metrics_enabled = telemetry_config.enabled,
            metrics_endpoint = metrics_endpoint.as_deref(),
            prometheus_listen = prometheus_listen_field,
            prometheus_auth = prometheus_auth,
            storage_io_uring_ring_entries = config.storage.ring_size,
            mode = mode.as_str(),
            config_source = config_source,
            "tracing initialised"
        );
        return Ok(None);
    }

    let prometheus_guard = install_prometheus_recorder(&telemetry_config)
        .context("failed to initialise Prometheus recorder")?;
    let resource = telemetry_resource(config, metadata, mode, config_source, &instance_id);
    let mut metrics_config = telemetry_config.clone();
    let (runtime_metrics, metrics_guard) =
        match init_runtime_metrics(&metrics_config, resource.clone()) {
            Ok(metrics) => metrics,
            Err(error) => {
                record_otlp_failure("metrics", "init");
                warn!(
                    target = "telemetry",
                    sink = "metrics",
                    phase = "init",
                    error = %error,
                    "failed to initialise OTLP metric exporter; metrics will only be logged locally"
                );
                metrics_config.enabled = false;
                metrics_config.endpoint = None;
                metrics_config.http_endpoint = None;
                init_runtime_metrics(&metrics_config, resource.clone())
                    .context("failed to initialise runtime metrics fallback")?
            }
        };
    let mut guard = OtelGuard::new(metrics_guard);
    if let Some(prometheus_guard) = prometheus_guard {
        guard = guard.with_prometheus_guard(prometheus_guard);
    }
    let metrics_endpoint = TelemetryExporterBuilder::new(&metrics_config)
        .http_endpoint()
        .map(str::to_string);
    let metrics_endpoint_field = metrics_endpoint.as_deref();
    let metrics_enabled = metrics_config.enabled;

    match build_otlp_layer(&telemetry_config, resource)? {
        Some(OtlpLayer { layer, endpoint }) => {
            tracing_subscriber::registry()
                .with(filter.clone())
                .with(fmt_layer())
                .with(layer)
                .try_init()?;

            guard = guard.with_tracer_shutdown(|| {
                if let Err(err) = global::shutdown_tracer_provider() {
                    eprintln!("failed to shutdown otlp tracer provider: {err}");
                }
            });

            let telemetry_span = info_span!(
                "node.telemetry.init",
                service.name = "rpp",
                service.component = "rpp-node",
                rpp.mode = mode.as_str(),
                rpp.config_source = config_source,
                instance.id = instance_id.as_str(),
                otlp_enabled = true,
                otlp_endpoint = endpoint.as_str(),
                metrics_enabled = metrics_enabled,
                metrics_endpoint = metrics_endpoint_field,
                prometheus_listen = prometheus_listen_field,
                prometheus_auth = prometheus_auth,
                dry_run = false,
                mode = mode.as_str(),
                config_source = config_source,
                storage_io_uring_ring_entries = config.storage.ring_size
            );
            let _span_guard = telemetry_span.enter();
            info!(
                target = "telemetry",
                service.name = "rpp",
                service.component = "rpp-node",
                rpp.mode = mode.as_str(),
                rpp.config_source = config_source,
                instance.id = instance_id.as_str(),
                otlp_enabled = true,
                otlp_endpoint = endpoint,
                metrics_enabled = metrics_enabled,
                metrics_endpoint = metrics_endpoint_field,
                prometheus_listen = prometheus_listen_field,
                prometheus_auth = prometheus_auth,
                dry_run = false,
                storage_io_uring_ring_entries = config.storage.ring_size,
                mode = mode.as_str(),
                config_source = config_source,
                "tracing initialised"
            );
            Ok(Some(TelemetryHandles {
                guard,
                runtime_metrics,
            }))
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer())
                .try_init()?;

            let telemetry_span = info_span!(
                "node.telemetry.init",
                service.name = "rpp",
                service.component = "rpp-node",
                rpp.mode = mode.as_str(),
                rpp.config_source = config_source,
                instance.id = instance_id.as_str(),
                otlp_enabled = false,
                metrics_enabled = metrics_enabled,
                metrics_endpoint = metrics_endpoint_field,
                prometheus_listen = prometheus_listen_field,
                prometheus_auth = prometheus_auth,
                dry_run = false,
                mode = mode.as_str(),
                config_source = config_source
            );
            let _span_guard = telemetry_span.enter();
            info!(
                target = "telemetry",
                service.name = "rpp",
                service.component = "rpp-node",
                rpp.mode = mode.as_str(),
                rpp.config_source = config_source,
                instance.id = instance_id.as_str(),
                otlp_enabled = false,
                metrics_enabled = metrics_enabled,
                metrics_endpoint = metrics_endpoint_field,
                prometheus_listen = prometheus_listen_field,
                prometheus_auth = prometheus_auth,
                dry_run = false,
                mode = mode.as_str(),
                config_source = config_source,
                "tracing initialised"
            );
            Ok(Some(TelemetryHandles {
                guard,
                runtime_metrics,
            }))
        }
    }
}

fn structured_log_layer(
    mode: RuntimeMode,
    config_source: &str,
    instance_id: &str,
    redact_sensitive: bool,
) -> StructuredLogLayer {
    StructuredLogLayer::new(mode, config_source, instance_id, redact_sensitive)
}

fn resolve_instance_id(metadata: Option<&ConfigMetadata>, mode: RuntimeMode) -> String {
    if let Ok(value) = env::var("RPP_INSTANCE_ID") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Some(metadata) = metadata {
        if let Some(file_name) = metadata.path.file_name().and_then(|name| name.to_str()) {
            return format!("{}-{file_name}", metadata.source.as_str());
        }
    }

    if let Ok(host) = env::var("HOSTNAME") {
        let trimmed = host.trim();
        if !trimmed.is_empty() {
            return format!("{trimmed}-{}", std::process::id());
        }
    }

    format!("{}-{}", mode.as_str(), std::process::id())
}

#[derive(Clone)]
struct StructuredLogLayer {
    mode: RuntimeMode,
    config_source: String,
    instance_id: String,
    redact_sensitive: bool,
}

impl StructuredLogLayer {
    fn new(
        mode: RuntimeMode,
        config_source: &str,
        instance_id: &str,
        redact_sensitive: bool,
    ) -> Self {
        Self {
            mode,
            config_source: config_source.to_string(),
            instance_id: instance_id.to_string(),
            redact_sensitive,
        }
    }
}

impl<S> Layer<S> for StructuredLogLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = JsonEventVisitor::default();
        event.record(&mut visitor);
        let mut fields = visitor.into_fields();

        let message = fields
            .remove("message")
            .and_then(|value| match value {
                JsonValue::String(value) => Some(value),
                JsonValue::Null => None,
                other => Some(other.to_string()),
            })
            .unwrap_or_default();

        let mut log = fields;
        log.insert("msg".to_string(), JsonValue::String(message));
        log.insert("ts".to_string(), JsonValue::String(current_timestamp()));
        log.insert(
            "level".to_string(),
            JsonValue::String(event.metadata().level().as_str().to_lowercase()),
        );
        log.insert(
            "target".to_string(),
            JsonValue::String(event.metadata().target().to_string()),
        );
        log.insert(
            "service.name".to_string(),
            JsonValue::String("rpp".to_string()),
        );
        log.insert(
            "service.component".to_string(),
            JsonValue::String("rpp-node".to_string()),
        );
        let mode_value = JsonValue::String(self.mode.as_str().to_string());
        log.insert("rpp.mode".to_string(), mode_value.clone());
        log.insert("mode".to_string(), mode_value);
        let config_source_value = JsonValue::String(self.config_source.clone());
        log.insert("rpp.config_source".to_string(), config_source_value.clone());
        log.insert("config_source".to_string(), config_source_value);
        log.insert(
            "instance.id".to_string(),
            JsonValue::String(self.instance_id.clone()),
        );

        if self.redact_sensitive {
            redact_sensitive_fields(&mut log);
        }

        let payload = serde_json::to_string(&JsonValue::Object(log)).or_else(|err| {
            let mut fallback = JsonMap::new();
            fallback.insert("level".to_string(), JsonValue::String("error".to_string()));
            fallback.insert(
                "msg".to_string(),
                JsonValue::String("failed to serialize log event".to_string()),
            );
            fallback.insert("error".to_string(), JsonValue::String(err.to_string()));
            serde_json::to_string(&JsonValue::Object(fallback))
        });

        if let Ok(line) = payload {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{line}");
        }
    }
}

#[derive(Default)]
struct JsonEventVisitor {
    fields: JsonMap<String, JsonValue>,
}

impl JsonEventVisitor {
    fn insert_value(&mut self, field: &Field, value: JsonValue) {
        self.fields.insert(field.name().to_string(), value);
    }

    fn into_fields(self) -> JsonMap<String, JsonValue> {
        self.fields
    }
}

impl Visit for JsonEventVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert_value(field, JsonValue::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert_value(field, JsonValue::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert_value(field, JsonValue::Number(value.into()));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.insert_value(field, JsonValue::String(value.to_string()));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.insert_value(field, JsonValue::String(value.to_string()));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if let Some(number) = serde_json::Number::from_f64(value) {
            self.insert_value(field, JsonValue::Number(number));
        } else {
            self.insert_value(field, JsonValue::String(value.to_string()));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert_value(field, JsonValue::String(value.to_string()));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert_value(field, JsonValue::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert_value(field, JsonValue::String(format!("{value:?}")));
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        let encoded = value
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
        self.insert_value(field, JsonValue::String(encoded));
    }
}

fn current_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn redact_sensitive_fields(fields: &mut JsonMap<String, JsonValue>) {
    let keys: Vec<String> = fields
        .keys()
        .filter(|key| should_redact_key(key))
        .cloned()
        .collect();

    for key in keys {
        if let Some(value) = fields.get(&key).cloned() {
            if let Some(hash) = hash_sensitive_value(&value) {
                fields.insert(key, JsonValue::String(format!("sha256:{hash}")));
            } else {
                fields.insert(key, JsonValue::Null);
            }
        }
    }
}

fn should_redact_key(key: &str) -> bool {
    const SENSITIVE_SUBSTRINGS: &[&str] = &["token", "secret", "password", "auth"];
    let lower = key.to_ascii_lowercase();
    SENSITIVE_SUBSTRINGS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

fn hash_sensitive_value(value: &JsonValue) -> Option<String> {
    let raw = match value {
        JsonValue::Null => return None,
        JsonValue::String(inner) => inner.clone(),
        other => other.to_string(),
    };

    if raw.is_empty() {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let hash = digest.iter().map(|byte| format!("{:02x}", byte)).collect();
    Some(hash)
}

struct TelemetryHandles {
    guard: OtelGuard,
    runtime_metrics: Arc<RuntimeMetrics>,
}

fn install_prometheus_recorder(
    telemetry: &TelemetryConfig,
) -> Result<Option<PrometheusRecorderGuard>> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .context("failed to install Prometheus metrics recorder")?;
    let listen = telemetry.metrics.listen;
    let auth_token = normalize_bearer_token(&telemetry.metrics.auth_token);
    let guard = PrometheusRecorderGuard::new(handle, listen, auth_token)
        .context("failed to initialise Prometheus metrics endpoint")?;
    Ok(Some(guard))
}

struct OtelGuard {
    metrics_guard: Option<RuntimeMetricsGuard>,
    tracer_shutdown: Option<Box<dyn FnOnce() + Send + Sync + 'static>>,
    prometheus_guard: Option<PrometheusRecorderGuard>,
}

impl OtelGuard {
    fn new(metrics_guard: RuntimeMetricsGuard) -> Self {
        Self {
            metrics_guard: Some(metrics_guard),
            tracer_shutdown: None,
            prometheus_guard: None,
        }
    }

    fn with_tracer_shutdown(mut self, shutdown: impl FnOnce() + Send + Sync + 'static) -> Self {
        self.tracer_shutdown = Some(Box::new(shutdown));
        self
    }

    fn with_prometheus_guard(mut self, guard: PrometheusRecorderGuard) -> Self {
        self.prometheus_guard = Some(guard);
        self
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        self.prometheus_guard.take();
        if let Some(mut metrics_guard) = self.metrics_guard.take() {
            metrics_guard.flush_and_shutdown();
        }
        if let Some(shutdown) = self.tracer_shutdown.take() {
            shutdown();
        }
    }
}

struct PrometheusRecorderGuard {
    #[allow(dead_code)]
    handle: PrometheusHandle,
    upkeep_shutdown: Option<oneshot::Sender<()>>,
    upkeep_task: Option<JoinHandle<()>>,
    server: Option<MetricsServerGuard>,
}

impl PrometheusRecorderGuard {
    fn new(
        handle: PrometheusHandle,
        listen: Option<SocketAddr>,
        auth_token: Option<String>,
    ) -> Result<Self> {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let upkeep_handle = {
            let upkeep_handle = handle.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(5));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => upkeep_handle.run_upkeep(),
                        _ = &mut shutdown_rx => break,
                    }
                }
            })
        };

        let server = if let Some(addr) = listen {
            Some(spawn_prometheus_server(addr, handle.clone(), auth_token)?)
        } else {
            None
        };

        Ok(Self {
            handle,
            upkeep_shutdown: Some(shutdown_tx),
            upkeep_task: Some(upkeep_handle),
            server,
        })
    }
}

impl Drop for PrometheusRecorderGuard {
    fn drop(&mut self) {
        self.server.take();
        if let Some(tx) = self.upkeep_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.upkeep_task.take() {
            task.abort();
        }
    }
}

struct MetricsServerGuard {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Drop for MetricsServerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}

fn spawn_prometheus_server(
    listen: SocketAddr,
    handle: PrometheusHandle,
    auth_token: Option<String>,
) -> Result<MetricsServerGuard> {
    let auth_required = auth_token.is_some();
    let builder = Server::try_bind(&listen)
        .with_context(|| format!("failed to bind Prometheus metrics endpoint on {listen}"))?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let service_handle = handle.clone();
    let service_auth = auth_token.clone();
    let make_service = make_service_fn(move |_conn| {
        let handle = service_handle.clone();
        let auth = service_auth.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |request| {
                prometheus_http_handler(request, handle.clone(), auth.clone())
            }))
        }
    });

    let listen_for_task = listen;
    let server = builder
        .serve(make_service)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });

    let task = tokio::spawn(async move {
        if let Err(err) = server.await {
            error!(
                target = "telemetry",
                listen = %listen_for_task,
                "prometheus metrics endpoint exited with error: {err}"
            );
        }
    });

    info!(
        target = "telemetry",
        listen = %listen,
        auth = auth_required,
        "prometheus metrics endpoint listening"
    );

    Ok(MetricsServerGuard {
        shutdown: Some(shutdown_tx),
        task,
    })
}

async fn prometheus_http_handler(
    request: Request<Body>,
    handle: PrometheusHandle,
    auth_token: Option<String>,
) -> Result<Response<Body>, Infallible> {
    if let Some(expected) = auth_token.as_ref() {
        let provided = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if provided != Some(expected.as_str()) {
            return Ok(unauthorized_response());
        }
    }

    if request.uri().path() != "/metrics" {
        return Ok(Response::builder()
            .status(hyper::StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap_or_else(|_| Response::new(Body::from("not found"))));
    }

    match *request.method() {
        Method::GET => {
            let body = handle.render();
            Ok(Response::builder()
                .status(hyper::StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain; version=0.0.4")
                .header(CACHE_CONTROL, "no-cache")
                .body(Body::from(body))
                .unwrap_or_else(|_| Response::new(Body::empty())))
        }
        Method::HEAD => Ok(Response::builder()
            .status(hyper::StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain; version=0.0.4")
            .header(CACHE_CONTROL, "no-cache")
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::empty()))),
        _ => Ok(Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("method not allowed"))
            .unwrap_or_else(|_| Response::new(Body::from("method not allowed")))),
    }
}

fn unauthorized_response() -> Response<Body> {
    Response::builder()
        .status(hyper::StatusCode::UNAUTHORIZED)
        .header(WWW_AUTHENTICATE, "Bearer")
        .body(Body::from("unauthorized"))
        .unwrap_or_else(|_| Response::new(Body::from("unauthorized")))
}

struct OtlpLayer {
    layer: OpenTelemetryLayer<tracing_subscriber::Registry, Tracer>,
    endpoint: String,
}

fn resolved_telemetry_config(config: &NodeConfig) -> Result<TelemetryConfig> {
    let mut telemetry = config.rollout.telemetry.clone();

    let endpoint_override = normalize_option(std::env::var("RPP_NODE_OTLP_ENDPOINT").ok());
    let env_endpoint = normalize_option(std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok());

    if let Some(endpoint) = endpoint_override.clone().or(env_endpoint.clone()) {
        telemetry.endpoint = Some(endpoint);
        telemetry.enabled = true;
    }

    if let Some(http_endpoint) = normalize_option(std::env::var("RPP_NODE_OTLP_HTTP_ENDPOINT").ok())
    {
        telemetry.http_endpoint = Some(http_endpoint);
    }

    if let Some(token) = normalize_option(std::env::var("RPP_NODE_OTLP_AUTH_TOKEN").ok()) {
        telemetry.auth_token = Some(token);
    }

    if let Some(timeout) = std::env::var("RPP_NODE_OTLP_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        telemetry.timeout_ms = timeout;
    }

    telemetry.validate().map_err(|err| anyhow!(err))?;

    Ok(telemetry)
}

fn build_otlp_layer(telemetry: &TelemetryConfig, resource: Resource) -> Result<Option<OtlpLayer>> {
    let builder = TelemetryExporterBuilder::new(telemetry);

    let exporter = match builder.build_span_exporter() {
        Ok(Some(exporter)) => exporter,
        Ok(None) => {
            if telemetry.enabled {
                anyhow::bail!("telemetry endpoint required when OTLP is enabled");
            }
            return Ok(None);
        }
        Err(error) => {
            record_otlp_failure("traces", "init");
            warn!(
                target = "telemetry",
                sink = "traces",
                phase = "init",
                error = %error,
                "failed to initialise OTLP span exporter; traces will not be exported"
            );
            return Ok(None);
        }
    };

    let batch_config = builder.build_trace_batch_config();
    let sampler = builder.trace_sampler();
    let endpoint = builder
        .grpc_endpoint()
        .map(str::to_string)
        .unwrap_or_default();

    let provider = trace::TracerProvider::builder()
        .with_config(
            trace::Config::default()
                .with_resource(resource)
                .with_sampler(sampler),
        )
        .with_batch_config(batch_config)
        .with_batch_exporter(exporter, Tokio)
        .build();

    let tracer = provider.tracer("rpp-node", Some(env!("CARGO_PKG_VERSION")));
    global::set_tracer_provider(provider);

    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Ok(Some(OtlpLayer { layer, endpoint }))
}

fn telemetry_resource(
    config: &NodeConfig,
    metadata: Option<&ConfigMetadata>,
    mode: RuntimeMode,
    config_source: &str,
    instance_id: &str,
) -> Resource {
    let mut attributes = vec![
        KeyValue::new("service.name", "rpp"),
        KeyValue::new("service.component", "rpp-node"),
        KeyValue::new("service.namespace", "rpp"),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("rpp.mode", mode.as_str()),
        KeyValue::new("rpp.config_source", config_source.to_string()),
        KeyValue::new("instance.id", instance_id.to_string()),
        KeyValue::new("schema.version", config.config_version.clone()),
        KeyValue::new(
            "rpp.rollout.release_channel",
            format!("{:?}", config.rollout.release_channel),
        ),
        KeyValue::new(
            "rpp.telemetry.sample_interval_secs",
            config.rollout.telemetry.sample_interval_secs as i64,
        ),
        KeyValue::new(
            "rpp.telemetry.redact_logs",
            config.rollout.telemetry.redact_logs,
        ),
    ];

    if let Some(metadata) = metadata {
        attributes.push(KeyValue::new(
            "rpp.config.node.source",
            metadata.source.as_str(),
        ));
        attributes.push(KeyValue::new(
            "rpp.config.node.path",
            metadata.path.display().to_string(),
        ));
    }

    Resource::new(attributes)
}

fn normalize_option(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry::trace::Tracer as _;
    use opentelemetry_sdk::export::trace::InMemorySpanExporter;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use opentelemetry_sdk::trace::{self, SimpleSpanProcessor};
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use tempfile::tempdir;

    #[cfg(unix)]
    use {
        std::io::{Read, Seek, SeekFrom},
        std::mem::MaybeUninit,
        std::os::unix::io::AsRawFd,
        std::panic,
        tempfile::tempfile,
    };

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> &'static Mutex<()> {
        ENV_MUTEX.get_or_init(|| Mutex::new(()))
    }

    struct ConfigEnvGuard {
        previous: Option<String>,
    }

    impl ConfigEnvGuard {
        fn set(value: Option<&str>) -> Self {
            let previous = std::env::var("RPP_CONFIG").ok();
            match value {
                Some(value) => std::env::set_var("RPP_CONFIG", value),
                None => std::env::remove_var("RPP_CONFIG"),
            }
            Self { previous }
        }
    }

    impl Drop for ConfigEnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                std::env::set_var("RPP_CONFIG", value);
            } else {
                std::env::remove_var("RPP_CONFIG");
            }
        }
    }

    struct IoUringEnvGuard {
        previous: Option<String>,
    }

    impl IoUringEnvGuard {
        fn force_unsupported() -> Self {
            let previous = std::env::var(IO_URING_FORCE_UNSUPPORTED_ENV).ok();
            std::env::set_var(IO_URING_FORCE_UNSUPPORTED_ENV, "1");
            Self { previous }
        }
    }

    impl Drop for IoUringEnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                std::env::set_var(IO_URING_FORCE_UNSUPPORTED_ENV, value);
            } else {
                std::env::remove_var(IO_URING_FORCE_UNSUPPORTED_ENV);
            }
        }
    }

    #[derive(Clone)]
    struct BufferWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffer.lock().expect("buffer").write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.buffer.lock().expect("buffer").flush()
        }
    }

    fn capture_logs<F, R>(callback: F) -> (R, String)
    where
        F: FnOnce() -> R,
    {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = BufferWriter {
            buffer: Arc::clone(&buffer),
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let result = tracing::subscriber::with_default(subscriber, callback);
        let output = String::from_utf8(buffer.lock().expect("buffer").clone()).expect("utf8 logs");
        (result, output)
    }

    fn base_bootstrap_options() -> BootstrapOptions {
        BootstrapOptions {
            node_config: None,
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
            dry_run: true,
            write_config: false,
            storage_ring_size: None,
            pruning: PruningOverrides::default(),
        }
    }

    #[test]
    fn apply_pruning_overrides_updates_config() {
        let mut config = NodeConfig::default();
        let mut options = base_bootstrap_options();
        options.pruning = PruningOverrides {
            cadence_secs: Some(120),
            retention_depth: Some(256),
            emergency_pause: Some(true),
        };

        apply_overrides(&mut config, &options);

        assert_eq!(config.pruning.cadence_secs, 120);
        assert_eq!(config.pruning.retention_depth, 256);
        assert!(config.pruning.emergency_pause);
    }

    #[cfg(unix)]
    fn capture_stderr<F, R>(f: F) -> (String, R)
    where
        F: FnOnce() -> R,
    {
        let mut file = tempfile().expect("tempfile");
        let file_fd = file.as_raw_fd();
        let stderr_fd = libc::STDERR_FILENO;

        unsafe {
            let saved = libc::dup(stderr_fd);
            assert!(saved >= 0, "failed to duplicate stderr");
            libc::fflush(libc::stderr);
            assert!(
                libc::dup2(file_fd, stderr_fd) >= 0,
                "failed to redirect stderr"
            );

            let mut result = MaybeUninit::uninit();
            let outcome = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                result.write(f());
            }));

            libc::fflush(libc::stderr);
            assert!(
                libc::dup2(saved, stderr_fd) >= 0,
                "failed to restore stderr"
            );
            libc::close(saved);

            match outcome {
                Ok(()) => {
                    file.seek(SeekFrom::Start(0)).expect("seek stderr capture");
                    let mut output = String::new();
                    file.read_to_string(&mut output)
                        .expect("read captured stderr");
                    (output, result.assume_init())
                }
                Err(err) => {
                    file.seek(SeekFrom::Start(0)).expect("seek stderr capture");
                    let mut output = String::new();
                    file.read_to_string(&mut output)
                        .expect("read captured stderr");
                    std::panic::resume_unwind(err);
                }
            }
        }
    }

    #[test]
    fn resolve_config_path_prefers_command_line() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = ConfigEnvGuard::set(Some("/tmp/env-config.toml"));

        let cli_path = PathBuf::from("/tmp/cli-config.toml");
        let resolved = resolve_config_path(Some(cli_path.clone()), Some("config/default.toml"))
            .expect("resolved path");

        assert_eq!(resolved.path, cli_path);
        assert_eq!(resolved.source, ConfigSource::CommandLine);
    }

    #[test]
    fn resolve_config_path_uses_environment_when_cli_absent() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = ConfigEnvGuard::set(Some("/tmp/env-config.toml"));

        let resolved = resolve_config_path(None, Some("config/default.toml")).expect("resolved");

        assert_eq!(resolved.path, PathBuf::from("/tmp/env-config.toml"));
        assert_eq!(resolved.source, ConfigSource::Environment);
    }

    #[test]
    fn resolve_config_path_uses_default_when_other_sources_missing() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = ConfigEnvGuard::set(None);

        let resolved = resolve_config_path(None, Some("config/default.toml")).expect("resolved");

        assert_eq!(resolved.path, PathBuf::from("config/default.toml"));
        assert_eq!(resolved.source, ConfigSource::Default);
    }

    #[test]
    fn resolve_config_path_returns_none_when_all_sources_missing() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = ConfigEnvGuard::set(None);

        assert!(resolve_config_path(None, None).is_none());
    }

    #[test]
    fn resolve_config_path_trims_environment_variable() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = ConfigEnvGuard::set(Some("  /tmp/env-config.toml  "));

        let resolved = resolve_config_path(None, Some("config/default.toml")).expect("resolved");

        assert_eq!(resolved.path, PathBuf::from("/tmp/env-config.toml"));
        assert_eq!(resolved.source, ConfigSource::Environment);
    }

    #[test]
    fn resolve_config_path_ignores_blank_environment_variable() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = ConfigEnvGuard::set(Some("   "));

        let resolved = resolve_config_path(None, Some("config/default.toml")).expect("resolved");

        assert_eq!(resolved.path, PathBuf::from("config/default.toml"));
        assert_eq!(resolved.source, ConfigSource::Default);
    }

    #[test]
    fn load_node_configuration_reports_missing_cli_path() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = ConfigEnvGuard::set(None);

        let temp = tempdir().expect("tempdir");
        let missing = temp.path().join("hybrid-node.toml");
        let mut options = base_bootstrap_options();
        options.node_config = Some(missing.clone());

        let error = load_node_configuration(RuntimeMode::Hybrid, &options)
            .expect_err("missing node config should error");
        let config_error = error
            .downcast::<ConfigurationError>()
            .expect("configuration error");

        match config_error {
            ConfigurationError::Missing {
                role,
                path,
                source,
                suggestion,
            } => {
                assert_eq!(role, ConfigRole::Node);
                assert_eq!(path, missing);
                assert_eq!(source, ConfigSource::CommandLine);
                let suggestion = suggestion.expect("suggestion expected");
                assert!(
                    suggestion.contains("config/hybrid.toml"),
                    "unexpected suggestion: {}",
                    suggestion
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_wallet_configuration_reports_missing_cli_path() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = ConfigEnvGuard::set(None);

        let temp = tempdir().expect("tempdir");
        let missing = temp.path().join("hybrid-wallet.toml");
        let mut options = base_bootstrap_options();
        options.wallet_config = Some(missing.clone());

        let error = load_wallet_configuration(RuntimeMode::Hybrid, &options)
            .expect_err("missing wallet config should error");
        let config_error = error
            .downcast::<ConfigurationError>()
            .expect("configuration error");

        match config_error {
            ConfigurationError::Missing {
                role,
                path,
                source,
                suggestion,
            } => {
                assert_eq!(role, ConfigRole::Wallet);
                assert_eq!(path, missing);
                assert_eq!(source, ConfigSource::CommandLine);
                let suggestion = suggestion.expect("suggestion expected");
                assert!(
                    suggestion.contains("config/wallet.toml"),
                    "unexpected suggestion: {}",
                    suggestion
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_wallet_configuration_skipped_in_node_mode() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = ConfigEnvGuard::set(None);

        let mut options = base_bootstrap_options();
        options.wallet_config = Some(PathBuf::from("/tmp/ignored-wallet.toml"));

        let result = load_wallet_configuration(RuntimeMode::Node, &options)
            .expect("node mode should skip wallet config");
        assert!(result.is_none());
    }

    #[test]
    fn ensure_listener_conflicts_accepts_matching_configuration() {
        let mut node_config = NodeConfig::for_mode(RuntimeMode::Hybrid);
        node_config.network.rpc.listen = "127.0.0.1:7070".parse().expect("socket addr");
        node_config.network.p2p.listen_addr = "/ip4/0.0.0.0/tcp/7600".to_string();

        let mut wallet_config = WalletConfig::for_mode(RuntimeMode::Hybrid);
        wallet_config.wallet.rpc.listen = node_config.network.rpc.listen;

        let node_bundle = ConfigBundle {
            value: node_config,
            metadata: None,
            capabilities: CapabilityHints::default(),
        };
        let wallet_bundle = ConfigBundle {
            value: wallet_config,
            metadata: None,
            capabilities: CapabilityHints::default(),
        };

        ensure_listener_conflicts(
            RuntimeMode::Hybrid,
            Some(&node_bundle),
            Some(&wallet_bundle),
        )
        .expect("matching listeners should not conflict");
    }

    #[test]
    fn ensure_listener_conflicts_detects_rpc_mismatch() {
        let mut node_config = NodeConfig::for_mode(RuntimeMode::Hybrid);
        node_config.network.rpc.listen = "127.0.0.1:7000".parse().expect("socket addr");

        let mut wallet_config = WalletConfig::for_mode(RuntimeMode::Hybrid);
        wallet_config.wallet.rpc.listen = "127.0.0.1:8000".parse().expect("socket addr");

        let node_bundle = ConfigBundle {
            value: node_config,
            metadata: Some(ConfigMetadata::new(
                PathBuf::from("/etc/rpp/node.toml"),
                ConfigSource::CommandLine,
            )),
            capabilities: CapabilityHints::default(),
        };
        let wallet_bundle = ConfigBundle {
            value: wallet_config,
            metadata: Some(ConfigMetadata::new(
                PathBuf::from("/etc/rpp/wallet.toml"),
                ConfigSource::CommandLine,
            )),
            capabilities: CapabilityHints::default(),
        };

        let error = ensure_listener_conflicts(
            RuntimeMode::Hybrid,
            Some(&node_bundle),
            Some(&wallet_bundle),
        )
        .expect_err("mismatched listeners should error");
        let config_error = error
            .downcast::<ConfigurationError>()
            .expect("configuration error");

        match config_error {
            ConfigurationError::Conflict { message } => {
                assert!(message.contains("listener mismatch"), "{message}");
                assert!(message.contains("node configuration"), "{message}");
                assert!(message.contains("wallet configuration"), "{message}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ensure_listener_conflicts_detects_port_reuse() {
        let mut node_config = NodeConfig::for_mode(RuntimeMode::Hybrid);
        node_config.network.rpc.listen = "127.0.0.1:7500".parse().expect("socket addr");
        node_config.network.p2p.listen_addr = "/ip4/0.0.0.0/tcp/7500".to_string();

        let mut wallet_config = WalletConfig::for_mode(RuntimeMode::Hybrid);
        wallet_config.wallet.rpc.listen = node_config.network.rpc.listen;

        let node_bundle = ConfigBundle {
            value: node_config,
            metadata: Some(ConfigMetadata::new(
                PathBuf::from("/etc/rpp/node.toml"),
                ConfigSource::CommandLine,
            )),
            capabilities: CapabilityHints::default(),
        };
        let wallet_bundle = ConfigBundle {
            value: wallet_config,
            metadata: Some(ConfigMetadata::new(
                PathBuf::from("/etc/rpp/wallet.toml"),
                ConfigSource::CommandLine,
            )),
            capabilities: CapabilityHints::default(),
        };

        let error = ensure_listener_conflicts(
            RuntimeMode::Hybrid,
            Some(&node_bundle),
            Some(&wallet_bundle),
        )
        .expect_err("port reuse should error");
        let config_error = error
            .downcast::<ConfigurationError>()
            .expect("configuration error");

        match config_error {
            ConfigurationError::Conflict { message } => {
                assert!(message.contains("listener conflict"), "{message}");
                assert!(message.contains("TCP port 7500"), "{message}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn handle_io_uring_capability_warns_when_disabled() {
        let (_result, logs) = capture_logs(|| {
            handle_io_uring_capability(
                IoUringCapability::Disabled {
                    reason: "feature disabled".into(),
                },
                FileBacked::DEFAULT_RING_ENTRIES,
            )
            .expect("disabled capability should not error");
        });

        assert!(
            logs.contains("io-uring unavailable"),
            "io-uring warning missing from logs: {logs}"
        );
        assert!(
            logs.contains("feature disabled"),
            "reason missing from logs: {logs}"
        );
    }

    #[test]
    fn ensure_io_uring_support_errors_when_forced_unsupported() {
        let _lock = env_lock().lock().expect("env mutex");
        let _guard = IoUringEnvGuard::force_unsupported();

        let (result, logs) =
            capture_logs(|| ensure_io_uring_support(FileBacked::DEFAULT_RING_ENTRIES));
        let error = result.expect_err("forced unsupported environment should error");

        assert!(
            logs.contains("io-uring is enabled but unsupported"),
            "kernel warning missing from logs: {logs}"
        );

        let message = format!("{error}");
        assert!(
            message.contains("io-uring support requested but unavailable"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn telemetry_resource_includes_service_attributes() {
        let config = NodeConfig::default();
        let resource =
            telemetry_resource(&config, None, RuntimeMode::Node, "default", "test-instance");
        let attributes: HashMap<_, _> = resource
            .iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.clone()))
            .collect();

        fn value_to_string(value: &Value) -> Option<String> {
            match value {
                Value::String(value) => Some(value.to_string()),
                Value::Bool(value) => Some(value.to_string()),
                Value::F64(value) => Some(value.to_string()),
                Value::I64(value) => Some(value.to_string()),
                Value::Bytes(value) => Some(format!("{:?}", value)),
                Value::Array(values) => Some(format!("{:?}", values)),
                Value::Map(values) => Some(format!("{:?}", values)),
            }
        }

        assert_eq!(
            attributes
                .get("service.name")
                .and_then(|value| value_to_string(value)),
            Some("rpp".to_string())
        );
        assert_eq!(
            attributes
                .get("service.component")
                .and_then(|value| value_to_string(value)),
            Some("rpp-node".to_string())
        );
        assert_eq!(
            attributes
                .get("rpp.mode")
                .and_then(|value| value_to_string(value)),
            Some("node".to_string())
        );
        assert_eq!(
            attributes
                .get("rpp.config_source")
                .and_then(|value| value_to_string(value)),
            Some("default".to_string())
        );
        assert_eq!(
            attributes
                .get("instance.id")
                .and_then(|value| value_to_string(value)),
            Some("test-instance".to_string())
        );
        assert_eq!(
            attributes
                .get("schema.version")
                .and_then(|value| value_to_string(value)),
            Some(config.config_version.clone())
        );
    }

    #[test]
    fn otel_guard_shuts_down_providers() {
        let provider = SdkMeterProvider::builder().build();
        let before = global::meter_provider() as *const dyn MeterProvider;
        global::set_meter_provider(provider.clone());
        let during = global::meter_provider() as *const dyn MeterProvider;
        assert_ne!(before, during, "meter provider was not installed");
        let metrics_guard = RuntimeMetricsGuard::new(provider);
        let tracer_flag = Arc::new(AtomicBool::new(false));
        {
            let guard = OtelGuard::new(metrics_guard).with_tracer_shutdown({
                let tracer_flag = Arc::clone(&tracer_flag);
                move || tracer_flag.store(true, Ordering::SeqCst)
            });
            drop(guard);
        }
        let after = global::meter_provider() as *const dyn MeterProvider;
        assert_ne!(during, after, "meter provider was not reset to noop");
        assert!(
            tracer_flag.load(Ordering::SeqCst),
            "tracer shutdown hook was not invoked"
        );
    }

    #[cfg(unix)]
    #[test]
    fn init_tracing_dry_run_skips_exporters_and_logs_tags() {
        let mut config = NodeConfig::for_mode(RuntimeMode::Hybrid);
        config.rollout.telemetry.enabled = true;
        config.rollout.telemetry.endpoint = Some("http://127.0.0.1:4317".to_string());
        config.rollout.telemetry.http_endpoint = Some("http://127.0.0.1:4318".to_string());
        config.rollout.telemetry.auth_token = Some("test-token".to_string());

        std::env::remove_var("RPP_NODE_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");

        let before = global::meter_provider() as *const dyn MeterProvider;
        let (captured, telemetry) = capture_stderr(|| {
            init_tracing(
                &config,
                None,
                Some("info".to_string()),
                false,
                RuntimeMode::Hybrid,
                "cli",
                true,
            )
            .expect("init tracing")
        });

        assert!(telemetry.is_none(), "dry run should not start exporters");
        let after = global::meter_provider() as *const dyn MeterProvider;
        assert_eq!(before, after, "dry run should not install metrics provider");
        assert!(captured.contains("\"rpp.mode\":\"hybrid\""), "{captured}");
        assert!(
            captured.contains("\"rpp.config_source\":\"cli\""),
            "{captured}"
        );
    }

    #[test]
    fn tracing_and_metrics_share_resource_attributes() {
        let config = NodeConfig::default();
        let resource = telemetry_resource(
            &config,
            None,
            RuntimeMode::Node,
            "default",
            "shared-instance",
        );

        let metric_exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(metric_exporter.clone()).build();
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_reader(reader)
            .build();
        let meter = meter_provider.meter("test-meter");
        let counter = meter
            .u64_counter("test.counter")
            .with_description("test counter")
            .with_unit("1")
            .build();
        counter.add(1, &[]);
        meter_provider.force_flush().expect("flush metrics");
        let exported = metric_exporter
            .get_finished_metrics()
            .expect("collect metrics");
        assert!(!exported.is_empty(), "expected exported metrics");
        for data in exported {
            assert_eq!(data.resource, resource, "metric resource mismatch");
        }

        let span_exporter = InMemorySpanExporter::new();
        let processor = SimpleSpanProcessor::new(Box::new(span_exporter.clone()));
        let tracer_provider = trace::TracerProvider::builder()
            .with_config(trace::Config::default().with_resource(resource.clone()))
            .with_span_processor(processor)
            .build();
        let tracer = tracer_provider.tracer("test-tracer", None);
        tracer.in_span("test-span", |_span| {});
        tracer_provider.force_flush().expect("flush spans");
        let spans = span_exporter.get_finished_spans();
        assert!(!spans.is_empty(), "expected exported spans");
        for span in spans {
            assert_eq!(span.resource, resource, "span resource mismatch");
        }
    }

    #[test]
    fn recursive_proofs_require_proof_backend_when_not_available() {
        if cfg!(any(
            feature = "prover-mock",
            feature = "prover-stwo",
            feature = "backend-plonky3",
            feature = "backend-rpp-stark",
        )) {
            return;
        }

        let node_bundle = ConfigBundle {
            value: NodeConfig::default(),
            metadata: None,
            capabilities: CapabilityHints::default(),
        };

        let error = ensure_capabilities_supported(Some(&node_bundle), None)
            .expect_err("recursive proofs should require an available proof backend");
        assert_eq!(error.kind(), BootstrapErrorKind::Configuration);
        assert!(
            error
                .to_string()
                .contains("rollout.feature_gates.recursive_proofs"),
            "unexpected error message: {}",
            error
        );
    }

    #[test]
    fn wallet_security_controls_require_wallet_rpc_mtls() {
        if cfg!(feature = "wallet_rpc_mtls") {
            return;
        }

        let mut wallet_config = WalletConfig::for_mode(RuntimeMode::Wallet);
        wallet_config.gui.security_controls_enabled = true;
        let wallet_bundle = ConfigBundle {
            value: wallet_config,
            metadata: None,
            capabilities: CapabilityHints::for_wallet(WalletCapabilityHints::new(false)),
        };

        let error = ensure_capabilities_supported(None, Some(&wallet_bundle))
            .expect_err("wallet security controls should require wallet_rpc_mtls");
        assert_eq!(error.kind(), BootstrapErrorKind::Configuration);
        assert!(
            error
                .to_string()
                .contains("wallet.gui.security_controls_enabled"),
            "unexpected error message: {}",
            error
        );
    }

    #[test]
    fn wallet_electrs_configuration_requires_vendor_feature() {
        if cfg!(feature = "vendor_electrs") {
            return;
        }

        let wallet_bundle = ConfigBundle {
            value: WalletConfig::for_mode(RuntimeMode::Wallet),
            metadata: None,
            capabilities: CapabilityHints::for_wallet(WalletCapabilityHints::new(true)),
        };

        let error = ensure_capabilities_supported(None, Some(&wallet_bundle))
            .expect_err("wallet electrs configuration should require vendor feature");
        assert_eq!(error.kind(), BootstrapErrorKind::Configuration);
        assert!(
            error.to_string().contains("wallet.electrs"),
            "unexpected error message: {}",
            error
        );
    }
}
