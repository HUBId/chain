use std::num::NonZeroU64;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use opentelemetry::global;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{self, BatchConfig, Tracer};
use opentelemetry_sdk::Resource;
use parking_lot::RwLock;
use tokio::task::JoinError;
use tonic::metadata::{MetadataMap, MetadataValue};
use tracing::{error, info, info_span, warn};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

use rpp_chain::api::ApiContext;
use rpp_chain::config::NodeConfig;
use rpp_chain::node::{Node, NodeHandle};
use rpp_chain::runtime::RuntimeMode;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run an rpp node", long_about = None)]
struct Cli {
    /// Optional path to a configuration file that will be loaded before starting the node
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override the data directory defined in the configuration
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Override the RPC listen address defined in the configuration
    #[arg(long)]
    rpc_listen: Option<std::net::SocketAddr>,

    /// Override the RPC authentication token defined in the configuration
    #[arg(long)]
    rpc_auth_token: Option<String>,

    /// Override the telemetry endpoint defined in the configuration
    #[arg(long)]
    telemetry_endpoint: Option<String>,

    /// Override the telemetry authentication token defined in the configuration
    #[arg(long)]
    telemetry_auth_token: Option<String>,

    /// Override the telemetry sample interval (seconds) defined in the configuration
    #[arg(long)]
    telemetry_sample_interval: Option<u64>,

    /// Override the log level (also respects RUST_LOG)
    #[arg(long)]
    log_level: Option<String>,

    /// Emit logs in JSON format
    #[arg(long)]
    log_json: bool,

    /// Persist the resulting configuration into the current working directory
    #[arg(long)]
    write_config: bool,
}

#[derive(Debug)]
enum ShutdownEvent {
    Runtime(std::result::Result<(), JoinError>),
    CtrlC(std::io::Result<()>),
    #[cfg(unix)]
    SigTerm(Option<i32>),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = load_configuration(&cli)?;
    apply_overrides(&mut config, &cli);

    let _telemetry_guard = init_tracing(&config, cli.log_level.clone(), cli.log_json)
        .context("failed to initialise logging")?;

    if cli.write_config {
        let path = std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join("node.toml");
        config
            .save(&path)
            .with_context(|| format!("failed to persist configuration to {}", path.display()))?;
        info!(path = %path.display(), "persisted node configuration");
    }

    let preview_node = Node::new(config.clone())
        .context("failed to build node with the provided configuration")?;
    info!(address = %preview_node.handle().address(), "node initialised");
    drop(preview_node);

    let (handle, runtime) = NodeHandle::start(config.clone())
        .await
        .context("failed to start node runtime")?;

    info!(address = %handle.address(), "node runtime started");
    info!(target = "rpc", listen = %config.rpc_listen, "rpc endpoint configured");
    if config.rollout.telemetry.enabled {
        if let Some(endpoint) = &config.rollout.telemetry.endpoint {
            info!(
                target = "telemetry",
                endpoint = %endpoint,
                sample_interval_secs = config.rollout.telemetry.sample_interval_secs,
                "telemetry endpoint configured"
            );
        } else {
            info!(
                target = "telemetry",
                sample_interval_secs = config.rollout.telemetry.sample_interval_secs,
                "telemetry enabled without explicit endpoint"
            );
        }
    } else {
        info!(target = "telemetry", "telemetry disabled");
    }
    info!(
        target = "p2p",
        listen_addr = %config.p2p.listen_addr,
        "p2p endpoint configured"
    );

    let runtime_mode = Arc::new(RwLock::new(RuntimeMode::Node));
    let rpc_context = ApiContext::new(
        Arc::clone(&runtime_mode),
        Some(handle.clone()),
        None,
        None,
        config
            .rpc_requests_per_minute
            .and_then(|limit| NonZeroU64::new(limit)),
    );

    let rpc_addr = config.rpc_listen;
    let rpc_auth = config.rpc_auth_token.clone();
    let rpc_origin = config.rpc_allowed_origin.clone();
    let rpc_task = tokio::spawn(async move {
        if let Err(err) = rpp_chain::api::serve(rpc_context, rpc_addr, rpc_auth, rpc_origin).await {
            error!(?err, "rpc server terminated");
        }
    });

    let shutdown_handle = handle.clone();
    let outcome = wait_for_shutdown(shutdown_handle, runtime).await;

    rpc_task.abort();
    if let Err(err) = rpc_task.await {
        if !err.is_cancelled() {
            warn!(?err, "rpc server join failed");
        }
    }

    match outcome {
        ShutdownOutcome::Clean => Ok(()),
        ShutdownOutcome::Errored(err) => Err(err),
    }
}

#[derive(Debug)]
enum ShutdownOutcome {
    Clean,
    Errored(anyhow::Error),
}

async fn wait_for_shutdown(
    handle: NodeHandle,
    mut runtime: tokio::task::JoinHandle<()>,
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

fn load_configuration(cli: &Cli) -> Result<NodeConfig> {
    if let Some(path) = cli.config.as_ref() {
        NodeConfig::load(path)
            .with_context(|| format!("failed to load configuration from {}", path.display()))
    } else {
        Ok(NodeConfig::default())
    }
}

fn apply_overrides(config: &mut NodeConfig, cli: &Cli) {
    if let Some(dir) = cli.data_dir.as_ref() {
        config.data_dir = dir.clone();
    }
    if let Some(addr) = cli.rpc_listen {
        config.rpc_listen = addr;
    }
    if let Some(token) = cli.rpc_auth_token.as_ref() {
        let token = token.trim();
        if token.is_empty() {
            config.rpc_auth_token = None;
        } else {
            config.rpc_auth_token = Some(token.to_string());
        }
    }
    if let Some(endpoint) = cli.telemetry_endpoint.as_ref() {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            config.rollout.telemetry.endpoint = None;
            config.rollout.telemetry.enabled = false;
        } else {
            config.rollout.telemetry.endpoint = Some(endpoint.to_string());
            config.rollout.telemetry.enabled = true;
        }
    }
    if let Some(auth) = cli.telemetry_auth_token.as_ref() {
        let token = auth.trim();
        if token.is_empty() {
            config.rollout.telemetry.auth_token = None;
        } else {
            config.rollout.telemetry.auth_token = Some(token.to_string());
        }
    }
    if let Some(interval) = cli.telemetry_sample_interval {
        config.rollout.telemetry.sample_interval_secs = interval;
        if config.rollout.telemetry.endpoint.is_some() {
            config.rollout.telemetry.enabled = true;
        }
    }
}

fn init_tracing(
    config: &NodeConfig,
    log_level: Option<String>,
    json: bool,
) -> Result<Option<OtelGuard>> {
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

    let fmt_layer = || {
        let layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_ansi(!json);
        if json {
            layer.json().flatten_event(true).boxed()
        } else {
            layer.boxed()
        }
    };

    match build_otlp_layer(config)? {
        Some(OtlpLayer {
            layer,
            guard,
            endpoint,
        }) => {
            tracing_subscriber::registry()
                .with(filter.clone())
                .with(fmt_layer())
                .with(layer)
                .try_init()?;

            let telemetry_span = info_span!(
                "node.telemetry.init",
                otlp_enabled = true,
                otlp_endpoint = endpoint.as_str()
            );
            let _span_guard = telemetry_span.enter();
            info!(target: "telemetry", otlp_endpoint = endpoint, "tracing initialised");
            Ok(Some(guard))
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer())
                .try_init()?;

            let telemetry_span = info_span!("node.telemetry.init", otlp_enabled = false);
            let _span_guard = telemetry_span.enter();
            info!(target: "telemetry", otlp_enabled = false, "tracing initialised");
            Ok(None)
        }
    }
}

struct OtelGuard;

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = global::shutdown_tracer_provider() {
            eprintln!("failed to shutdown otlp tracer provider: {err}");
        }
    }
}

struct OtlpLayer {
    layer: OpenTelemetryLayer<tracing_subscriber::Registry, Tracer>,
    guard: OtelGuard,
    endpoint: String,
}

struct OtlpSettings {
    endpoint: String,
    auth_header: Option<String>,
    timeout: Duration,
}

fn build_otlp_layer(config: &NodeConfig) -> Result<Option<OtlpLayer>> {
    let Some(settings) = otlp_settings(config)? else {
        return Ok(None);
    };

    let mut exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(settings.endpoint.clone())
        .with_timeout(settings.timeout);

    if let Some(header) = settings.auth_header.as_ref() {
        let mut metadata = MetadataMap::new();
        let value = MetadataValue::from_str(header)
            .map_err(|err| anyhow!("invalid telemetry auth token: {err}"))?;
        metadata.insert("authorization", value);
        exporter = exporter.with_metadata(metadata);
    }

    let exporter = exporter.build_span_exporter()?;
    let batch_config = BatchConfig::default()
        .with_max_queue_size(2048)
        .with_max_export_batch_size(512)
        .with_max_export_timeout(settings.timeout);

    let resource = Resource::new(vec![
        KeyValue::new("service.name", "rpp-node"),
        KeyValue::new("service.namespace", "rpp"),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
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
    ]);

    let provider = trace::TracerProvider::builder()
        .with_config(trace::Config::default().with_resource(resource))
        .with_batch_config(batch_config)
        .with_batch_exporter(exporter, Tokio)
        .build();

    let tracer = provider.tracer("rpp-node", Some(env!("CARGO_PKG_VERSION")));
    global::set_tracer_provider(provider);

    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Ok(Some(OtlpLayer {
        layer,
        guard: OtelGuard,
        endpoint: settings.endpoint,
    }))
}

fn otlp_settings(config: &NodeConfig) -> Result<Option<OtlpSettings>> {
    let telemetry = &config.rollout.telemetry;

    let endpoint_override = normalize_option(std::env::var("RPP_NODE_OTLP_ENDPOINT").ok());
    let env_endpoint = normalize_option(std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok());
    let endpoint = endpoint_override
        .clone()
        .or_else(|| normalize_option(telemetry.endpoint.clone()))
        .or(env_endpoint.clone());

    let telemetry_enabled =
        telemetry.enabled || endpoint_override.is_some() || env_endpoint.is_some();

    let Some(endpoint) = endpoint else {
        if telemetry_enabled {
            anyhow::bail!("telemetry endpoint required when OTLP is enabled");
        }
        return Ok(None);
    };

    let auth_header = normalize_option(std::env::var("RPP_NODE_OTLP_AUTH_TOKEN").ok())
        .or_else(|| normalize_option(telemetry.auth_token.clone()))
        .map(
            |token| match token.to_ascii_lowercase().starts_with("bearer ") {
                true => token,
                false => format!("Bearer {token}"),
            },
        );

    let timeout_ms = std::env::var("RPP_NODE_OTLP_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(telemetry.timeout_ms);

    Ok(Some(OtlpSettings {
        endpoint,
        auth_header,
        timeout: Duration::from_millis(timeout_ms),
    }))
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
