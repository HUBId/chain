//! Helpers shared across observability-focused integration tests.

use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rpp_chain::config::{NodeConfig, WalletConfig};
use tempfile::TempDir;

/// Timeout applied when waiting for an rpp-node instance to emit its startup logs.
pub const INIT_TIMEOUT: Duration = Duration::from_secs(90);

/// Timeout applied when waiting for an rpp-node instance to shut down gracefully.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone, Copy)]
pub enum TelemetryExpectation {
    Disabled,
    WithEndpoint,
}

impl TelemetryExpectation {
    pub fn expected_log(self) -> &'static str {
        match self {
            TelemetryExpectation::Disabled => "telemetry disabled",
            TelemetryExpectation::WithEndpoint => "telemetry endpoint configured",
        }
    }
}

/// Manages configuration files and temporary directories for integration tests.
pub struct ModeContext {
    temp_dir: TempDir,
    node_config: Option<PathBuf>,
    wallet_config: Option<PathBuf>,
}

impl ModeContext {
    pub fn prepare(
        needs_node: bool,
        needs_wallet: bool,
        telemetry: Option<TelemetryExpectation>,
    ) -> Result<Self> {
        let temp_dir = TempDir::new().context("failed to create temporary directory")?;
        let mut node_config = None;
        let mut ports = PortAllocator::default();
        if needs_node {
            let path = write_node_config(temp_dir.path(), telemetry, &mut ports)
                .context("failed to write node configuration")?;
            node_config = Some(path);
        }

        let mut wallet_config = None;
        if needs_wallet {
            let path = write_wallet_config(temp_dir.path(), &mut ports)
                .context("failed to write wallet configuration")?;
            wallet_config = Some(path);
        }

        Ok(Self {
            temp_dir,
            node_config,
            wallet_config,
        })
    }

    pub fn node_config(&self) -> Option<&PathBuf> {
        self.node_config.as_ref()
    }

    pub fn wallet_config(&self) -> Option<&PathBuf> {
        self.wallet_config.as_ref()
    }
}

#[derive(Default)]
pub struct PortAllocator {
    reserved: HashSet<u16>,
}

impl PortAllocator {
    pub fn next_port(&mut self) -> Result<u16> {
        loop {
            let port = pick_free_tcp_port()?;
            if self.reserved.insert(port) {
                return Ok(port);
            }
        }
    }

    pub fn reserve(&mut self, port: u16) {
        self.reserved.insert(port);
    }
}

pub struct ChildTerminationGuard<'a> {
    pub child: Option<&'a mut Child>,
}

impl Drop for ChildTerminationGuard<'_> {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn write_node_config(
    base: &Path,
    telemetry: Option<TelemetryExpectation>,
    ports: &mut PortAllocator,
) -> Result<PathBuf> {
    write_node_config_with(base, telemetry, ports, |_| {})
}

pub fn write_node_config_with(
    base: &Path,
    telemetry: Option<TelemetryExpectation>,
    ports: &mut PortAllocator,
    mut update: impl FnOnce(&mut NodeConfig),
) -> Result<PathBuf> {
    let mut config = NodeConfig::default();
    let node_root = base.join("node");
    let key_root = node_root.join("keys");
    config.data_dir = node_root.join("data");
    config.key_path = key_root.join("node.toml");
    config.p2p_key_path = key_root.join("p2p.toml");
    config.vrf_key_path = key_root.join("vrf.toml");
    config.snapshot_dir = node_root.join("snapshots");
    config.proof_cache_dir = node_root.join("proofs");
    config.consensus_pipeline_path = node_root.join("consensus/pipeline.json");
    config.p2p.peerstore_path = node_root.join("p2p/peerstore.json");
    config.p2p.gossip_path = Some(node_root.join("p2p/gossip.json"));
    config.p2p.listen_addr =
        format!("/ip4/127.0.0.1/tcp/{}", ports.next_port()?).into();
    config.rpc_listen = format!("127.0.0.1:{}", ports.next_port()?)
        .parse()
        .context("invalid rpc listen address")?;

    match telemetry {
        Some(TelemetryExpectation::Disabled) | None => {
            config.rollout.telemetry.enabled = false;
            config.rollout.telemetry.endpoint = None;
        }
        Some(TelemetryExpectation::WithEndpoint) => {
            config.rollout.telemetry.enabled = true;
            config.rollout.telemetry.endpoint = Some("http://127.0.0.1:4317".to_string());
            config.rollout.telemetry.auth_token = Some("test-token".to_string());
            config.rollout.telemetry.sample_interval_secs = 5;
            config.rollout.telemetry.redact_logs = false;
        }
    }

    update(&mut config);
    ports.reserve(config.rpc_listen.port());
    if let Some(port) = extract_port(config.p2p.listen_addr.to_string()) {
        ports.reserve(port);
    }

    config
        .ensure_directories()
        .context("failed to prepare node directories")?;

    let path = base.join("node-config.toml");
    config
        .save(&path)
        .with_context(|| format!("failed to save node config at {}", path.display()))?;
    Ok(path)
}

pub fn write_wallet_config(base: &Path, ports: &mut PortAllocator) -> Result<PathBuf> {
    write_wallet_config_with(base, ports, |_| {})
}

pub fn write_wallet_config_with(
    base: &Path,
    ports: &mut PortAllocator,
    mut update: impl FnOnce(&mut WalletConfig),
) -> Result<PathBuf> {
    let mut config = WalletConfig::default();
    let wallet_root = base.join("wallet");
    config.data_dir = wallet_root.join("data");
    config.wallet.keys.key_path = wallet_root.join("keys/wallet.toml");
    config.wallet.rpc.listen = format!("127.0.0.1:{}", ports.next_port()?)
        .parse()
        .context("invalid wallet rpc listen address")?;

    update(&mut config);
    ports.reserve(config.wallet.rpc.listen.port());

    config
        .ensure_directories()
        .context("failed to prepare wallet directories")?;

    let path = base.join("wallet-config.toml");
    config
        .save(&path)
        .with_context(|| format!("failed to save wallet config at {}", path.display()))?;
    Ok(path)
}

fn extract_port(address: String) -> Option<u16> {
    address
        .rsplit('/')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
}

pub fn capture_child_output(child: &mut Child) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();

    if let Some(stdout) = child.stdout.take() {
        spawn_reader(stdout, tx.clone());
    }

    if let Some(stderr) = child.stderr.take() {
        spawn_reader(stderr, tx.clone());
    }

    rx
}

fn spawn_reader<R>(reader: R, tx: mpsc::Sender<String>)
where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || {
        let lines = BufReader::new(reader).lines();
        for line in lines.flatten() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
}

pub fn wait_for_log(logs: &mut Receiver<String>, pattern: &str) -> Result<String> {
    let deadline = Instant::now() + INIT_TIMEOUT;
    let mut collected = Vec::new();

    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_else(|| Duration::from_secs(0));

        match logs.recv_timeout(remaining) {
            Ok(line) => {
                collected.push(line.clone());
                if line.contains(pattern) {
                    return Ok(line);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(anyhow!(
                    "timed out waiting for log pattern `{pattern}`; collected logs: {collected:?}"
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow!(
                    "log stream ended before pattern `{pattern}` appeared; collected logs: {collected:?}"
                ));
            }
        }
    }
}

pub fn wait_for_pipeline_marker(logs: &mut Receiver<String>, pipeline: &str) -> Result<String> {
    let pattern = format!("pipeline=\\\"{pipeline}\\\" started");

    loop {
        let line = wait_for_log(logs, &pattern)?;
        if line.contains(&pattern) {
            return Ok(line);
        }
    }
}

pub fn start_log_drain(logs: Receiver<String>) {
    thread::spawn(move || for _ in logs {});
}

pub fn wait_for_exit(child: &mut Child) -> Result<ExitStatus> {
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("failed to poll child status")? {
            return Ok(status);
        }

        if Instant::now() >= deadline {
            return Err(anyhow!("timed out waiting for rpp-node to exit"));
        }

        thread::sleep(Duration::from_millis(100));
    }
}

pub fn pick_free_tcp_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to bind ephemeral port")?;
    let port = listener
        .local_addr()
        .context("failed to read local address")?
        .port();
    drop(listener);
    Ok(port)
}

pub fn locate_rpp_node_binary() -> Result<PathBuf> {
    locate_binary("rpp-node")
}

pub fn locate_binary(name: &str) -> Result<PathBuf> {
    let env_key = format!("CARGO_BIN_EXE_{name}");
    if let Ok(path) = std::env::var(&env_key) {
        return Ok(PathBuf::from(path));
    }

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let mut current = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !current.join("target").exists() {
        if !current.pop() {
            return Err(anyhow!("failed to locate workspace target directory"));
        }
    }

    let mut binary_path = current.join("target").join(&profile).join(name);
    if cfg!(windows) {
        binary_path.set_extension("exe");
    }

    if binary_path.exists() {
        return Ok(binary_path);
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .arg("build")
        .arg("--profile")
        .arg(&profile)
        .arg("--bin")
        .arg(name)
        .status()
        .with_context(|| format!("failed to build {name} binary via cargo"))?;

    if !status.success() {
        return Err(anyhow!("cargo failed to build {name} binary"));
    }

    if binary_path.exists() {
        Ok(binary_path)
    } else {
        Err(anyhow!(
            "{name} binary not found at {} even after building",
            binary_path.display()
        ))
    }
}

#[cfg(unix)]
pub fn send_ctrl_c(child: &Child) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};

    let id = child
        .id()
        .ok_or_else(|| Error::new(ErrorKind::Other, "child process is not running"))?;

    let result = unsafe { libc::kill(id as libc::pid_t, libc::SIGINT) };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn send_ctrl_c(child: &Child) -> std::io::Result<()> {
    child.kill()
}
