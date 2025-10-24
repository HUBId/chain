#![cfg(feature = "integration")]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rpp_chain::config::{NodeConfig, WalletConfig};
use tempfile::TempDir;

const INIT_TIMEOUT: Duration = Duration::from_secs(90);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);

#[test]
fn binary_mode_switch_smoke() -> Result<()> {
    let binary = locate_rpp_node_binary().context("failed to locate rpp-node binary")?;

    let specs = [
        ModeSpec {
            name: "node",
            needs_node: true,
            needs_wallet: false,
            telemetry: Some(TelemetryExpectation::Disabled),
        },
        ModeSpec {
            name: "wallet",
            needs_node: false,
            needs_wallet: true,
            telemetry: None,
        },
        ModeSpec {
            name: "hybrid",
            needs_node: true,
            needs_wallet: true,
            telemetry: Some(TelemetryExpectation::WithEndpoint),
        },
        ModeSpec {
            name: "validator",
            needs_node: true,
            needs_wallet: true,
            telemetry: Some(TelemetryExpectation::WithEndpoint),
        },
    ];

    for spec in &specs {
        run_mode_switch(&binary, spec).with_context(|| format!("mode {} failed", spec.name))?;
    }

    Ok(())
}

struct ModeSpec {
    name: &'static str,
    needs_node: bool,
    needs_wallet: bool,
    telemetry: Option<TelemetryExpectation>,
}

#[derive(Clone, Copy)]
enum TelemetryExpectation {
    Disabled,
    WithEndpoint,
}

impl TelemetryExpectation {
    fn expected_log(self) -> &'static str {
        match self {
            TelemetryExpectation::Disabled => "telemetry disabled",
            TelemetryExpectation::WithEndpoint => "telemetry endpoint configured",
        }
    }
}

struct ModeContext {
    #[allow(dead_code)]
    temp_dir: TempDir,
    node_config: Option<PathBuf>,
    wallet_config: Option<PathBuf>,
}

fn run_mode_switch(binary: &Path, spec: &ModeSpec) -> Result<()> {
    let context = ModeContext::prepare(spec)?;

    let mut command = Command::new(binary);
    command
        .arg(spec.name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(
            "RUST_LOG",
            "info,rpp_node=info,rpp-chain=info,rpp_chain=info,rpp_node::runtime=info",
        );

    if let Some(node_config) = context.node_config.as_ref() {
        command.arg("--config").arg(node_config);
    }

    if let Some(wallet_config) = context.wallet_config.as_ref() {
        let flag = match spec.name {
            "wallet" => "--config",
            _ => "--wallet-config",
        };
        command.arg(flag).arg(wallet_config);
    }

    let mut child = command.spawn().context("failed to spawn rpp-node")?;

    // Ensure the child process is terminated if the test encounters an early failure.
    let mut child_guard = ChildTerminationGuard {
        child: Some(&mut child),
    };

    let mut logs = capture_child_output(&mut child);

    wait_for_log(&mut logs, "node.telemetry.init")?;

    if let Some(expectation) = spec.telemetry {
        wait_for_log(&mut logs, expectation.expected_log())?;
    }

    if spec.needs_node {
        wait_for_log(&mut logs, "node runtime started")?;
    }

    if spec.needs_wallet {
        wait_for_log(&mut logs, "wallet runtime initialised")?;
    }

    // Drain remaining logs so the child process cannot block on a full pipe during shutdown.
    start_log_drain(logs);

    send_ctrl_c(child_guard.child.as_ref().unwrap())
        .context("failed to deliver CTRL+C to rpp-node")?;

    let status = wait_for_exit(child_guard.child.as_mut().unwrap())?;
    if !status.success() {
        return Err(anyhow!("rpp-node exited with status {status}"));
    }

    // Prevent the guard from killing the process again on drop.
    child_guard.child.take();

    Ok(())
}

#[test]
fn binary_dry_run_smoke() -> Result<()> {
    let binary = locate_rpp_node_binary().context("failed to locate rpp-node binary")?;
    let spec = ModeSpec {
        name: "node",
        needs_node: true,
        needs_wallet: false,
        telemetry: Some(TelemetryExpectation::Disabled),
    };

    let context = ModeContext::prepare(&spec)?;

    let mut command = Command::new(&binary);
    command
        .arg(spec.name)
        .arg("--dry-run")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(
            "RUST_LOG",
            "info,rpp_node=info,rpp-chain=info,rpp_chain=info,rpp_node::runtime=info",
        );

    if let Some(node_config) = context.node_config.as_ref() {
        command.arg("--config").arg(node_config);
    }

    let output = command
        .output()
        .context("failed to run rpp-node in dry-run mode")?;

    if !output.status.success() {
        return Err(anyhow!(
            "rpp-node dry run exited with status {}",
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);
    if !combined.contains("dry run completed") {
        return Err(anyhow!(
            "dry run logs did not contain confirmation marker: {combined}"
        ));
    }

    Ok(())
}

struct ChildTerminationGuard<'a> {
    child: Option<&'a mut Child>,
}

impl Drop for ChildTerminationGuard<'_> {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl ModeContext {
    fn prepare(spec: &ModeSpec) -> Result<Self> {
        let temp_dir = TempDir::new().context("failed to create temporary directory")?;
        let mut node_config = None;
        if spec.needs_node {
            let path = write_node_config(temp_dir.path(), spec.telemetry)
                .context("failed to write node configuration")?;
            node_config = Some(path);
        }

        let mut wallet_config = None;
        if spec.needs_wallet {
            let path = write_wallet_config(temp_dir.path())
                .context("failed to write wallet configuration")?;
            wallet_config = Some(path);
        }

        Ok(Self {
            temp_dir,
            node_config,
            wallet_config,
        })
    }
}

fn write_node_config(base: &Path, telemetry: Option<TelemetryExpectation>) -> Result<PathBuf> {
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
    config.p2p.listen_addr = format!("/ip4/127.0.0.1/tcp/{}", pick_free_tcp_port()?).into();
    config.rpc_listen = format!("127.0.0.1:{}", pick_free_tcp_port()?)
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

    config
        .ensure_directories()
        .context("failed to prepare node directories")?;

    let path = base.join("node-config.toml");
    config
        .save(&path)
        .with_context(|| format!("failed to save node config at {}", path.display()))?;
    Ok(path)
}

fn write_wallet_config(base: &Path) -> Result<PathBuf> {
    let mut config = WalletConfig::default();
    let wallet_root = base.join("wallet");
    config.data_dir = wallet_root.join("data");
    config.key_path = wallet_root.join("keys/wallet.toml");
    config.rpc_listen = format!("127.0.0.1:{}", pick_free_tcp_port()?)
        .parse()
        .context("invalid wallet rpc listen address")?;

    config
        .ensure_directories()
        .context("failed to prepare wallet directories")?;

    let path = base.join("wallet-config.toml");
    config
        .save(&path)
        .with_context(|| format!("failed to save wallet config at {}", path.display()))?;
    Ok(path)
}

fn capture_child_output(child: &mut Child) -> Receiver<String> {
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

fn wait_for_log(logs: &mut Receiver<String>, pattern: &str) -> Result<()> {
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
                    return Ok(());
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

fn start_log_drain(logs: Receiver<String>) {
    thread::spawn(move || for _ in logs {});
}

fn wait_for_exit(child: &mut Child) -> Result<ExitStatus> {
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

fn pick_free_tcp_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to bind ephemeral port")?;
    let port = listener
        .local_addr()
        .context("failed to read local address")?
        .port();
    drop(listener);
    Ok(port)
}

fn locate_rpp_node_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rpp-node") {
        return Ok(PathBuf::from(path));
    }

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let mut current = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !current.join("target").exists() {
        if !current.pop() {
            return Err(anyhow!("failed to locate workspace target directory"));
        }
    }

    let mut binary_path = current.join("target").join(&profile).join("rpp-node");
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
        .arg("rpp-node")
        .status()
        .context("failed to build rpp-node binary via cargo")?;

    if !status.success() {
        return Err(anyhow!("cargo failed to build rpp-node binary"));
    }

    if binary_path.exists() {
        Ok(binary_path)
    } else {
        Err(anyhow!(
            "rpp-node binary not found at {} even after building",
            binary_path.display()
        ))
    }
}

#[cfg(unix)]
fn send_ctrl_c(child: &Child) -> std::io::Result<()> {
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
fn send_ctrl_c(child: &Child) -> std::io::Result<()> {
    child.kill()
}
