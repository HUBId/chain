use std::collections::VecDeque;
use std::fmt;
use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use rpp_wallet_interface::runtime_config::{WalletConfig, WalletNodeRuntimeConfig};
use thiserror::Error;

const DEFAULT_LOG_TAIL: usize = 200;

/// Describes how the embedded node process should be launched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedNodeCommand {
    /// Executable used for spawning the embedded node.
    pub program: PathBuf,
    /// Command-line arguments passed to the embedded node.
    pub args: Vec<String>,
    /// Optional working directory for the spawned process.
    pub working_dir: Option<PathBuf>,
    /// Custom environment variables injected into the process.
    pub env: Vec<(String, String)>,
}

impl EmbeddedNodeCommand {
    /// Construct a new command with the provided executable.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            working_dir: None,
            env: Vec::new(),
        }
    }

    fn spawn(&self) -> io::Result<Child> {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        if let Some(dir) = &self.working_dir {
            command.current_dir(dir);
        }
        for (key, value) in &self.env {
            command.env(key, value);
        }
        command.spawn()
    }
}

#[derive(Clone)]
struct NodeLogBuffer {
    inner: Arc<Mutex<VecDeque<String>>>,
    redactions: Arc<Vec<String>>,
}

impl NodeLogBuffer {
    fn new(redactions: Vec<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(DEFAULT_LOG_TAIL))),
            redactions: Arc::new(redactions),
        }
    }

    fn push(&self, line: &str) {
        let mut buffer = self
            .inner
            .lock()
            .expect("embedded node log buffer mutex poisoned");
        buffer.push_back(self.redact(line));
        if buffer.len() > DEFAULT_LOG_TAIL {
            buffer.pop_front();
        }
    }

    fn snapshot(&self) -> Vec<String> {
        let buffer = self
            .inner
            .lock()
            .expect("embedded node log buffer mutex poisoned");
        buffer.iter().cloned().collect()
    }

    fn redact(&self, line: &str) -> String {
        self.redactions
            .iter()
            .filter(|secret| !secret.is_empty())
            .fold(line.to_string(), |mut current, secret| {
                current = current.replace(secret, "***");
                current
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddedNodeStatus {
    Stopped,
    Running { pid: u32 },
    Error { message: String },
}

impl Default for EmbeddedNodeStatus {
    fn default() -> Self {
        EmbeddedNodeStatus::Stopped
    }
}

impl fmt::Display for EmbeddedNodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmbeddedNodeStatus::Stopped => write!(f, "stopped"),
            EmbeddedNodeStatus::Running { pid } => write!(f, "running (pid {pid})"),
            EmbeddedNodeStatus::Error { message } => write!(f, "error: {message}"),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EmbeddedNodeError {
    #[error("embedded node runtime is disabled in wallet configuration")]
    Disabled,
    #[error("embedded node already running with pid {pid}")]
    AlreadyRunning { pid: u32 },
    #[error("port {addr} is already in use")]
    PortInUse { addr: SocketAddr },
    #[error("unable to spawn embedded node: {0}")]
    SpawnFailed(String),
    #[error("failed to shutdown embedded node: {0}")]
    ShutdownFailed(String),
}

struct EmbeddedNodeState {
    status: EmbeddedNodeStatus,
    child: Option<Child>,
    log_task: Option<JoinHandle<()>>,
}

impl Default for EmbeddedNodeState {
    fn default() -> Self {
        Self {
            status: EmbeddedNodeStatus::Stopped,
            child: None,
            log_task: None,
        }
    }
}

/// Thread-safe lifecycle handle for an embedded node process.
#[derive(Clone)]
pub struct EmbeddedNodeLifecycle {
    command: EmbeddedNodeCommand,
    node_config: WalletNodeRuntimeConfig,
    ports: Vec<SocketAddr>,
    logs: NodeLogBuffer,
    state: Arc<Mutex<EmbeddedNodeState>>,
}

impl EmbeddedNodeLifecycle {
    /// Construct a new lifecycle handle for the provided node command and configuration.
    pub fn new(
        node_config: WalletNodeRuntimeConfig,
        command: EmbeddedNodeCommand,
        ports: Vec<SocketAddr>,
        redactions: Vec<String>,
    ) -> Self {
        Self {
            command,
            node_config,
            ports,
            logs: NodeLogBuffer::new(redactions),
            state: Arc::new(Mutex::new(EmbeddedNodeState::default())),
        }
    }

    /// Build a lifecycle handle from a wallet configuration, respecting the `[wallet.node]` settings.
    pub fn from_wallet_config(config: &WalletConfig, command: EmbeddedNodeCommand) -> Option<Self> {
        if !config.node.embedded {
            return None;
        }

        let mut redactions = Vec::new();
        if let Some(token) = config.wallet.auth.token.as_ref() {
            redactions.push(token.clone());
        }

        Some(Self::new(
            config.node.clone(),
            command,
            vec![config.wallet.rpc.listen],
            redactions,
        ))
    }

    /// Start the embedded node process if enabled.
    pub fn start(&self) -> Result<EmbeddedNodeStatus, EmbeddedNodeError> {
        if !self.node_config.embedded {
            return Err(EmbeddedNodeError::Disabled);
        }

        self.ensure_ports_available()?;

        let mut state = self
            .state
            .lock()
            .expect("embedded node lifecycle mutex poisoned");

        if let EmbeddedNodeStatus::Running { pid } = state.status {
            return Err(EmbeddedNodeError::AlreadyRunning { pid });
        }

        let mut child = self
            .command
            .spawn()
            .map_err(|err| EmbeddedNodeError::SpawnFailed(err.to_string()))?;
        let pid = child.id();
        let log_task = spawn_log_tail(&mut child, self.logs.clone());
        state.child = Some(child);
        state.log_task = log_task;
        state.status = EmbeddedNodeStatus::Running { pid };
        Ok(state.status.clone())
    }

    /// Stop the embedded node process, killing it if needed.
    pub fn stop(&self) -> Result<(), EmbeddedNodeError> {
        let mut state = self
            .state
            .lock()
            .expect("embedded node lifecycle mutex poisoned");

        if let Some(mut child) = state.child.take() {
            if let Err(err) = child.kill() {
                return Err(EmbeddedNodeError::ShutdownFailed(err.to_string()));
            }
            if let Err(err) = child.wait() {
                return Err(EmbeddedNodeError::ShutdownFailed(err.to_string()));
            }
        }

        if let Some(handle) = state.log_task.take() {
            let _ = handle.join();
        }

        state.status = EmbeddedNodeStatus::Stopped;
        Ok(())
    }

    /// Retrieve the latest lifecycle status.
    pub fn status(&self) -> EmbeddedNodeStatus {
        let mut state = self
            .state
            .lock()
            .expect("embedded node lifecycle mutex poisoned");
        if let (EmbeddedNodeStatus::Running { .. }, Some(child)) =
            (&state.status, state.child.as_mut())
        {
            if let Ok(Some(_)) = child.try_wait() {
                state.status = EmbeddedNodeStatus::Stopped;
                state.child = None;
            }
        }
        state.status.clone()
    }

    /// Return the most recent log lines with secrets redacted.
    pub fn log_tail(&self) -> Vec<String> {
        self.logs.snapshot()
    }

    fn ensure_ports_available(&self) -> Result<(), EmbeddedNodeError> {
        for addr in &self.ports {
            if addr.port() == 0 {
                continue;
            }
            if TcpListener::bind(addr).is_err() {
                return Err(EmbeddedNodeError::PortInUse { addr: *addr });
            }
        }
        Ok(())
    }
}

fn spawn_log_tail(child: &mut Child, logs: NodeLogBuffer) -> Option<JoinHandle<()>> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    if stdout.is_none() && stderr.is_none() {
        return None;
    }

    Some(std::thread::spawn(move || {
        let mut readers: Vec<Box<dyn BufRead + Send>> = Vec::new();
        if let Some(stdout) = stdout {
            readers.push(Box::new(BufReader::new(stdout)));
        }
        if let Some(stderr) = stderr {
            readers.push(Box::new(BufReader::new(stderr)));
        }

        loop {
            let mut active = 0;
            for reader in readers.iter_mut() {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {}
                    Ok(_) => {
                        if let Some(stripped) = line.strip_suffix('\n') {
                            logs.push(stripped);
                        } else {
                            logs.push(&line);
                        }
                        active += 1;
                    }
                    Err(_) => {}
                }
            }
            if active == 0 {
                break;
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Duration;

    fn lifecycle_with_command(command: &str) -> EmbeddedNodeLifecycle {
        let mut node_command = EmbeddedNodeCommand::new("sh");
        node_command.args = vec!["-c".into(), command.into()];
        let config = WalletNodeRuntimeConfig {
            embedded: true,
            gossip_endpoints: Vec::new(),
        };
        EmbeddedNodeLifecycle::new(config, node_command, Vec::new(), vec!["SECRET".into()])
    }

    #[test]
    fn starts_and_captures_logs() {
        let lifecycle = lifecycle_with_command("echo SECRET && sleep 1");

        let status = lifecycle.start().expect("start embedded node");
        assert!(matches!(status, EmbeddedNodeStatus::Running { .. }));

        std::thread::sleep(Duration::from_millis(50));
        lifecycle.stop().expect("stop embedded node");

        let tail = lifecycle.log_tail();
        assert!(tail.iter().any(|line| line.contains("***")));
        assert!(tail.iter().all(|line| !line.contains("SECRET")));
        assert!(matches!(lifecycle.status(), EmbeddedNodeStatus::Stopped));
    }

    #[test]
    fn detects_already_running_instance() {
        let lifecycle = lifecycle_with_command("sleep 1");

        lifecycle.start().expect("start embedded node");
        let error = lifecycle.start().expect_err("second start should fail");

        assert!(matches!(error, EmbeddedNodeError::AlreadyRunning { .. }));
        lifecycle.stop().expect("stop embedded node");
    }

    #[test]
    fn rejects_port_collisions() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("listener address");

        let mut node_command = EmbeddedNodeCommand::new("sh");
        node_command.args = vec!["-c".into(), "sleep 1".into()];
        let config = WalletNodeRuntimeConfig {
            embedded: true,
            gossip_endpoints: Vec::new(),
        };
        let lifecycle = EmbeddedNodeLifecycle::new(config, node_command, vec![addr], Vec::new());

        let error = lifecycle.start().expect_err("port collision should fail");
        assert!(matches!(error, EmbeddedNodeError::PortInUse { addr: err } if err == addr));
    }

    #[test]
    fn skips_disabled_embedded_config() {
        let command = EmbeddedNodeCommand::new("sh");
        let config = WalletConfig::default();

        assert!(EmbeddedNodeLifecycle::from_wallet_config(&config, command).is_none());
    }

    #[test]
    fn builds_from_wallet_config_with_redaction() {
        let mut config = WalletConfig::default();
        config.node.embedded = true;
        config.wallet.rpc.listen = "127.0.0.1:0".parse().unwrap();
        config.wallet.auth.token = Some("TOPSECRET".into());

        let mut command = EmbeddedNodeCommand::new("sh");
        command.args = vec!["-c".into(), "echo TOPSECRET && sleep 1".into()];

        let lifecycle =
            EmbeddedNodeLifecycle::from_wallet_config(&config, command).expect("lifecycle");
        lifecycle.start().expect("start embedded node");
        std::thread::sleep(Duration::from_millis(50));
        lifecycle.stop().expect("stop embedded node");

        let tail = lifecycle.log_tail();
        assert!(tail.iter().any(|line| line.contains("***")));
        assert!(tail.iter().all(|line| !line.contains("TOPSECRET")));
    }
}
