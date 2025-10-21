#![cfg(unix)]

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use assert_cmd::cargo::CommandCargoExt;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::timeout;

use rpp_chain::config::NodeConfig;

const INIT_TIMEOUT: Duration = Duration::from_secs(60);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_smoke_shutdown() -> Result<()> {
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let config_path = write_configuration(temp_dir.path(), false)?;

    let mut child = spawn_node(&config_path, &[]).await?;
    let mut logs = capture_child_output(&mut child);
    wait_for_log_line(&mut logs, "node runtime started").await?;

    // Continue draining logs in the background to avoid filling the pipes while the process shuts down.
    let _ = tokio::spawn(async move { while let Some(_line) = logs.recv().await {} });

    send_ctrl_c(&child).context("failed to send SIGINT to node process")?;
    verify_clean_exit(child).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_smoke_shutdown_with_telemetry() -> Result<()> {
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let config_path = write_configuration(temp_dir.path(), true)?;

    let mut child = spawn_node(
        &config_path,
        &["--telemetry-endpoint", "http://127.0.0.1:0/collect"],
    )
    .await?;
    let mut logs = capture_child_output(&mut child);
    wait_for_log_line(&mut logs, "telemetry endpoint configured").await?;

    let _ = tokio::spawn(async move { while let Some(_line) = logs.recv().await {} });

    send_ctrl_c(&child).context("failed to send SIGINT to node process")?;
    verify_clean_exit(child).await
}

async fn spawn_node(config_path: &Path, extra_args: &[&str]) -> Result<Child> {
    let binary = assert_cmd::cargo::cargo_bin("rpp-node");

    let mut command = Command::new(binary);
    command
        .kill_on_drop(true)
        .arg("--config")
        .arg(config_path)
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("RUST_LOG", "info,rpp-node=info,rpp_chain=info");

    for arg in extra_args {
        command.arg(arg);
    }

    command.spawn().context("failed to spawn node process")
}

fn capture_child_output(child: &mut Child) -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();

    if let Some(stdout) = child.stdout.take() {
        let tx = tx.clone();
        tokio::spawn(async move {
            forward_lines(stdout, tx).await;
        });
    }

    if let Some(stderr) = child.stderr.take() {
        let tx = tx.clone();
        tokio::spawn(async move {
            forward_lines(stderr, tx).await;
        });
    }

    rx
}

async fn forward_lines<R>(reader: R, tx: mpsc::UnboundedSender<String>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if tx.send(line).is_err() {
            break;
        }
    }
}

async fn wait_for_log_line(
    logs: &mut mpsc::UnboundedReceiver<String>,
    pattern: &str,
) -> Result<()> {
    let mut collected = Vec::new();

    timeout(INIT_TIMEOUT, async {
        while let Some(line) = logs.recv().await {
            collected.push(line.clone());
            if line.contains(pattern) {
                return Ok(());
            }
        }
        Err(anyhow!("log stream ended before pattern appeared"))
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for log pattern: {pattern}"))?
    .with_context(|| format!("logs observed before failure: {:?}", collected))?
}

fn write_configuration(base: &Path, telemetry: bool) -> Result<PathBuf> {
    let mut config = NodeConfig::default();
    config.data_dir = base.join("data");
    config.key_path = base.join("keys/node.toml");
    config.p2p_key_path = base.join("keys/p2p.toml");
    config.vrf_key_path = base.join("keys/vrf.toml");
    config.snapshot_dir = base.join("snapshots");
    config.proof_cache_dir = base.join("proofs");

    config.p2p.peerstore_path = base.join("p2p/peerstore.json");
    config.p2p.gossip_path = Some(base.join("p2p/gossip.json"));
    config.p2p.listen_addr = format!("/ip4/127.0.0.1/tcp/{}", pick_free_tcp_port()?);

    config.rpc_listen = format!("127.0.0.1:{}", pick_free_tcp_port()?)
        .parse()
        .context("failed to parse rpc listen address")?;

    if telemetry {
        config.rollout.telemetry.enabled = true;
        config.rollout.telemetry.endpoint = Some("http://127.0.0.1:1/telemetry".to_string());
        config.rollout.telemetry.auth_token = Some("test-token".to_string());
        config.rollout.telemetry.sample_interval_secs = 1;
        config.rollout.telemetry.redact_logs = false;
    }

    let config_path = base.join("config.toml");
    config.save(&config_path).with_context(|| {
        format!(
            "failed to persist configuration at {}",
            config_path.display()
        )
    })?;

    Ok(config_path)
}

fn pick_free_tcp_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("failed to bind to an ephemeral TCP port")?;
    let port = listener
        .local_addr()
        .context("failed to determine local socket address")?
        .port();
    drop(listener);
    Ok(port)
}

fn send_ctrl_c(child: &Child) -> io::Result<()> {
    let id = child
        .id()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "child process is not running"))?;

    let result = unsafe { libc::kill(id as libc::pid_t, libc::SIGINT) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

async fn verify_clean_exit(mut child: Child) -> Result<()> {
    let status = timeout(SHUTDOWN_TIMEOUT, child.wait())
        .await
        .context("node process did not exit in time")??;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("node process exited unsuccessfully: {status}"))
    }
}
