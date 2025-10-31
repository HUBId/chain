#![cfg(unix)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use libc;
use rpp_chain::config::{NodeConfig, WalletConfig};
use rpp_node::config::PruningCliOverrides;
use rpp_node::{RuntimeMode, RuntimeOptions};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{timeout, Instant};

const HEALTH_TIMEOUT: Duration = Duration::from_secs(120);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_roundtrip_resolves_relative_paths() -> Result<()> {
    let _guard = env_lock().lock().expect("env mutex");
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let configs_dir = temp_dir.path().join("configs");
    fs::create_dir_all(&configs_dir).context("failed to create configs directory")?;

    let repo = repo_root();
    copy_file(&repo, "config/node.toml", configs_dir.join("node.toml"))?;
    copy_file(
        &repo,
        "config/malachite.toml",
        configs_dir.join("malachite.toml"),
    )?;

    let mut options = base_runtime_options();
    options.config = Some(PathBuf::from("configs/node.toml"));
    options.data_dir = Some(PathBuf::from("state"));
    options.write_config = true;
    options.dry_run = true;

    let previous_dir = std::env::current_dir().context("failed to capture current directory")?;
    std::env::set_current_dir(temp_dir.path()).context("failed to enter temp directory")?;
    let result = rpp_node::run(RuntimeMode::Node, options).await;
    std::env::set_current_dir(previous_dir).context("failed to restore working directory")?;
    result?;

    let stray = temp_dir.path().join("node.toml");
    assert!(
        !stray.exists(),
        "expected configuration to be persisted next to the relative path, found stray file at {}",
        stray.display()
    );

    let persisted = configs_dir.join("node.toml");
    let config_content = fs::read_to_string(&persisted)
        .with_context(|| format!("failed to read persisted config at {}", persisted.display()))?;
    assert!(
        config_content.contains("data_dir = \"state\""),
        "expected CLI overrides to round-trip into persisted config: {config_content}"
    );

    Ok(())
}

#[tokio::test]
async fn hybrid_listener_conflict_is_reported() -> Result<()> {
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let configs_dir = temp_dir.path().join("configs");
    fs::create_dir_all(&configs_dir).context("failed to create configs directory")?;

    let repo = repo_root();
    copy_file(
        &repo,
        "config/malachite.toml",
        configs_dir.join("malachite.toml"),
    )?;

    let mut node_config = NodeConfig::for_mode(RuntimeMode::Hybrid);
    let node_config_path = configs_dir.join("hybrid-node.toml");
    node_config.save(&node_config_path).with_context(|| {
        format!(
            "failed to persist node config at {}",
            node_config_path.display()
        )
    })?;

    let mut wallet_config = WalletConfig::for_mode(RuntimeMode::Hybrid);
    wallet_config.wallet.rpc.listen = node_config.network.rpc.listen;
    let wallet_config_path = configs_dir.join("hybrid-wallet.toml");
    wallet_config.save(&wallet_config_path).with_context(|| {
        format!(
            "failed to persist wallet config at {}",
            wallet_config_path.display()
        )
    })?;

    let mut options = base_runtime_options();
    options.config = Some(node_config_path);
    options.wallet_config = Some(wallet_config_path);
    options.dry_run = true;

    let error = rpp_node::run(RuntimeMode::Hybrid, options)
        .await
        .expect_err("conflicting listeners should fail the bootstrap phase");
    let message = error.to_string();
    assert!(
        message.contains("listener conflict"),
        "expected listener conflict in error message, got: {message}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_script_handles_shutdown_signal() -> Result<()> {
    let _guard = env_lock().lock().expect("env mutex");
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let repo = repo_root();
    let script_path = repo.join("scripts/run_node_mode.sh");
    let binary_path = assert_cmd::cargo::cargo_bin("rpp-node");

    let mut command = Command::new(&script_path);
    command
        .env("RPP_NODE_BIN", &binary_path)
        .current_dir(temp_dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .context("failed to launch node mode helper script")?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing stderr pipe"))?;

    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(_)) = lines.next_line().await {}
    });

    let mut lines = BufReader::new(stdout).lines();
    let deadline = Instant::now() + HEALTH_TIMEOUT;
    let mut ready = false;
    while Instant::now() < deadline {
        if let Some(line) = lines
            .next_line()
            .await
            .context("failed to read script output")?
        {
            if line.contains("runtime ready") {
                ready = true;
                break;
            }
        } else {
            break;
        }
    }
    assert!(
        ready,
        "helper script did not report readiness before timeout"
    );

    send_ctrl_c(&child).context("failed to send SIGINT to helper script")?;
    let status = timeout(SHUTDOWN_TIMEOUT, child.wait())
        .await
        .context("helper script did not exit in time")??;
    if !status.success() {
        anyhow::bail!("helper script exited unsuccessfully: {status}");
    }

    Ok(())
}

fn base_runtime_options() -> RuntimeOptions {
    RuntimeOptions {
        config: None,
        wallet_config: None,
        data_dir: None,
        rpc_listen: None,
        rpc_auth_token: None,
        telemetry_endpoint: None,
        telemetry_auth_token: None,
        telemetry_sample_interval: None,
        log_level: None,
        log_json: false,
        dry_run: false,
        write_config: false,
        pruning: PruningCliOverrides::default(),
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn copy_file(repo: &Path, relative: &str, destination: PathBuf) -> Result<()> {
    let source = repo.join(relative);
    fs::copy(&source, &destination).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
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
