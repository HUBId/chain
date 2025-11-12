#![cfg(feature = "integration")]

use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use tempfile::TempDir;

mod support;

use support::{
    capture_child_output, locate_rpp_node_binary, seeded_rng, start_log_drain, wait_for_exit,
    wait_for_log, write_node_config, ChildTerminationGuard, PortAllocator, TelemetryExpectation,
};

#[test]
fn config_merge_sources() -> Result<()> {
    let mut _rng = seeded_rng("config_merge_sources");
    let binary = locate_rpp_node_binary().context("failed to locate rpp-node binary")?;

    run_cli_config_case(&binary)?;
    run_env_config_case(&binary)?;
    run_default_template_case(&binary)?;
    run_cli_ring_size_override_case(&binary)?;
    run_env_ring_size_override_case(&binary)?;
    run_missing_cli_config_case(&binary)?;

    Ok(())
}

fn run_cli_config_case(binary: &Path) -> Result<()> {
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let mut ports = PortAllocator::default();
    let config_path = write_node_config(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
    )?;

    let _ = run_success_case(binary, Some(config_path.as_path()), None, "cli")?;
    Ok(())
}

fn run_env_config_case(binary: &Path) -> Result<()> {
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let mut ports = PortAllocator::default();
    let config_path = write_node_config(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
    )?;

    let _ = run_success_case(binary, None, Some(config_path.as_path()), "env")?;
    Ok(())
}

fn run_default_template_case(binary: &Path) -> Result<()> {
    let json = run_success_case(binary, None, None, "default")?;
    assert!(
        json.get("storage_io_uring_ring_entries").is_some(),
        "dry run log should include storage ring size field: {json}"
    );
    Ok(())
}

fn dry_run_with_overrides(
    binary: &Path,
    cli_config: Option<&Path>,
    env_config: Option<&Path>,
    configure_command: impl FnOnce(&mut Command),
) -> Result<Value> {
    let mut command = Command::new(binary);
    command
        .arg("node")
        .arg("--dry-run")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(
            "RUST_LOG",
            "info,rpp-node=info,rpp_chain=info,rpp_chain=info,rpp_node::runtime=info",
        )
        .env_remove("RPP_CONFIG");

    let _env_guard = EnvVarGuard::set_path("RPP_CONFIG", env_config);

    if let Some(path) = cli_config {
        command.arg("--node-config").arg(path);
    }

    if let Some(path) = env_config {
        command.env("RPP_CONFIG", path);
    }

    configure_command(&mut command);

    let mut child = command.spawn().context("failed to spawn rpp-node")?;
    let mut guard = ChildTerminationGuard {
        child: Some(&mut child),
    };

    let mut logs = capture_child_output(&mut child);
    let dry_run_log = wait_for_log(&mut logs, "dry run completed")?;
    let json: Value = serde_json::from_str(&dry_run_log)
        .with_context(|| format!("failed to parse structured log: {dry_run_log}"))?;

    start_log_drain(logs);

    let status = wait_for_exit(&mut child)?;
    if !status.success() {
        return Err(anyhow!(
            "dry run completed log emitted but process exited with status {status}"
        ));
    }

    guard.child.take();
    Ok(json)
}

fn run_success_case(
    binary: &Path,
    cli_config: Option<&Path>,
    env_config: Option<&Path>,
    expected_source: &str,
) -> Result<Value> {
    let json = dry_run_with_overrides(binary, cli_config, env_config, |_| {})?;

    let source = json
        .get("rpp.config_source")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert_eq!(
        source, expected_source,
        "dry run completed log reported unexpected config source",
    );

    let message = json.get("msg").and_then(Value::as_str).unwrap_or_default();
    assert!(
        message.contains("dry run completed"),
        "dry run completed log missing expected message: {message}",
    );

    Ok(json)
}

fn run_missing_cli_config_case(binary: &Path) -> Result<()> {
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let missing_path = temp_dir.path().join("missing/config.toml");

    let _env_guard = EnvVarGuard::set_path("RPP_CONFIG", None);

    let output = Command::new(binary)
        .arg("node")
        .arg("--dry-run")
        .arg("--node-config")
        .arg(&missing_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("RPP_CONFIG")
        .output()
        .context("failed to execute rpp-node with missing config path")?;

    match output.status.code() {
        Some(2) => {}
        other => {
            return Err(anyhow!(
                "expected exit code 2 for missing configuration, got {other:?}",
            ));
        }
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let expected_path = format!("node configuration not found at {}", missing_path.display());
    assert!(
        stderr.contains(&expected_path),
        "stderr missing configuration path: {stderr}"
    );
    assert!(
        stderr.contains("resolved from the command line"),
        "stderr missing configuration source: {stderr}"
    );

    Ok(())
}

fn run_cli_ring_size_override_case(binary: &Path) -> Result<()> {
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let mut ports = PortAllocator::default();
    let config_path = write_node_config(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
    )?;

    let json = dry_run_with_overrides(binary, Some(config_path.as_path()), None, |command| {
        command.arg("--storage-ring-size").arg("64");
    })?;

    let ring_size = json
        .get("storage_io_uring_ring_entries")
        .and_then(Value::as_u64)
        .context("dry run log missing storage ring size")?;
    assert_eq!(
        ring_size, 64,
        "cli override should appear in dry run log: {json}"
    );

    Ok(())
}

fn run_env_ring_size_override_case(binary: &Path) -> Result<()> {
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let mut ports = PortAllocator::default();
    let config_path = write_node_config(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
    )?;

    let json = dry_run_with_overrides(binary, None, Some(config_path.as_path()), |command| {
        command.env("RPP_NODE_STORAGE_RING_SIZE", "128");
    })?;

    let ring_size = json
        .get("storage_io_uring_ring_entries")
        .and_then(Value::as_u64)
        .context("dry run log missing storage ring size")?;
    assert_eq!(
        ring_size, 128,
        "env override should appear in dry run log: {json}"
    );

    Ok(())
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn set_path(key: &'static str, value: Option<&Path>) -> Self {
        let previous = env::var_os(key);
        match value {
            Some(path) => env::set_var(key, path),
            None => env::remove_var(key),
        }

        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            env::set_var(self.key, previous);
        } else {
            env::remove_var(self.key);
        }
    }
}
