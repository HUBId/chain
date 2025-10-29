#![cfg(feature = "integration")]

//! Integration smoke tests for the rpp-node binary.
//!
//! The telemetry assertions are gated behind the `RPP_OBSERVABILITY_ASSERTS`
//! environment variable so CI jobs can opt in to deeper OTLP validation without
//! paying the cost on every run.

use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{anyhow, Context, Result};
use tempfile::TempDir;

mod support;

use support::{
    capture_child_output, locate_rpp_node_binary, pick_free_tcp_port, send_ctrl_c, start_log_drain,
    wait_for_exit, wait_for_log, wait_for_pipeline_marker, write_node_config,
    write_node_config_with, write_wallet_config, write_wallet_config_with, ChildTerminationGuard,
    ModeContext, PortAllocator, TelemetryExpectation,
};

const OBSERVABILITY_ENV: &str = "RPP_OBSERVABILITY_ASSERTS";

#[test]
fn binary_mode_switch_smoke() -> Result<()> {
    let binary = locate_rpp_node_binary().context("failed to locate rpp-node binary")?;

    let specs = [
        ModeSpec {
            name: "node",
            needs_node: true,
            needs_wallet: false,
            telemetry: Some(TelemetryExpectation::Disabled),
            config_source: "cli",
            pipelines: &["node"],
        },
        ModeSpec {
            name: "wallet",
            needs_node: false,
            needs_wallet: true,
            telemetry: None,
            config_source: "none",
            pipelines: &["wallet"],
        },
        ModeSpec {
            name: "hybrid",
            needs_node: true,
            needs_wallet: true,
            telemetry: Some(TelemetryExpectation::WithEndpoint),
            config_source: "cli",
            pipelines: &["node", "wallet"],
        },
        ModeSpec {
            name: "validator",
            needs_node: true,
            needs_wallet: true,
            telemetry: Some(TelemetryExpectation::WithEndpoint),
            config_source: "cli",
            pipelines: &["node", "wallet"],
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
    config_source: &'static str,
    pipelines: &'static [&'static str],
}

fn observability_assertions_enabled() -> bool {
    match env::var(OBSERVABILITY_ENV) {
        Ok(value) => matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn assert_observability_attributes(log: &str, spec: &ModeSpec) {
    let expectations = [
        ("service.name", "rpp"),
        ("service.component", "rpp-node"),
        ("service.namespace", "rpp"),
        ("rpp.mode", spec.name),
        ("rpp.config_source", spec.config_source),
    ];

    for (key, value) in expectations {
        let pattern = format!("\"{key}\":\"{value}\"");
        assert!(
            log.contains(&pattern),
            "telemetry log missing attribute {pattern}: {log}",
            pattern = pattern,
            log = log
        );
    }

    assert!(
        log.contains("\"instance.id\":"),
        "telemetry log missing instance.id attribute: {log}",
        log = log
    );
}

fn run_mode_switch(binary: &Path, spec: &ModeSpec) -> Result<()> {
    let context = ModeContext::prepare(spec.needs_node, spec.needs_wallet, spec.telemetry)?;

    let mut command = Command::new(binary);
    command
        .arg(spec.name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(
            "RUST_LOG",
            "info,rpp_node=info,rpp-chain=info,rpp_chain=info,rpp_node::runtime=info",
        );

    if let Some(node_config) = context.node_config() {
        command.arg("--node-config").arg(node_config);
    }

    if let Some(wallet_config) = context.wallet_config() {
        command.arg("--wallet-config").arg(wallet_config);
    }

    let mut child = command.spawn().context("failed to spawn rpp-node")?;

    // Ensure the child process is terminated if the test encounters an early failure.
    let mut child_guard = ChildTerminationGuard {
        child: Some(&mut child),
    };

    let mut logs = capture_child_output(&mut child);

    let bootstrap_log = wait_for_log(&mut logs, "bootstrap configuration resolved")?;
    assert!(
        bootstrap_log.contains(&format!("\"mode\":\"{}\"", spec.name)),
        "bootstrap log missing mode: {}",
        bootstrap_log
    );
    assert!(
        bootstrap_log.contains(&format!("\"config_source\":\"{}\"", spec.config_source)),
        "bootstrap log missing config source: {}",
        bootstrap_log
    );
    if observability_assertions_enabled() {
        assert_observability_attributes(&bootstrap_log, spec);
    }

    let telemetry_log = wait_for_log(&mut logs, "node.telemetry.init")?;
    assert!(
        telemetry_log.contains(&format!("\"mode\":\"{}\"", spec.name)),
        "telemetry log missing mode: {}",
        telemetry_log
    );
    assert!(
        telemetry_log.contains(&format!("\"config_source\":\"{}\"", spec.config_source)),
        "telemetry log missing config source: {}",
        telemetry_log
    );

    if observability_assertions_enabled() {
        assert_observability_attributes(&telemetry_log, spec);
        assert!(
            telemetry_log.contains("\"target\":\"telemetry\""),
            "telemetry log missing telemetry target marker: {}",
            telemetry_log
        );
    }

    if let Some(expectation) = spec.telemetry {
        let _ = wait_for_log(&mut logs, expectation.expected_log())?;
    }

    if spec.needs_node {
        let node_log = wait_for_log(&mut logs, "node runtime started")?;
        if observability_assertions_enabled() {
            assert_observability_attributes(&node_log, spec);
        }
    }

    if spec.needs_wallet {
        let wallet_log = wait_for_log(&mut logs, "wallet runtime initialised")?;
        if observability_assertions_enabled() {
            assert_observability_attributes(&wallet_log, spec);
        }
    }

    for pipeline in spec.pipelines {
        let pipeline_log = wait_for_pipeline_marker(&mut logs, pipeline)?;
        if observability_assertions_enabled() {
            assert_observability_attributes(&pipeline_log, spec);
            assert!(
                pipeline_log.contains("\"target\":\"pipeline\""),
                "pipeline log missing pipeline target marker: {}",
                pipeline_log
            );
            assert!(
                pipeline_log.contains(&format!("\"pipeline\":\"{pipeline}\"")),
                "pipeline log missing pipeline label: {}",
                pipeline_log
            );
        }
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
        config_source: "cli",
        pipelines: &[],
    };

    let context = ModeContext::prepare(spec.needs_node, spec.needs_wallet, spec.telemetry)?;

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

    if let Some(node_config) = context.node_config() {
        command.arg("--node-config").arg(node_config);
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

    if !combined.contains("bootstrap configuration resolved") {
        return Err(anyhow!(
            "dry run logs did not include bootstrap confirmation: {combined}"
        ));
    }

    if !combined.contains("\"dry_run\":true") {
        return Err(anyhow!(
            "dry run logs did not record dry run flag: {combined}"
        ));
    }

    if !combined.contains("\"mode\":\"node\"") {
        return Err(anyhow!(
            "dry run logs did not record the runtime mode: {combined}"
        ));
    }

    if !combined.contains("\"config_source\":\"cli\"") {
        return Err(anyhow!(
            "dry run logs did not record the config source: {combined}"
        ));
    }

    if combined.contains("pipeline orchestrator started")
        || combined.contains("\"msg\":\"pipeline=\\\"")
    {
        return Err(anyhow!(
            "dry run logs indicate pipeline orchestrator was started: {combined}"
        ));
    }

    Ok(())
}

#[test]
fn validator_dry_run_rejects_invalid_configuration() -> Result<()> {
    let binary = locate_rpp_node_binary().context("failed to locate rpp-node binary")?;
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;

    let node_port = pick_free_tcp_port()?;
    let wallet_port = loop {
        let candidate = pick_free_tcp_port()?;
        if candidate != node_port {
            break candidate;
        }
    };

    let node_addr: SocketAddr = format!("127.0.0.1:{node_port}")
        .parse()
        .context("invalid node rpc listen address")?;
    let wallet_addr: SocketAddr = format!("127.0.0.1:{wallet_port}")
        .parse()
        .context("invalid wallet rpc listen address")?;

    let mut ports = PortAllocator::default();
    let node_config = write_node_config_with(
        temp_dir.path(),
        Some(TelemetryExpectation::WithEndpoint),
        &mut ports,
        |config| {
            config.network.rpc.listen = node_addr;
        },
    )?;
    ports.reserve(node_addr.port());

    let wallet_config = write_wallet_config_with(temp_dir.path(), &mut ports, |config| {
        config.wallet.rpc.listen = wallet_addr;
    })?;
    ports.reserve(wallet_addr.port());

    let output = Command::new(&binary)
        .arg("validator")
        .arg("--node-config")
        .arg(&node_config)
        .arg("--wallet-config")
        .arg(&wallet_config)
        .arg("--dry-run")
        .output()
        .context("failed to run validator dry run")?;

    assert_eq!(
        output.status.code(),
        Some(2),
        "validator dry run exited with unexpected status: {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("listener mismatch"),
        "stderr missing mismatch message: {stderr}"
    );
    assert!(
        stderr.contains("node-config.toml::network.rpc.listen"),
        "stderr missing node rpc reference: {stderr}"
    );
    assert!(
        stderr.contains("wallet-config.toml::wallet.rpc.listen"),
        "stderr missing wallet rpc reference: {stderr}"
    );

    Ok(())
}

#[test]
fn hybrid_rejects_mismatched_rpc_listeners() -> Result<()> {
    let binary = locate_rpp_node_binary().context("failed to locate rpp-node binary")?;
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let node_port = pick_free_tcp_port()?;
    let wallet_port = loop {
        let candidate = pick_free_tcp_port()?;
        if candidate != node_port {
            break candidate;
        }
    };
    let node_addr: SocketAddr = format!("127.0.0.1:{node_port}")
        .parse()
        .context("invalid node rpc listen address")?;
    let wallet_addr: SocketAddr = format!("127.0.0.1:{wallet_port}")
        .parse()
        .context("invalid wallet rpc listen address")?;

    let mut ports = PortAllocator::default();
    let node_config = write_node_config_with(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
        |config| {
            config.network.rpc.listen = node_addr;
        },
    )?;
    ports.reserve(node_addr.port());

    let wallet_config = write_wallet_config_with(temp_dir.path(), &mut ports, |config| {
        config.wallet.rpc.listen = wallet_addr;
    })?;
    ports.reserve(wallet_addr.port());

    let output = Command::new(&binary)
        .arg("hybrid")
        .arg("--node-config")
        .arg(&node_config)
        .arg("--wallet-config")
        .arg(&wallet_config)
        .output()
        .context("failed to run rpp-node hybrid")?;

    assert_eq!(
        output.status.code(),
        Some(2),
        "hybrid mode exited with unexpected status: {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("listener mismatch"),
        "stderr missing mismatch message: {stderr}"
    );
    assert!(
        stderr.contains("node-config.toml::network.rpc.listen"),
        "stderr missing node rpc reference: {stderr}"
    );
    assert!(
        stderr.contains("wallet-config.toml::wallet.rpc.listen"),
        "stderr missing wallet rpc reference: {stderr}"
    );
    assert!(
        stderr.contains(&node_port.to_string()),
        "stderr missing node port {node_port}: {stderr}"
    );
    assert!(
        stderr.contains(&wallet_port.to_string()),
        "stderr missing wallet port {wallet_port}: {stderr}"
    );

    Ok(())
}

#[test]
fn validator_rejects_mismatched_rpc_listeners() -> Result<()> {
    let binary = locate_rpp_node_binary().context("failed to locate rpp-node binary")?;
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;

    let node_port = pick_free_tcp_port()?;
    let wallet_port = loop {
        let candidate = pick_free_tcp_port()?;
        if candidate != node_port {
            break candidate;
        }
    };

    let node_addr: SocketAddr = format!("127.0.0.1:{node_port}")
        .parse()
        .context("invalid node rpc listen address")?;
    let wallet_addr: SocketAddr = format!("127.0.0.1:{wallet_port}")
        .parse()
        .context("invalid wallet rpc listen address")?;

    let mut ports = PortAllocator::default();
    let node_config = write_node_config_with(
        temp_dir.path(),
        Some(TelemetryExpectation::WithEndpoint),
        &mut ports,
        |config| {
            config.network.rpc.listen = node_addr;
        },
    )?;
    ports.reserve(node_addr.port());

    let wallet_config = write_wallet_config_with(temp_dir.path(), &mut ports, |config| {
        config.wallet.rpc.listen = wallet_addr;
    })?;
    ports.reserve(wallet_addr.port());

    let output = Command::new(&binary)
        .arg("validator")
        .arg("--node-config")
        .arg(&node_config)
        .arg("--wallet-config")
        .arg(&wallet_config)
        .output()
        .context("failed to run rpp-node validator")?;

    assert_eq!(
        output.status.code(),
        Some(2),
        "validator mode exited with unexpected status: {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("listener mismatch"),
        "stderr missing mismatch message: {stderr}"
    );
    assert!(
        stderr.contains("node-config.toml::network.rpc.listen"),
        "stderr missing node rpc reference: {stderr}"
    );
    assert!(
        stderr.contains("wallet-config.toml::wallet.rpc.listen"),
        "stderr missing wallet rpc reference: {stderr}"
    );
    assert!(
        stderr.contains(&node_port.to_string()),
        "stderr missing node port {node_port}: {stderr}"
    );
    assert!(
        stderr.contains(&wallet_port.to_string()),
        "stderr missing wallet port {wallet_port}: {stderr}"
    );

    Ok(())
}

#[test]
fn validator_rejects_wallet_reusing_p2p_port() -> Result<()> {
    let binary = locate_rpp_node_binary().context("failed to locate rpp-node binary")?;
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;

    let wallet_port = pick_free_tcp_port()?;
    let wallet_addr: SocketAddr = format!("127.0.0.1:{wallet_port}")
        .parse()
        .context("invalid wallet rpc listen address")?;

    let node_rpc_port = loop {
        let candidate = pick_free_tcp_port()?;
        if candidate != wallet_port {
            break candidate;
        }
    };
    let node_rpc_addr: SocketAddr = format!("127.0.0.1:{node_rpc_port}")
        .parse()
        .context("invalid node rpc listen address")?;
    let p2p_multiaddr = format!("/ip4/127.0.0.1/tcp/{wallet_port}");

    let mut ports = PortAllocator::default();
    let node_config = write_node_config_with(
        temp_dir.path(),
        Some(TelemetryExpectation::WithEndpoint),
        &mut ports,
        |config| {
            config.network.rpc.listen = node_rpc_addr;
            config.network.p2p.listen_addr = p2p_multiaddr.clone();
        },
    )?;
    ports.reserve(node_rpc_addr.port());
    if let Some(port) = extract_port(p2p_multiaddr.clone()) {
        ports.reserve(port);
    }

    let wallet_config = write_wallet_config_with(temp_dir.path(), &mut ports, |config| {
        config.wallet.rpc.listen = wallet_addr;
    })?;
    ports.reserve(wallet_addr.port());

    let output = Command::new(&binary)
        .arg("validator")
        .arg("--node-config")
        .arg(&node_config)
        .arg("--wallet-config")
        .arg(&wallet_config)
        .output()
        .context("failed to run rpp-node validator")?;

    assert_eq!(
        output.status.code(),
        Some(2),
        "validator mode exited with unexpected status: {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("listener conflict"),
        "stderr missing conflict message: {stderr}"
    );
    assert!(
        stderr.contains("wallet-config.toml::wallet.rpc.listen"),
        "stderr missing wallet rpc reference: {stderr}"
    );
    assert!(
        stderr.contains("p2p.listen_addr"),
        "stderr missing p2p reference: {stderr}"
    );
    assert!(
        stderr.contains(&wallet_port.to_string()),
        "stderr missing shared port {wallet_port}: {stderr}"
    );

    Ok(())
}
