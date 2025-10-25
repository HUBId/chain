#![cfg(feature = "integration")]

use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use tempfile::TempDir;

mod support;

use support::{
    capture_child_output, locate_rpp_node_binary, seeded_rng, send_ctrl_c, start_log_drain,
    wait_for_exit, wait_for_log, ChildTerminationGuard, PortAllocator, TelemetryExpectation,
    write_node_config_with, write_wallet_config_with,
};

#[test]
fn observability_smoke() -> Result<()> {
    let mut _rng = seeded_rng("observability_smoke");
    let binary = locate_rpp_node_binary().context("failed to locate rpp-node binary")?;

    let specs = [
        ObservabilitySpec {
            mode: "node",
            needs_node: true,
            needs_wallet: false,
            config_source: "cli",
            expect_bootstrap_warning: true,
        },
        ObservabilitySpec {
            mode: "wallet",
            needs_node: false,
            needs_wallet: true,
            config_source: "none",
            expect_bootstrap_warning: false,
        },
        ObservabilitySpec {
            mode: "hybrid",
            needs_node: true,
            needs_wallet: true,
            config_source: "cli",
            expect_bootstrap_warning: true,
        },
        ObservabilitySpec {
            mode: "validator",
            needs_node: true,
            needs_wallet: true,
            config_source: "cli",
            expect_bootstrap_warning: true,
        },
    ];

    for spec in &specs {
        let temp_dir = TempDir::new().context("failed to create temporary directory")?;
        let mut ports = PortAllocator::default();

        let node_config = if spec.needs_node {
            let path = write_node_config_with(
                temp_dir.path(),
                Some(TelemetryExpectation::Disabled),
                &mut ports,
                |config| {
                    config.rollout.telemetry.enabled = true;
                    config.rollout.telemetry.endpoint = None;
                    config.rollout.telemetry.auth_token = None;
                },
            )?;
            Some(path)
        } else {
            None
        };

        let wallet_config = if spec.needs_wallet {
            let path = write_wallet_config_with(temp_dir.path(), &mut ports, |_| {})?;
            Some(path)
        } else {
            None
        };

        let mut command = Command::new(&binary);
        command
            .arg(spec.mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env(
                "RUST_LOG",
                "info,rpp_node=info,rpp-chain=info,rpp_chain=info,rpp_node::runtime=info",
            );

        if let Some(path) = node_config.as_ref() {
            command.arg("--node-config").arg(path);
        }

        if let Some(path) = wallet_config.as_ref() {
            command.arg("--wallet-config").arg(path);
        }

        let mut child = command.spawn().with_context(|| {
            format!("failed to spawn rpp-node in {} mode", spec.mode)
        })?;
        let mut child_guard = ChildTerminationGuard {
            child: Some(&mut child),
        };

        let mut logs = capture_child_output(&mut child);

        let bootstrap_line = wait_for_log(&mut logs, "bootstrap configuration resolved")?;
        let bootstrap_json = parse_log(&bootstrap_line)?;
        assert_common_fields(&bootstrap_json, spec);
        assert_eq!(
            bootstrap_json
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "bootstrap",
            "bootstrap log missing target marker"
        );

        if spec.expect_bootstrap_warning {
            let telemetry_warning =
                wait_for_log(&mut logs, "telemetry enabled without explicit endpoint")?;
            let telemetry_json = parse_log(&telemetry_warning)?;
            assert_common_fields(&telemetry_json, spec);
            assert_eq!(
                telemetry_json
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                "telemetry",
                "telemetry warning emitted with unexpected target"
            );
            assert!(
                telemetry_json
                    .get("msg")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .contains("telemetry enabled without explicit endpoint"),
                "telemetry warning missing expected message"
            );
        }

        let telemetry_line = wait_for_log(&mut logs, "node.telemetry.init")?;
        let telemetry_json = parse_log(&telemetry_line)?;
        assert_common_fields(&telemetry_json, spec);
        assert_eq!(
            telemetry_json
                .get("otlp_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            false,
            "telemetry init event reported unexpected otlp_enabled flag"
        );

        if spec.needs_node {
            let node_runtime = wait_for_log(&mut logs, "node runtime started")?;
            let node_json = parse_log(&node_runtime)?;
            assert_common_fields(&node_json, spec);
        }

        if spec.needs_wallet {
            let wallet_runtime = wait_for_log(&mut logs, "wallet runtime initialised")?;
            let wallet_json = parse_log(&wallet_runtime)?;
            assert_common_fields(&wallet_json, spec);
        }

        start_log_drain(logs);

        send_ctrl_c(child_guard.child.as_ref().unwrap())
            .context("failed to deliver CTRL+C to rpp-node")?;
        let status = wait_for_exit(child_guard.child.as_mut().unwrap())?;
        if !status.success() {
            return Err(anyhow!(
                "rpp-node exited with status {status} while running {} mode",
                spec.mode
            ));
        }

        child_guard.child.take();
    }

    Ok(())
}

struct ObservabilitySpec {
    mode: &'static str,
    needs_node: bool,
    needs_wallet: bool,
    config_source: &'static str,
    expect_bootstrap_warning: bool,
}

fn parse_log(line: &str) -> Result<Value> {
    serde_json::from_str(line).with_context(|| format!("failed to parse structured log: {line}"))
}

fn assert_common_fields(value: &Value, spec: &ObservabilitySpec) {
    assert_eq!(
        value.get("service.name").and_then(Value::as_str),
        Some("rpp"),
        "structured log missing service.name"
    );
    assert_eq!(
        value.get("service.component").and_then(Value::as_str),
        Some("rpp-node"),
        "structured log missing service.component"
    );
    assert_eq!(
        value.get("service.namespace").and_then(Value::as_str),
        Some("rpp"),
        "structured log missing service.namespace"
    );
    assert_eq!(
        value.get("rpp.mode").and_then(Value::as_str),
        Some(spec.mode),
        "structured log missing rpp.mode"
    );
    assert_eq!(
        value.get("rpp.config_source").and_then(Value::as_str),
        Some(spec.config_source),
        "structured log missing rpp.config_source"
    );
    assert!(
        value
            .get("instance.id")
            .and_then(Value::as_str)
            .map(|value| !value.is_empty())
            .unwrap_or(false),
        "structured log missing instance.id"
    );
    assert!(
        value.get("level").and_then(Value::as_str).is_some(),
        "structured log missing level field"
    );
    assert!(
        value.get("target").and_then(Value::as_str).is_some(),
        "structured log missing target field"
    );
}

