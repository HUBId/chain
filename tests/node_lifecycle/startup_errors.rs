#![cfg(feature = "integration")]

use std::fs;
use std::process::Command;

use anyhow::{Context, Result};
use tempfile::TempDir;

use super::support::{locate_rpp_node_binary, write_node_config, PortAllocator};

const CONFIG_EXIT_CODE: i32 = 2;

#[test]
fn startup_fails_on_malformed_config() -> Result<()> {
    let temp_dir = TempDir::new().context("create temporary directory")?;
    let config_path = temp_dir.path().join("broken-node.toml");
    fs::write(&config_path, "[node\ninvalid = true").context("write malformed configuration")?;

    let binary = locate_rpp_node_binary().context("locate rpp-node binary")?;
    let output = Command::new(&binary)
        .arg("node")
        .arg("--config")
        .arg(&config_path)
        .output()
        .context("spawn rpp-node with malformed configuration")?;

    assert!(!output.status.success(), "process unexpectedly succeeded");
    assert_eq!(
        output.status.code(),
        Some(CONFIG_EXIT_CODE),
        "malformed configuration should map to configuration exit code",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("configuration error: failed to load configuration"),
        "expected configuration load failure in stderr, found: {stderr}"
    );

    Ok(())
}

#[test]
fn startup_reports_missing_config_path() -> Result<()> {
    let temp_dir = TempDir::new().context("create temporary directory")?;
    let missing = temp_dir.path().join("missing-node.toml");
    let binary = locate_rpp_node_binary().context("locate rpp-node binary")?;

    let output = Command::new(&binary)
        .arg("node")
        .env("RPP_CONFIG", &missing)
        .output()
        .context("spawn rpp-node with missing configuration")?;

    assert!(!output.status.success(), "process unexpectedly succeeded");
    assert_eq!(
        output.status.code(),
        Some(CONFIG_EXIT_CODE),
        "missing configuration should map to configuration exit code",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("configuration error: node configuration not found"),
        "expected missing configuration error in stderr, found: {stderr}"
    );
    assert!(
        stderr.contains("resolved from environment"),
        "expected environment source details in stderr, found: {stderr}"
    );

    Ok(())
}

#[test]
fn startup_rejects_invalid_env_overrides() -> Result<()> {
    let temp_dir = TempDir::new().context("create temporary directory")?;
    let mut ports = PortAllocator::default();
    let config_path = write_node_config(temp_dir.path(), None, &mut ports)
        .context("write baseline node configuration")?;

    let binary = locate_rpp_node_binary().context("locate rpp-node binary")?;
    let output = Command::new(&binary)
        .arg("node")
        .arg("--config")
        .arg(&config_path)
        .env("RPP_NODE_OTLP_ENDPOINT", "ftp://invalid.endpoint")
        .output()
        .context("spawn rpp-node with invalid OTLP override")?;

    assert!(!output.status.success(), "process unexpectedly succeeded");
    assert_eq!(
        output.status.code(),
        Some(CONFIG_EXIT_CODE),
        "invalid OTLP override should map to configuration exit code",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("telemetry.endpoint must use http or https scheme"),
        "expected telemetry endpoint validation failure in stderr, found: {stderr}"
    );

    Ok(())
}

#[test]
fn startup_rejects_out_of_range_ring_size() -> Result<()> {
    let temp_dir = TempDir::new().context("create temporary directory")?;
    let mut ports = PortAllocator::default();
    let config_path = write_node_config(temp_dir.path(), None, &mut ports)
        .context("write baseline node configuration")?;

    let binary = locate_rpp_node_binary().context("locate rpp-node binary")?;
    let output = Command::new(&binary)
        .arg("node")
        .arg("--config")
        .arg(&config_path)
        .env("RPP_NODE_STORAGE_RING_SIZE", "1")
        .output()
        .context("spawn rpp-node with invalid ring size override")?;

    assert!(!output.status.success(), "process unexpectedly succeeded");
    assert_eq!(
        output.status.code(),
        Some(CONFIG_EXIT_CODE),
        "invalid ring size should map to configuration exit code",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("storage.ring_size must be between 2 and 4096"),
        "expected storage ring size validation failure in stderr, found: {stderr}"
    );

    Ok(())
}
