use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use reqwest::StatusCode;
use rpp_chain::config::{NodeConfig, SecretsBackendConfig};
use rpp_chain::crypto::HsmKeystoreConfig;
use rpp_node::RuntimeMode;
use rpp_node::{validator_setup, ValidatorSetupError, ValidatorSetupOptions, ValidatorSetupReport};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn validator_template(temp: &TempDir) -> NodeConfig {
    let mut config = NodeConfig::for_mode(RuntimeMode::Validator);
    config.data_dir = temp.path().join("data");
    config.key_path = temp.path().join("keys/validator.toml");
    config.p2p_key_path = temp.path().join("keys/p2p.toml");
    config.vrf_key_path = temp.path().join("keys/vrf.toml");
    config.secrets.backend = SecretsBackendConfig::Filesystem(Default::default());
    config
}

async fn spinup_http_server() -> Result<(TcpListener, std::net::SocketAddr)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

#[tokio::test]
async fn validator_setup_rotates_vrf_and_checks_telemetry() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = validator_template(&temp);

    let (listener, addr) = spinup_http_server().await?;
    config.rollout.telemetry.enabled = true;
    config.rollout.telemetry.endpoint = Some(format!("http://{}", addr));
    config.rollout.telemetry.http_endpoint = Some(format!("http://{}", addr));

    let server = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });

    let options = ValidatorSetupOptions {
        telemetry_probe_timeout: Duration::from_secs(5),
        skip_telemetry_probe: false,
    };

    let report = validator_setup(&config, options).await?;
    assert!(matches!(
        report.secrets_backend,
        SecretsBackendConfig::Filesystem(_)
    ));
    assert_eq!(report.telemetry.http_status, Some(StatusCode::NO_CONTENT));
    assert!(report.telemetry.http_endpoint.is_some());
    assert!(report.telemetry.enabled);
    assert!(!report.telemetry.skipped);
    assert!(!report.public_key.is_empty());

    let vrf_path = config.vrf_key_path.clone();
    assert!(
        vrf_path.exists(),
        "expected VRF material at {}",
        vrf_path.display()
    );

    let _ = server.await;

    Ok(())
}

#[tokio::test]
async fn validator_setup_reports_network_failure() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = validator_template(&temp);

    config.rollout.telemetry.enabled = true;
    config.rollout.telemetry.endpoint = Some("http://127.0.0.1:9".to_string());
    config.rollout.telemetry.http_endpoint = Some("http://127.0.0.1:9".to_string());

    let options = ValidatorSetupOptions {
        telemetry_probe_timeout: Duration::from_secs(1),
        skip_telemetry_probe: false,
    };

    let error = validator_setup(&config, options)
        .await
        .expect_err("network probe should fail");
    assert!(matches!(error, ValidatorSetupError::Network(_)));
    Ok(())
}

#[tokio::test]
async fn validator_setup_skips_probe_when_requested() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = validator_template(&temp);

    config.rollout.telemetry.enabled = true;
    config.rollout.telemetry.endpoint = Some("http://127.0.0.1:9".to_string());
    config.rollout.telemetry.http_endpoint = Some("http://127.0.0.1:9".to_string());

    let options = ValidatorSetupOptions {
        telemetry_probe_timeout: Duration::from_secs(1),
        skip_telemetry_probe: true,
    };

    let ValidatorSetupReport { telemetry, .. } = validator_setup(&config, options).await?;
    assert!(telemetry.enabled);
    assert!(telemetry.skipped);
    assert!(telemetry.http_status.is_none());
    Ok(())
}

#[tokio::test]
async fn validator_setup_handles_hsm_backend() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = validator_template(&temp);

    config.vrf_key_path = PathBuf::from("/hsm/key");
    config.secrets.backend = SecretsBackendConfig::Hsm(HsmKeystoreConfig {
        library_path: Some(temp.path().join("libhsm-emulator.so")),
        slot: Some(0),
        key_id: Some("validator-hsm".to_string()),
    });

    let options = ValidatorSetupOptions {
        telemetry_probe_timeout: Duration::from_secs(1),
        skip_telemetry_probe: true,
    };

    let report = validator_setup(&config, options).await?;
    assert!(matches!(
        report.secrets_backend,
        SecretsBackendConfig::Hsm(_)
    ));
    assert_eq!(report.public_key.len(), 64);

    let keystore_root = match &config.secrets.backend {
        SecretsBackendConfig::Hsm(config) => config.storage_root(),
        _ => unreachable!("hsm backend required"),
    };
    let expected = keystore_root.join("validator-hsm.toml");
    assert!(expected.exists(), "hsm backend should persist vrf keys");

    Ok(())
}
