#![cfg(all(
    feature = "wallet_rpc_mtls",
    feature = "wallet-integration",
    feature = "wallet-ui"
))]

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyUsagePurpose, SanType,
};
use reqwest::{Certificate as ReqwestCert, Client, Identity};
use tempfile::TempDir;

use rpp_chain::config::{NetworkTlsConfig, NodeConfig, TlsVersion};

#[path = "../support/mod.rs"]
mod support;

use support::cluster::TestCluster;

struct TlsMaterial {
    dir: TempDir,
    ca_pem: String,
    ca_path: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    client_bundle_path: PathBuf,
}

impl TlsMaterial {
    fn new() -> Result<Self> {
        let dir = TempDir::new().context("create TLS tempdir")?;

        let ca = build_ca_cert()?;
        let ca_pem = ca.serialize_pem().context("serialize CA certificate")?;
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &ca_pem).context("persist CA certificate")?;

        let (server_cert_path, server_key_path, _) =
            write_signed_certificate(dir.path(), "server", &ca, server_cert_params()?)?;
        let (client_cert_path, client_key_path, client_bundle_path) =
            write_signed_certificate(dir.path(), "client", &ca, client_cert_params()?)?;

        // The RPC server needs only the leaf certificate and key, while the client identity
        // consumes a bundle.
        let _ = client_cert_path;
        let _ = client_key_path;

        Ok(Self {
            dir,
            ca_pem,
            ca_path,
            server_cert_path,
            server_key_path,
            client_bundle_path,
        })
    }

    fn client(&self, identity_path: Option<&PathBuf>) -> Result<Client> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(10))
            .add_root_certificate(ReqwestCert::from_pem(self.ca_pem.as_bytes())?);

        if let Some(path) = identity_path {
            let pem = std::fs::read(path).context("read client identity bundle")?;
            let identity = Identity::from_pem(&pem).context("decode client identity")?;
            builder = builder.identity(identity);
        }

        builder.build().context("construct TLS client")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_and_snapshot_reject_plain_http_when_tls_is_enabled() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let material = TlsMaterial::new()?;
    let mut cluster = TestCluster::start_with(2, |config, _| {
        apply_tls_config(config, &material, false)?;
        Ok(())
    })
    .await?;

    cluster
        .wait_for_full_mesh(Duration::from_secs(10))
        .await
        .context("cluster mesh")?;

    let rpc_addr = cluster.nodes()[0].config.network.rpc.listen;
    let https_base = format!("https://{rpc_addr}");

    let https = material.client(None)?;
    https
        .get(format!("{https_base}/health/ready"))
        .send()
        .await
        .context("ready probe")?
        .error_for_status()
        .context("ready status")?;
    https
        .get(format!("{https_base}/p2p/snapshots/breaker"))
        .send()
        .await
        .context("breaker status request")?
        .error_for_status()
        .context("breaker status")?;

    let http_client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build plain HTTP client")?;
    let http_error = http_client
        .get(format!("http://{rpc_addr}/health/ready"))
        .send()
        .await
        .expect_err("plain HTTP must not be accepted over TLS sockets");
    let message = http_error.to_string();
    assert!(
        message.contains("tls") || message.contains("handshake") || message.contains("unexpected"),
        "plain HTTP request should fail due to TLS enforcement: {message}"
    );

    cluster.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_and_snapshot_enforce_client_certs_when_mtls_enabled() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let material = TlsMaterial::new()?;
    let mut cluster = TestCluster::start_with(2, |config, _| {
        apply_tls_config(config, &material, true)?;
        Ok(())
    })
    .await?;

    cluster
        .wait_for_full_mesh(Duration::from_secs(10))
        .await
        .context("cluster mesh")?;

    let rpc_addr = cluster.nodes()[0].config.network.rpc.listen;
    let https_base = format!("https://{rpc_addr}");

    let missing_identity = material.client(None)?;
    let mtls_error = missing_identity
        .get(format!("{https_base}/health/ready"))
        .send()
        .await
        .expect_err("mTLS should reject clients without a certificate");
    let mtls_message = mtls_error.to_string();
    assert!(
        mtls_message.to_lowercase().contains("certificate")
            || mtls_message.to_lowercase().contains("handshake"),
        "expected client-certificate failure, got: {mtls_message}"
    );

    let mtls = material.client(Some(&material.client_bundle_path))?;
    mtls.get(format!("{https_base}/health/ready"))
        .send()
        .await
        .context("ready probe (mTLS)")?
        .error_for_status()
        .context("ready status (mTLS)")?;
    mtls.get(format!("{https_base}/p2p/snapshots/breaker"))
        .send()
        .await
        .context("breaker status request (mTLS)")?
        .error_for_status()
        .context("breaker status (mTLS)")?;

    cluster.shutdown().await?;
    Ok(())
}

fn apply_tls_config(
    config: &mut NodeConfig,
    material: &TlsMaterial,
    require_client_auth: bool,
) -> Result<()> {
    config.network.rpc.require_auth = false;
    config.network.rpc.auth_token = None;

    config.network.tls = NetworkTlsConfig {
        enabled: true,
        certificate: Some(material.server_cert_path.clone()),
        private_key: Some(material.server_key_path.clone()),
        client_ca: Some(material.ca_path.clone()),
        min_tls_version: Some(TlsVersion::Tls13),
        cipher_suites: Vec::new(),
        require_client_auth,
    };

    Ok(())
}

fn build_ca_cert() -> Result<Certificate> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "test-ca".to_string());
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Certificate::from_params(params).context("build CA certificate")
}

fn server_cert_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]);
    params
        .distinguished_name
        .push(DnType::CommonName, "rpp-node".to_string());
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    Ok(params)
}

fn client_cert_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(vec!["rpc-client".to_string()]);
    params
        .distinguished_name
        .push(DnType::CommonName, "rpc-client".to_string());
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    Ok(params)
}

fn write_signed_certificate(
    dir: &std::path::Path,
    stem: &str,
    ca: &Certificate,
    mut params: CertificateParams,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    params.is_ca = IsCa::NoCa;
    let cert = Certificate::from_params(params).context("build leaf certificate")?;
    let cert_pem = cert
        .serialize_pem_with_signer(ca)
        .context("sign leaf certificate")?;
    let key_pem = cert.serialize_private_key_pem();

    let cert_path = dir.join(format!("{stem}.crt"));
    let key_path = dir.join(format!("{stem}.key"));

    std::fs::write(&cert_path, &cert_pem)
        .with_context(|| format!("write certificate for {stem} to {}", cert_path.display()))?;
    std::fs::write(&key_path, cert.serialize_private_key_pem())
        .with_context(|| format!("write private key for {stem} to {}", key_path.display()))?;

    let bundle_path = dir.join(format!("{stem}-bundle.pem"));
    std::fs::write(&bundle_path, cert_pem + &key_pem).with_context(|| {
        format!(
            "write certificate and key bundle for {stem} to {}",
            bundle_path.display()
        )
    })?;

    Ok((cert_path, key_path, bundle_path))
}
