use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate as RcgenCertificate, CertificateParams, DistinguishedName, DnType,
    IsCa, KeyUsagePurpose, SanType,
};
use reqwest::{Client, Identity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tempfile::tempdir;

use rpp::api::{self, ApiContext};
use rpp::runtime::config::{NetworkLimitsConfig, NetworkTlsConfig};
use rpp::runtime::RuntimeMode;

fn random_loopback() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

async fn spawn_server(
    addr: SocketAddr,
    limits: NetworkLimitsConfig,
    tls: NetworkTlsConfig,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let context = ApiContext::new(
        Arc::new(parking_lot::RwLock::new(RuntimeMode::Node)),
        None,
        None,
        None,
        None,
        false,
        false,
    );

    let handle = tokio::spawn(async move {
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        let _ = api::serve_with_shutdown(
            context,
            addr,
            None,
            None,
            limits,
            tls,
            shutdown,
            Some(ready_tx),
        )
        .await;
    });

    ready_rx.await.expect("server ready").expect("server start");

    (shutdown_tx, handle)
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let addr = random_loopback();
    let mut limits = NetworkLimitsConfig::default();
    limits.max_body_bytes = 16;
    limits.per_ip_token_bucket.enabled = false;

    let (shutdown_tx, handle) = spawn_server(addr, limits, NetworkTlsConfig::default()).await;

    let client = Client::builder().build().expect("client");
    let response = client
        .post(format!("http://{addr}/transactions"))
        .body(vec![0u8; 64])
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

#[tokio::test]
async fn read_timeout_closes_stalled_body() {
    let addr = random_loopback();
    let mut limits = NetworkLimitsConfig::default();
    limits.read_timeout_ms = 50;
    limits.per_ip_token_bucket.enabled = false;

    let (shutdown_tx, handle) = spawn_server(addr, limits, NetworkTlsConfig::default()).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let request = format!(
        "POST /transactions HTTP/1.1\r\nHost: {}\r\nContent-Length: 10\r\n\r\n12345",
        addr
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");

    sleep(Duration::from_millis(200)).await;

    let mut buf = [0u8; 1];
    let read = stream.read(&mut buf).await.expect("read");
    assert_eq!(read, 0, "server should close stalled connection");

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

#[tokio::test]
async fn tls_requires_client_certificate() {
    let addr = random_loopback();
    let temp = tempdir().expect("tempdir");

    let ca = build_ca_cert();
    let server = build_tls_cert(&ca, vec![SanType::DnsName("localhost".into())]);
    let client = build_tls_cert(&ca, vec![SanType::DnsName("client".into())]);

    let ca_path = write_pem(temp.path().join("ca.pem"), ca.serialize_pem().unwrap());
    let server_cert_path = write_pem(temp.path().join("server.pem"), server.certificate_pem.clone());
    let server_key_path = write_pem(temp.path().join("server.key"), server.private_key_pem.clone());

    let mut tls = NetworkTlsConfig::default();
    tls.enabled = true;
    tls.certificate = Some(server_cert_path);
    tls.private_key = Some(server_key_path);
    tls.client_ca = Some(ca_path);
    tls.require_client_auth = true;

    let mut limits = NetworkLimitsConfig::default();
    limits.per_ip_token_bucket.enabled = false;

    let (shutdown_tx, handle) = spawn_server(addr, limits, tls).await;

    let client_identity = Identity::from_pem(
        format!("{}{}", client.certificate_pem, client.private_key_pem).as_bytes(),
    )
    .expect("identity");
    let ca_cert = reqwest::Certificate::from_pem(ca.serialize_pem().unwrap().as_bytes())
        .expect("ca cert");
    let https_client = Client::builder()
        .add_root_certificate(ca_cert)
        .identity(client_identity)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("https client");

    let response = https_client
        .get(format!("https://localhost:{}/health", addr.port()))
        .send()
        .await
        .expect("https request");
    assert!(response.status().is_success());

    let unauthenticated_client = Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(ca.serialize_pem().unwrap().as_bytes()).unwrap(),
        )
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("client");
    let error = unauthenticated_client
        .get(format!("https://localhost:{}/health", addr.port()))
        .send()
        .await
        .expect_err("missing certificate should error");
    assert!(error.is_connect());

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

fn build_ca_cert() -> RcgenCertificate {
    let mut params = CertificateParams::new(vec![]);
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    RcgenCertificate::from_params(params).expect("ca cert")
}

struct GeneratedCert {
    certificate_pem: String,
    private_key_pem: String,
}

fn build_tls_cert(ca: &RcgenCertificate, san: Vec<SanType>) -> GeneratedCert {
    let mut params = CertificateParams::new(vec![]);
    params.subject_alt_names = san;
    params.distinguished_name = DistinguishedName::from_rdn_sequence(vec![
        (DnType::CommonName, "rpp-test".into()),
    ]);
    let cert = RcgenCertificate::from_params(params).expect("cert");
    let certificate_pem = cert
        .serialize_pem_with_signer(ca)
        .expect("serialize cert");
    let private_key_pem = cert.serialize_private_key_pem();
    GeneratedCert {
        certificate_pem,
        private_key_pem,
    }
}

fn write_pem(path: PathBuf, contents: String) -> PathBuf {
    std::fs::write(&path, contents).expect("write pem");
    path
}
