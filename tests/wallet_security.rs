use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::post, Json, Router};
use rcgen::{BasicConstraints, Certificate as RcgenCertificate, CertificateParams, DnType, IsCa};
use reqwest::{Certificate, Client, ClientBuilder, Identity};
use rpp_chain::runtime::telemetry::metrics::{RuntimeMetrics, WalletRpcMethod};
use rpp_chain::runtime::wallet::rpc::{
    authenticated_handler, AuthenticatedRpcHandler, RpcError, RpcInvocation, RpcRequest,
    StaticAuthenticator, WalletClientCertificates, WalletIdentity, WalletRbacStore, WalletRole,
    WalletRoleSet, WalletSecurityBinding, WalletSecurityContext, WalletSecurityPaths,
};
use rpp_chain::runtime::wallet::runtime::{
    DeterministicSync, WalletRpcSecurityRuntimeConfig, WalletRuntime, WalletRuntimeConfig,
    WalletService,
};
use rpp_chain::runtime::wallet::sync::SyncProvider;
use rpp_wallet::rpc::dto::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use rpp_wallet::rpc::error::WalletRpcErrorCode;
use serde_json::{json, Value};
use tempfile::tempdir;

const VIEWER_METHOD: &str = "viewer.echo";
const OPERATOR_METHOD: &str = "operator.echo";
const ADMIN_METHOD: &str = "admin.echo";

const ROLES_VIEWER: &[WalletRole] = &[WalletRole::Viewer, WalletRole::Operator, WalletRole::Admin];
const ROLES_OPERATOR: &[WalletRole] = &[WalletRole::Operator, WalletRole::Admin];
const ROLES_ADMIN: &[WalletRole] = &[WalletRole::Admin];

type TestHandlerFn =
    Arc<dyn Fn(RpcInvocation<'_, JsonRpcRequest>) -> JsonRpcResponse + Send + Sync + 'static>;
type TestHandler = AuthenticatedRpcHandler<TestHandlerFn, JsonRpcRequest>;

struct TestRpcServer {
    security: Arc<WalletSecurityContext>,
    handlers: HashMap<String, TestHandler>,
}

impl TestRpcServer {
    fn handler_for(&self, method: &str) -> Option<&TestHandler> {
        self.handlers.get(method)
    }
}

async fn test_rpc_handler(
    State(server): State<Arc<TestRpcServer>>,
    client_certs: Option<Extension<Arc<WalletClientCertificates>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(err) => {
            return rpc_error_response(
                StatusCode::BAD_REQUEST,
                None,
                JsonRpcError::new(-32700, format!("invalid JSON payload: {err}"), None),
            );
        }
    };

    let id = request.id.clone();
    let method = request.method.clone();
    let handler = match server.handler_for(&method) {
        Some(handler) => handler,
        None => {
            return rpc_error_response(
                StatusCode::OK,
                id,
                JsonRpcError::new(-32601, format!("method {method} not found"), None),
            );
        }
    };

    let token_owned = bearer_token(&headers);
    let certificate_view = client_certs
        .as_ref()
        .map(|Extension(certs)| Arc::as_ref(certs));
    let identities = request_identities(&headers, token_owned.as_deref(), certificate_view);
    let roles = server.security.resolve_roles(&identities);

    let invocation = RpcInvocation {
        request: RpcRequest {
            bearer_token: token_owned.as_deref(),
            identities,
            roles,
        },
        payload: request,
    };

    match handler.call(invocation) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => rpc_error_from_handler(id, err),
    }
}

fn rpc_error_from_handler(id: Option<Value>, err: RpcError) -> Response {
    let payload = if let Some(wallet_code) = err.wallet_code() {
        let details = wallet_code.data_payload(err.details().cloned());
        JsonRpcError::new(err.code(), err.to_string(), Some(details))
    } else {
        JsonRpcError::new(err.code(), err.to_string(), err.details().cloned())
    };
    rpc_error_response(err.status(), id, payload)
}

fn rpc_error_response(status: StatusCode, id: Option<Value>, error: JsonRpcError) -> Response {
    (status, Json(JsonRpcResponse::error(id, error))).into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let prefix = "Bearer ";
    if value.starts_with(prefix) {
        Some(value[prefix.len()..].to_string())
    } else {
        None
    }
}

fn request_identities(
    headers: &HeaderMap,
    bearer: Option<&str>,
    client_certs: Option<&WalletClientCertificates>,
) -> Vec<WalletIdentity> {
    let mut identities = Vec::new();
    if let Some(token) = bearer {
        identities.push(WalletIdentity::from_bearer_token(token));
    }
    if let Some(certs) = client_certs {
        identities.extend(certs.identities());
    }
    if let Some(identity) = certificate_identity(headers) {
        identities.push(identity);
    }
    identities
}

fn certificate_identity(headers: &HeaderMap) -> Option<WalletIdentity> {
    const HEADER_PEM: &str = "x-client-cert";
    const HEADER_FINGERPRINT: &str = "x-client-cert-sha256";

    if let Some(value) = headers.get(HEADER_FINGERPRINT) {
        let fingerprint = value.to_str().ok()?;
        return WalletIdentity::from_certificate_fingerprint(fingerprint).ok();
    }

    if let Some(value) = headers.get(HEADER_PEM) {
        let pem = value.to_str().ok()?;
        return WalletIdentity::from_certificate_pem(pem).ok();
    }

    None
}

fn format_identity(identity: &WalletIdentity) -> String {
    match identity {
        WalletIdentity::Token(hash) => format!("token:{hash}"),
        WalletIdentity::Certificate(fingerprint) => format!("certificate:{fingerprint}"),
    }
}

fn viewer_handler(metrics: Arc<RuntimeMetrics>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(None),
        Arc::new(|invocation: RpcInvocation<'_, JsonRpcRequest>| {
            let roles = invocation
                .request
                .roles
                .iter()
                .map(WalletRole::as_str)
                .collect::<Vec<_>>();
            let identities = invocation
                .request
                .identities
                .iter()
                .map(format_identity)
                .collect::<Vec<_>>();
            JsonRpcResponse::success(
                invocation.payload.id.clone(),
                json!({
                    "method": invocation.payload.method,
                    "roles": roles,
                    "identities": identities,
                }),
            )
        }),
        metrics,
        WalletRpcMethod::JsonGetBalance,
        None,
        ROLES_VIEWER,
    )
}

fn operator_handler(metrics: Arc<RuntimeMetrics>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(None),
        Arc::new(|invocation: RpcInvocation<'_, JsonRpcRequest>| {
            JsonRpcResponse::success(
                invocation.payload.id.clone(),
                json!({ "method": invocation.payload.method }),
            )
        }),
        metrics,
        WalletRpcMethod::JsonCreateTransaction,
        None,
        ROLES_OPERATOR,
    )
}

fn admin_handler(metrics: Arc<RuntimeMetrics>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(None),
        Arc::new(|invocation: RpcInvocation<'_, JsonRpcRequest>| {
            JsonRpcResponse::success(
                invocation.payload.id.clone(),
                json!({ "method": invocation.payload.method }),
            )
        }),
        metrics,
        WalletRpcMethod::JsonSetPolicy,
        None,
        ROLES_ADMIN,
    )
}

fn build_test_router(security: Arc<WalletSecurityContext>, metrics: Arc<RuntimeMetrics>) -> Router {
    let mut handlers = HashMap::new();
    handlers.insert(
        VIEWER_METHOD.to_string(),
        viewer_handler(Arc::clone(&metrics)),
    );
    handlers.insert(
        OPERATOR_METHOD.to_string(),
        operator_handler(Arc::clone(&metrics)),
    );
    handlers.insert(ADMIN_METHOD.to_string(), admin_handler(metrics));

    let server = Arc::new(TestRpcServer { security, handlers });

    Router::new()
        .route("/rpc", post(test_rpc_handler))
        .with_state(server)
}

#[derive(Clone)]
struct DummyWallet;

impl WalletService for DummyWallet {
    fn address(&self) -> String {
        "wallet-test".to_string()
    }
}

struct SignedCert {
    der: Vec<u8>,
    cert_pem: String,
    key_pem: String,
}

fn issue_cert(common_name: &str, sans: &[&str], ca: &RcgenCertificate) -> SignedCert {
    let mut params = CertificateParams::new(sans.iter().map(|value| value.to_string()).collect());
    params
        .distinguished_name
        .push(DnType::CommonName, common_name.to_string());
    let cert = RcgenCertificate::from_params(params).expect("issue certificate");
    let cert_pem = cert
        .serialize_pem_with_signer(ca)
        .expect("serialize certificate pem");
    let key_pem = cert.serialize_private_key_pem();
    let der = cert
        .serialize_der_with_signer(ca)
        .expect("serialize certificate der");
    SignedCert {
        der,
        cert_pem,
        key_pem,
    }
}

fn write_cert(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write certificate data");
}

fn build_client(ca_pem: &str, identity_pem: Option<&str>) -> Client {
    let ca = Certificate::from_pem(ca_pem.as_bytes()).expect("parse ca certificate");
    let mut builder = ClientBuilder::new()
        .add_root_certificate(ca)
        .use_rustls_tls()
        .timeout(Duration::from_secs(5));
    if let Some(identity) = identity_pem {
        let identity = Identity::from_pem(identity.as_bytes()).expect("parse identity");
        builder = builder.identity(identity);
    }
    builder.build().expect("build client")
}

fn role_set(roles: &[WalletRole]) -> WalletRoleSet {
    let mut set = WalletRoleSet::new();
    for role in roles {
        set.insert(*role);
    }
    set
}

async fn send_request(
    client: &Client,
    url: &str,
    method: &str,
) -> reqwest::Result<reqwest::Response> {
    client
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
        }))
        .send()
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_rpc_mtls_enforces_rbac() {
    let temp = tempdir().expect("temporary directory");

    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Wallet Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = RcgenCertificate::from_params(ca_params).expect("ca certificate");
    let ca_pem = ca_cert.serialize_pem().expect("ca pem");

    let server_cert = issue_cert("wallet-server", &["localhost", "127.0.0.1"], &ca_cert);
    let viewer_cert = issue_cert("viewer", &["viewer"], &ca_cert);
    let operator_cert = issue_cert("operator", &["operator"], &ca_cert);
    let admin_cert = issue_cert("admin", &["admin"], &ca_cert);

    let cert_dir = temp.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("cert directory");
    let server_cert_path = cert_dir.join("server.pem");
    let server_key_path = cert_dir.join("server.key");
    let ca_path = cert_dir.join("ca.pem");
    write_cert(&server_cert_path, &server_cert.cert_pem);
    write_cert(&server_key_path, &server_cert.key_pem);
    write_cert(&ca_path, &ca_pem);

    let viewer_bundle = viewer_cert.cert_pem.clone() + &viewer_cert.key_pem;
    let operator_bundle = operator_cert.cert_pem.clone() + &operator_cert.key_pem;
    let admin_bundle = admin_cert.cert_pem.clone() + &admin_cert.key_pem;

    let security_paths = WalletSecurityPaths::from_data_dir(temp.path());
    security_paths.ensure().expect("security paths");
    let store_path = security_paths.rbac_store();
    let store = WalletRbacStore::load(&store_path).expect("load rbac store");

    let viewer_identity = WalletIdentity::from_certificate_der(&viewer_cert.der);
    let operator_identity = WalletIdentity::from_certificate_der(&operator_cert.der);
    let admin_identity = WalletIdentity::from_certificate_der(&admin_cert.der);

    let bindings = vec![
        WalletSecurityBinding::new(viewer_identity.clone(), role_set(&[WalletRole::Viewer])),
        WalletSecurityBinding::new(operator_identity.clone(), role_set(&[WalletRole::Operator])),
        WalletSecurityBinding::new(admin_identity.clone(), role_set(&[WalletRole::Admin])),
    ];

    store.apply_bindings(bindings.as_slice());
    store.save().expect("save rbac store");

    let mut config = WalletRuntimeConfig::new("127.0.0.1:0".parse().unwrap());
    config.set_security_paths(security_paths);
    config.set_security_bindings(bindings.clone());
    config.set_security_settings(WalletRpcSecurityRuntimeConfig::new(
        true,
        Some(server_cert_path.clone()),
        Some(server_key_path.clone()),
        Some(ca_path.clone()),
        Vec::new(),
    ));
    config.ensure_security_context().expect("security context");

    let metrics = RuntimeMetrics::noop();
    let router = build_test_router(config.security_context(), Arc::clone(&metrics));
    let wallet = Arc::new(DummyWallet);
    let sync_provider: Box<dyn SyncProvider> = Box::new(DeterministicSync::new("wallet-security"));

    let handle = WalletRuntime::start(
        wallet,
        config,
        Arc::clone(&metrics),
        sync_provider,
        None,
        None,
        Some(router),
    )
    .expect("start runtime");

    let base_url = format!("https://{}", handle.listen_addr());
    let viewer_client = build_client(&ca_pem, Some(&viewer_bundle));
    let operator_client = build_client(&ca_pem, Some(&operator_bundle));
    let admin_client = build_client(&ca_pem, Some(&admin_bundle));
    let anonymous_client = build_client(&ca_pem, None);

    let viewer_response = send_request(&viewer_client, &base_url, VIEWER_METHOD)
        .await
        .expect("viewer request");
    assert_eq!(viewer_response.status(), StatusCode::OK);
    let viewer_payload: JsonRpcResponse = viewer_response.json().await.expect("viewer payload");
    let viewer_result = viewer_payload.result.expect("viewer result");
    assert_eq!(viewer_result["method"], VIEWER_METHOD);
    let identities = viewer_result["identities"]
        .as_array()
        .expect("identities array");
    let expected_identity = format_identity(&viewer_identity);
    assert!(identities
        .iter()
        .any(|value| value == &json!(expected_identity)));
    let roles = viewer_result["roles"].as_array().expect("roles array");
    assert!(roles.iter().any(|value| value == "viewer"));

    let operator_viewer = send_request(&operator_client, &base_url, VIEWER_METHOD)
        .await
        .expect("operator viewer request");
    assert_eq!(operator_viewer.status(), StatusCode::OK);
    let operator_viewer_payload: JsonRpcResponse = operator_viewer
        .json()
        .await
        .expect("operator viewer payload");
    assert!(operator_viewer_payload.error.is_none());

    let viewer_operator = send_request(&viewer_client, &base_url, OPERATOR_METHOD)
        .await
        .expect("viewer operator request");
    assert_eq!(viewer_operator.status(), StatusCode::FORBIDDEN);
    let viewer_operator_payload: JsonRpcResponse = viewer_operator
        .json()
        .await
        .expect("viewer operator payload");
    let viewer_error = viewer_operator_payload.error.expect("viewer error");
    assert_eq!(viewer_error.code, -32062);

    let operator_admin = send_request(&operator_client, &base_url, ADMIN_METHOD)
        .await
        .expect("operator admin request");
    assert_eq!(operator_admin.status(), StatusCode::FORBIDDEN);
    let operator_admin_payload: JsonRpcResponse =
        operator_admin.json().await.expect("operator admin payload");
    let operator_error = operator_admin_payload.error.expect("operator error");
    assert_eq!(operator_error.code, -32062);

    let admin_response = send_request(&admin_client, &base_url, ADMIN_METHOD)
        .await
        .expect("admin request");
    assert_eq!(admin_response.status(), StatusCode::OK);

    let anonymous_err = send_request(&anonymous_client, &base_url, VIEWER_METHOD)
        .await
        .expect_err("anonymous handshake should fail");
    assert!(
        anonymous_err.is_connect(),
        "unexpected error: {anonymous_err}"
    );

    handle.shutdown().await.expect("shutdown runtime");
}
