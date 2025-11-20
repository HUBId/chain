use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use rpp_chain::config::{SecretsAdapter, SecretsBackendConfig, SecretsConfig};
use rpp_chain::crypto::{
    FilesystemKeystoreConfig, FilesystemVrfKeyStore, HsmKeystoreConfig, StoredVrfKeypair,
    VaultKeystoreConfig, VaultVrfKeyStore, VrfKeyIdentifier, VrfKeyStore,
};
use rpp_chain::errors::ChainError;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

#[test]
fn filesystem_keystore_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = FilesystemKeystoreConfig {
        root: Some(dir.path().to_path_buf()),
    };
    let store = FilesystemVrfKeyStore::new(config);
    let identifier = VrfKeyIdentifier::filesystem(PathBuf::from("vrf.toml"));

    let first = store
        .load_or_generate(&identifier)
        .expect("generate vrf key");
    let second = store.load_or_generate(&identifier).expect("reload vrf key");

    assert_eq!(first.public.to_bytes(), second.public.to_bytes());
    assert_eq!(first.secret.to_bytes(), second.secret.to_bytes());
}

#[derive(Clone)]
struct VaultState {
    token: String,
    data: Arc<Mutex<HashMap<String, StoredVrfKeypair>>>,
}

impl VaultState {
    fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn authorize(&self, headers: &HeaderMap) -> bool {
        headers.get("x-vault-token").map(|value| value.as_bytes()) == Some(self.token.as_bytes())
    }
}

#[derive(Serialize, Deserialize)]
struct VaultReadResponse {
    data: VaultReadInner,
}

#[derive(Serialize, Deserialize)]
struct VaultReadInner {
    data: StoredVrfKeypair,
}

#[derive(Deserialize)]
struct VaultWriteRequest {
    data: StoredVrfKeypair,
}

async fn vault_get(
    State(state): State<VaultState>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, axum::http::StatusCode> {
    if !state.authorize(&headers) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    let guard = state.data.lock().expect("vault state lock");
    match guard.get(&key) {
        Some(stored) => Ok((
            axum::http::StatusCode::OK,
            Json(VaultReadResponse {
                data: VaultReadInner {
                    data: stored.clone(),
                },
            }),
        )),
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

async fn vault_post(
    State(state): State<VaultState>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<VaultWriteRequest>,
) -> Result<impl IntoResponse, axum::http::StatusCode> {
    if !state.authorize(&headers) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    let mut guard = state.data.lock().expect("vault state lock");
    guard.insert(key, payload.data);
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[test]
fn vault_keystore_roundtrip() {
    let runtime = Runtime::new().expect("runtime");
    let state = VaultState::new("root-token");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let addr = listener.local_addr().expect("addr");
    let server_state = state.clone();
    let app = Router::new()
        .route("/v1/kv/data/*key", get(vault_get).post(vault_post))
        .with_state(server_state);
    let server = runtime.spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server");
    });

    runtime.block_on(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let address = format!("http://{}", addr);
    let config = VaultKeystoreConfig {
        address: address.clone(),
        mount: "kv".into(),
        namespace: None,
        token: Some(state.token.clone()),
        token_file: None,
        token_env: None,
        tls: None,
        request_timeout_secs: 5,
    };

    let store = VaultVrfKeyStore::new(config).expect("vault keystore");
    let identifier = VrfKeyIdentifier::remote("validators/primary");

    let generated = store
        .load_or_generate(&identifier)
        .expect("generate via vault");
    let loaded_again = store
        .load_or_generate(&identifier)
        .expect("reload via vault");
    assert_eq!(generated.public.to_bytes(), loaded_again.public.to_bytes());
    assert_eq!(generated.secret.to_bytes(), loaded_again.secret.to_bytes());

    let second_store = VaultVrfKeyStore::new(VaultKeystoreConfig {
        address,
        mount: "kv".into(),
        namespace: None,
        token: Some("root-token".into()),
        token_file: None,
        token_env: None,
        tls: None,
        request_timeout_secs: 5,
    })
    .expect("second vault keystore");
    let persisted = second_store
        .load(&identifier)
        .expect("load persisted key")
        .expect("key present");
    assert_eq!(persisted.public.to_bytes(), generated.public.to_bytes());

    runtime.block_on(async {
        let _ = shutdown_tx.send(());
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    runtime.block_on(server).expect("server join");
}

#[test]
fn vault_keystore_missing_token_rejected() {
    let err = VaultVrfKeyStore::new(VaultKeystoreConfig {
        address: "http://127.0.0.1:8200".into(),
        mount: "kv".into(),
        namespace: None,
        token: None,
        token_file: None,
        token_env: None,
        tls: None,
        request_timeout_secs: 5,
    })
    .expect_err("missing token should fail");

    match err {
        ChainError::Config(message) => {
            assert!(message.contains("token"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn secrets_adapter_supports_hsm_backend() {
    let temp = tempfile::tempdir().expect("tempdir");

    let secrets = SecretsConfig {
        backend: SecretsBackendConfig::Hsm(HsmKeystoreConfig {
            library_path: Some(temp.path().join("libhsm-emulator.so")),
            slot: Some(0),
            key_id: Some("adapter-hsm".into()),
        }),
    };

    let adapter = SecretsAdapter::new(&secrets, std::path::Path::new("/vrf/adapter"));
    adapter.validate().expect("validation should pass");
    adapter
        .ensure_directories()
        .expect("directories should be created");

    let identifier = adapter.identifier().expect("identifier should resolve");
    let store = adapter.keystore().expect("keystore should build");
    let generated = store
        .load_or_generate(&identifier)
        .expect("store should persist hsm key");
    let reloaded = store
        .load(&identifier)
        .expect("reload should work")
        .expect("key should exist");

    assert_eq!(generated.public.to_bytes(), reloaded.public.to_bytes());

    let keystore_root = match &secrets.backend {
        SecretsBackendConfig::Hsm(config) => config.storage_root(),
        _ => unreachable!("hsm backend required"),
    };
    let expected = keystore_root.join("adapter-hsm.toml");
    assert!(expected.exists(), "hsm adapter should persist vrf keys");
}
