#![cfg(feature = "wallet_rpc_mtls")]

//! Wallet RBAC and mTLS integration tests.
//!
//! Exercises the security context helpers backed by the mocked wallet fixture
//! to ensure bearer-token and certificate identities map to the expected role
//! sets persisted in the RBAC store.

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use anyhow::{Context, Result};
use common::wallet::{wait_for, WalletTestBuilder};
use rpp_chain::runtime::wallet::rpc::security::{
    WalletClientCertificates, WalletIdentity, WalletRbacStore, WalletRole, WalletRoleSet,
    WalletSecurityBinding, WalletSecurityContext, WalletSecurityPaths,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_rbac_resolves_roles_for_bearer_and_mtls_identities() -> Result<()> {
    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![82_000])
        .build()
        .context("initialise wallet fixture")?;
    let wallet = fixture.wallet();
    let sync = Arc::new(
        fixture
            .start_sync()
            .context("start wallet sync coordinator")?,
    );

    wait_for(|| {
        let wallet = Arc::clone(&wallet);
        async move {
            wallet
                .list_utxos()
                .map(|utxos| !utxos.is_empty())
                .unwrap_or(false)
        }
    })
    .await;

    let data_dir = wallet
        .keystore_path()
        .parent()
        .context("wallet keystore directory")?
        .to_path_buf();
    let security_paths = WalletSecurityPaths::from_data_dir(&data_dir);
    security_paths
        .ensure()
        .context("ensure security path exists")?;

    let mut store =
        WalletRbacStore::load(security_paths.rbac_store()).context("load rbac store")?;
    let token_identity = WalletIdentity::from_bearer_token("operator-token");
    let certificate_bytes = b"client-certificate";
    let certificate_identity = WalletIdentity::from_certificate_der(certificate_bytes);

    let mut operator_roles = WalletRoleSet::new();
    operator_roles.insert(WalletRole::Operator);
    let mut viewer_roles = WalletRoleSet::new();
    viewer_roles.insert(WalletRole::Viewer);

    store.apply_bindings(&[
        WalletSecurityBinding::new(token_identity.clone(), operator_roles.clone()),
        WalletSecurityBinding::new(certificate_identity.clone(), viewer_roles.clone()),
    ]);
    store.save().context("persist rbac bindings")?;

    let context = WalletSecurityContext::from_store(store);
    let combined = context.resolve_roles(&[token_identity.clone(), certificate_identity.clone()]);
    assert!(combined.contains(&WalletRole::Operator));
    if cfg!(feature = "wallet_rpc_mtls") {
        assert!(combined.contains(&WalletRole::Viewer));
    }

    let token_roles = context.resolve_roles(&[token_identity.clone()]);
    assert_eq!(token_roles.len(), 1);
    assert!(token_roles.contains(&WalletRole::Operator));

    let certificate_roles = context.resolve_roles(&[certificate_identity.clone()]);
    if cfg!(feature = "wallet_rpc_mtls") {
        assert!(certificate_roles.contains(&WalletRole::Viewer));
    }

    let presented = WalletClientCertificates::from_der([certificate_bytes.as_slice()]);
    assert!(!presented.is_empty());
    if cfg!(feature = "wallet_rpc_mtls") {
        let identities = presented.identities();
        assert!(identities.contains(&certificate_identity));
    }

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}
