#![cfg(all(feature = "wallet-integration", feature = "wallet_multisig_hooks"))]

//! Wallet multisig coordinator integration tests.

#[path = "common/mod.rs"]
mod common;

use anyhow::Result;
use common::wallet::WalletTestBuilder;
use rpp_wallet::multisig::{Cosigner, CosignerRegistry, MultisigScope};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multisig_coordinator_persists_exports() -> Result<()> {
    let fixture = WalletTestBuilder::default().build()?;
    let wallet = fixture.wallet();

    let scope = MultisigScope::new(2, 3)?;
    let registry = CosignerRegistry::new(vec![
        Cosigner::new("aa11bb22cc33dd44ee55ff66aa77bb88", Some("https://cosigner.one"))?,
        Cosigner::new("bb11bb22cc33dd44ee55ff66aa77bb88", None)?,
    ])?;

    wallet.set_multisig_scope(Some(scope.clone()))?;
    wallet.set_cosigner_registry(Some(registry.clone()))?;

    let destination = wallet.derive_address(false)?;
    let draft = wallet.create_draft(destination, 50_000, Some(1))?;
    let metadata = draft
        .metadata
        .multisig
        .clone()
        .expect("multisig metadata present");

    assert_eq!(metadata.scope, scope);
    assert_eq!(metadata.cosigners, registry.to_vec());

    let export = wallet
        .multisig_coordinator()
        .export_metadata("draft-1", draft.metadata.multisig.clone())?;
    assert_eq!(export.draft_id, "draft-1");

    let persisted = wallet
        .multisig_coordinator()
        .load_export("draft-1")?
        .expect("export persisted");
    assert_eq!(persisted, metadata);

    Ok(())
}
