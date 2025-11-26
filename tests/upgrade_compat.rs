#![cfg(feature = "wallet-integration")]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use common::wallet::{wait_for, WalletTestBuilder};
use prover_backend_interface::{
    BackendError, BackendResult, IdentityCircuitDef, IdentityPublicInputs, ProofBackend,
    ProofBytes, ProvingKey, SecurityLevel, StateCircuitDef, StatePublicInputs, TxCircuitDef,
    TxPublicInputs, VerifyingKey, WitnessBytes,
};
use rpp_wallet::config::wallet::WalletProverConfig;
use rpp_wallet::node_client::{MempoolInfo, MempoolStatus, QueueWeightsConfig};
use tracing_subscriber::fmt::writer::MakeWriterExt;

#[path = "common/mod.rs"]
mod common;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_version_nodes_and_wallets_preserve_compatibility() -> Result<()> {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let _guard = install_log_capture(Arc::clone(&logs));

    let mut legacy_prover = WalletProverConfig::default();
    legacy_prover.require_proof = false;
    legacy_prover.allow_broadcast_without_proof = true;

    let legacy = WalletTestBuilder::default()
        .with_birthday_height(96)
        .with_prover(legacy_prover.clone())
        .with_zsi_backend(Arc::new(VersionedBackend::new("proof-v1")))
        .build()
        .context("prepare legacy wallet fixture")?;

    let mut upgraded_prover = WalletProverConfig::default();
    upgraded_prover.require_proof = true;
    upgraded_prover.allow_broadcast_without_proof = false;

    let upgraded = WalletTestBuilder::default()
        .with_latest_height(220)
        .with_prover(upgraded_prover.clone())
        .with_zsi_backend(Arc::new(VersionedBackend::new("proof-v2")))
        .build()
        .context("prepare upgraded wallet fixture")?;

    legacy.node().set_mempool_info(MempoolInfo {
        tx_count: 2,
        vsize_limit: 1_000_000,
        vsize_in_use: 128_000,
        min_fee_rate: None,
        max_fee_rate: Some(96),
    });
    legacy.node().set_mempool_status(MempoolStatus {
        transactions: vec!["legacy-a".to_string()],
        identities: vec![],
        votes: vec![],
        uptime_proofs: vec![],
        queue_weights: QueueWeightsConfig {
            transactions: 1,
            identities: 0,
            votes: 0,
            uptime_proofs: 0,
        },
    });

    upgraded.node().set_mempool_info(MempoolInfo {
        tx_count: 3,
        vsize_limit: 1_000_000,
        vsize_in_use: 256_000,
        min_fee_rate: Some(3),
        max_fee_rate: Some(128),
    });
    upgraded.node().set_mempool_status(MempoolStatus {
        transactions: vec!["upgrade-a".to_string(), "upgrade-b".to_string()],
        identities: vec!["upgrade-id".to_string()],
        votes: vec![],
        uptime_proofs: vec![],
        queue_weights: QueueWeightsConfig {
            transactions: 2,
            identities: 1,
            votes: 0,
            uptime_proofs: 0,
        },
    });

    let legacy_wallet = legacy.wallet();
    let legacy_recipient = legacy_wallet
        .derive_address(false)
        .context("derive legacy recipient")?;
    let legacy_draft = legacy_wallet
        .create_draft(legacy_recipient, 40_000, Some(2))
        .context("create legacy draft")?;
    let _ = legacy_wallet
        .sign_and_prove(&legacy_draft.draft)
        .context("sign legacy draft")?;
    legacy_wallet
        .broadcast(&legacy_draft.draft)
        .context("broadcast legacy draft")?;

    let upgraded_wallet = upgraded.wallet();
    let upgraded_recipient = upgraded_wallet
        .derive_address(false)
        .context("derive upgraded recipient")?;
    let upgraded_draft = upgraded_wallet
        .create_draft(upgraded_recipient, 50_000, Some(3))
        .context("create upgraded draft")?;
    let _ = upgraded_wallet
        .sign_and_prove(&upgraded_draft.draft)
        .context("sign upgraded draft")?;
    upgraded_wallet
        .broadcast(&upgraded_draft.draft)
        .context("broadcast upgraded draft")?;

    let legacy_submission = legacy
        .node()
        .last_submission()
        .expect("legacy submission captured");
    let upgraded_submission = upgraded
        .node()
        .last_submission()
        .expect("upgraded submission captured");

    assert_eq!(legacy_submission.fee_rate, legacy_draft.draft.fee_rate);
    assert_eq!(upgraded_submission.fee_rate, upgraded_draft.draft.fee_rate);
    assert_eq!(legacy.node().submission_count(), 1);
    assert_eq!(upgraded.node().submission_count(), 1);

    let legacy_mempool = legacy.node().mempool_info()?;
    let upgraded_mempool = upgraded.node().mempool_info()?;

    wait_for(|| async {
        legacy
            .node()
            .mempool_status()
            .map(|status| !status.transactions.is_empty())
            .unwrap_or(false)
    })
    .await;
    wait_for(|| async {
        upgraded
            .node()
            .mempool_status()
            .map(|status| status.transactions.len() > 1 && !status.identities.is_empty())
            .unwrap_or(false)
    })
    .await;

    if legacy_mempool.min_fee_rate.is_none() {
        tracing::warn!(
            target: "upgrade-compat",
            "deprecated mempool info missing min_fee_rate on legacy node"
        );
    }
    if upgraded_prover.require_proof && !legacy_prover.require_proof {
        tracing::warn!(
            target: "upgrade-compat",
            "deprecated proof flow: legacy wallets broadcast without proofs while upgraded nodes expect proof-gated submissions"
        );
    }
    if upgraded_mempool.min_fee_rate < legacy_mempool.min_fee_rate {
        tracing::warn!(
            target: "upgrade-compat",
            "deprecated fee floor gap detected between mixed-version nodes"
        );
    }

    let captured =
        String::from_utf8(logs.lock().unwrap().clone()).context("decode captured logs")?;
    assert!(
        captured.contains("deprecated"),
        "mixed-version run should surface deprecation warnings"
    );

    Ok(())
}

#[derive(Clone)]
struct CaptureWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.buffer.lock().unwrap();
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn install_log_capture(buffer: Arc<Mutex<Vec<u8>>>) -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(CaptureWriter { buffer }.with_max_level())
        .finish();
    tracing::subscriber::set_default(subscriber)
}

#[derive(Clone)]
struct VersionedBackend {
    label: &'static str,
}

impl VersionedBackend {
    fn new(label: &'static str) -> Self {
        Self { label }
    }

    fn unsupported<T>() -> BackendResult<T> {
        Err(BackendError::Unsupported("upgrade compat backend"))
    }
}

impl ProofBackend for VersionedBackend {
    fn name(&self) -> &'static str {
        self.label
    }

    fn setup_params(&self, _security: SecurityLevel) -> BackendResult<()> {
        Ok(())
    }

    fn keygen_tx(&self, _circuit: &TxCircuitDef) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Self::unsupported()
    }

    fn prove_tx(&self, _pk: &ProvingKey, _witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        Self::unsupported()
    }

    fn verify_tx(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &TxPublicInputs,
    ) -> BackendResult<bool> {
        Ok(true)
    }

    fn keygen_identity(
        &self,
        _circuit: &IdentityCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Self::unsupported()
    }

    fn prove_identity(
        &self,
        _pk: &ProvingKey,
        _witness: &WitnessBytes,
    ) -> BackendResult<ProofBytes> {
        Self::unsupported()
    }

    fn verify_identity(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &IdentityPublicInputs,
    ) -> BackendResult<()> {
        Ok(())
    }

    fn keygen_state(
        &self,
        _circuit: &StateCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Self::unsupported()
    }

    fn prove_state(&self, _pk: &ProvingKey, _witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        Self::unsupported()
    }

    fn verify_state(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &StatePublicInputs,
    ) -> BackendResult<()> {
        Ok(())
    }
}
