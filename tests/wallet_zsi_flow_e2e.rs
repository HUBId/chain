//! Wallet ZSI lifecycle integration tests.
//!
//! Exercises the high-level ZSI helpers with a deterministic backend to model
//! issuing, proving, verifying, and archiving identity artefacts.

#[path = "common/mod.rs"]
mod common;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use common::wallet::WalletTestBuilder;
use rpp_wallet::config::wallet::WalletZsiConfig;
use rpp_wallet::proof_backend::{
    BackendResult, IdentityPublicInputs, ProofBackend, ProofBytes, ProofHeader, ProofSystemKind,
    ProvingKey, VerifyingKey, WitnessBytes,
};
use rpp_wallet::wallet::{WalletError, ZsiError, ZsiProofRequest, ZsiVerifyRequest};
use rpp_wallet::zsi::{ConsensusApproval, ZsiOperation, ZsiRecord};

#[derive(Default)]
struct RecordingBackend {
    witnesses: Mutex<Vec<Vec<u8>>>,
    inputs: Mutex<Vec<IdentityPublicInputs>>,
}

impl RecordingBackend {
    fn recorded_witnesses(&self) -> Vec<Vec<u8>> {
        self.witnesses
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn recorded_inputs(&self) -> Vec<IdentityPublicInputs> {
        self.inputs
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl ProofBackend for RecordingBackend {
    fn name(&self) -> &'static str {
        "recording"
    }

    fn prove_identity(
        &self,
        _pk: &ProvingKey,
        witness: &WitnessBytes,
    ) -> BackendResult<ProofBytes> {
        if let Ok(mut recorded) = self.witnesses.lock() {
            recorded.push(witness.as_slice().to_vec());
        }
        ProofBytes::encode(
            &ProofHeader::new(ProofSystemKind::Mock, self.name()),
            &witness.as_slice(),
        )
    }

    fn verify_identity(
        &self,
        _vk: &VerifyingKey,
        proof: &ProofBytes,
        inputs: &IdentityPublicInputs,
    ) -> BackendResult<()> {
        if let Ok(mut recorded) = self.inputs.lock() {
            recorded.push(inputs.clone());
        }
        assert!(
            !proof.as_slice().is_empty(),
            "proof payload must be non-empty"
        );
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_zsi_flow_records_and_verifies_lifecycle_state() -> Result<()> {
    let zsi_feature_enabled = cfg!(feature = "wallet_zsi");
    let backend = Arc::new(RecordingBackend::default());

    let mut zsi_config = WalletZsiConfig::default();
    zsi_config.enabled = zsi_feature_enabled;
    zsi_config.backend = Some("recording".into());

    let builder = WalletTestBuilder::default().with_zsi_config(zsi_config.clone());
    let builder = if zsi_feature_enabled {
        builder.with_zsi_backend(backend.clone())
    } else {
        builder
    };
    let fixture = builder.build().context("initialise wallet fixture")?;
    let wallet = fixture.wallet();

    let record = ZsiRecord {
        identity: "alice.wallet".into(),
        genesis_id: "genesis-commitment".into(),
        attestation_digest: "attest-digest".into(),
        approvals: vec![ConsensusApproval {
            validator: "validator-001".into(),
            signature: "signature".into(),
            timestamp: 42,
        }],
    };
    let request = ZsiProofRequest {
        operation: ZsiOperation::Issue,
        record: record.clone(),
    };

    if !zsi_feature_enabled {
        let err = wallet
            .zsi_prove(request.clone())
            .expect_err("zsi should be disabled by feature flag");
        assert!(matches!(err, WalletError::Zsi(ZsiError::Disabled)));
        return Ok(());
    }

    let binding = wallet
        .zsi_bind_account(request.clone())
        .context("prepare zsi binding")?;
    assert_eq!(binding.operation, ZsiOperation::Issue);
    assert_eq!(binding.record.identity, record.identity);

    let proof = wallet
        .zsi_prove(request.clone())
        .context("prove zsi lifecycle")?;
    assert_eq!(proof.backend, "recording");

    let recorded_inputs = backend.recorded_inputs();
    assert_eq!(recorded_inputs.len(), 1);
    assert_eq!(recorded_inputs[0], binding.inputs);
    let recorded_witnesses = backend.recorded_witnesses();
    assert_eq!(recorded_witnesses.len(), 1);
    assert_eq!(recorded_witnesses[0], binding.witness);

    let artifacts = wallet.zsi_list().context("list cached zsi artifacts")?;
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].identity, record.identity);

    wallet
        .zsi_verify(ZsiVerifyRequest {
            operation: ZsiOperation::Issue,
            record: record.clone(),
            proof: proof.raw_proof.clone(),
        })
        .context("verify recorded zsi proof")?;

    wallet
        .zsi_delete(&record.identity, &proof.proof_commitment)
        .context("delete cached zsi artifact")?;
    assert!(wallet.zsi_list().context("list after delete")?.is_empty());

    Ok(())
}
