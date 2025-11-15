#![cfg(feature = "wallet_zsi")]

//! These tests require the `wallet_zsi` feature. Enable with `--features wallet_zsi`.

use std::sync::Arc;

use prover_mock_backend::MockBackend;
use rpp::runtime::telemetry::metrics::RuntimeMetrics;
use rpp_wallet::config::wallet::{
    WalletFeeConfig, WalletHwConfig, WalletPolicyConfig, WalletProverConfig, WalletZsiConfig,
};
use rpp_wallet::db::WalletStore;
use rpp_wallet::node_client::StubNodeClient;
use rpp_wallet::telemetry::WalletActionTelemetry;
use rpp_wallet::wallet::{
    Wallet, WalletError, WalletMode, WalletPaths, WatchOnlyError, ZsiProofRequest, ZsiVerifyRequest,
};
use rpp_wallet::zsi::prove::hash_hex;
use rpp_wallet::zsi::{ConsensusApproval, ZsiOperation, ZsiRecord};
use tempfile::tempdir;

type DynBackend = Arc<dyn prover_backend_interface::ProofBackend>;

struct WalletHarness {
    wallet: Arc<Wallet>,
    _tempdir: tempfile::TempDir,
}

fn mock_backend() -> DynBackend {
    Arc::new(MockBackend::new())
}

impl WalletHarness {
    fn new(mode: WalletMode, zsi_config: WalletZsiConfig, backend: Option<DynBackend>) -> Self {
        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("wallet store"));
        let policy = WalletPolicyConfig::default();
        let fees = WalletFeeConfig::default();
        let prover = WalletProverConfig::default();
        let node_client: Arc<dyn rpp_wallet::node_client::NodeClient> =
            Arc::new(StubNodeClient::default());
        let paths = WalletPaths::for_data_dir(tempdir.path());
        let wallet = Wallet::new(
            Arc::clone(&store),
            mode,
            policy,
            fees,
            prover,
            WalletHwConfig::default(),
            zsi_config,
            backend,
            node_client,
            paths,
            Arc::new(WalletActionTelemetry::new(true)),
        )
        .expect("wallet");
        Self {
            wallet: Arc::new(wallet),
            _tempdir: tempdir,
        }
    }

    fn with_zsi_enabled() -> Self {
        let backend = mock_backend();
        let mut config = WalletZsiConfig::default();
        config.enabled = true;
        config.backend = Some("mock".into());
        Self::new(
            WalletMode::Full {
                root_seed: [9u8; 32],
            },
            config,
            Some(backend),
        )
    }
}

fn sample_approval() -> ConsensusApproval {
    ConsensusApproval {
        validator: "validator-1".into(),
        signature: "feedcafe".into(),
        timestamp: 11,
    }
}

fn sample_record() -> ZsiRecord {
    ZsiRecord {
        identity: "alice".into(),
        genesis_id: "genesis-1".into(),
        attestation_digest: hash_hex("initial-proof"),
        approvals: vec![sample_approval()],
    }
}

fn sample_request(operation: ZsiOperation) -> ZsiProofRequest {
    ZsiProofRequest {
        operation,
        record: sample_record(),
    }
}

#[test]
fn wallet_proves_verifies_and_persists_mock_artifact() {
    let harness = WalletHarness::with_zsi_enabled();
    let wallet = &harness.wallet;

    let request = sample_request(ZsiOperation::Issue);
    let binding = wallet
        .zsi_bind_account(request.clone())
        .expect("bind account");
    assert_eq!(binding.operation, ZsiOperation::Issue);
    assert_eq!(binding.record.identity, request.record.identity);

    let proof = wallet.zsi_prove(request.clone()).expect("prove");
    assert_eq!(proof.backend, "mock");
    assert_eq!(proof.operation, "issue");
    assert_eq!(
        proof.witness_digest,
        hash_hex(binding.witness.as_slice()),
        "witness digest recorded",
    );
    assert!(!proof.raw_proof.is_empty(), "proof payload non-empty");

    let artifacts = wallet.zsi_list().expect("list artifacts");
    assert_eq!(artifacts.len(), 1);
    let artifact = &artifacts[0];
    assert_eq!(artifact.identity, request.record.identity);
    assert_eq!(artifact.backend, "mock");
    assert_eq!(artifact.commitment_digest, proof.proof_commitment);

    wallet
        .zsi_verify(ZsiVerifyRequest {
            operation: request.operation,
            record: request.record.clone(),
            proof: proof.raw_proof.clone(),
        })
        .expect("verify");

    let mut corrupted = proof.raw_proof.clone();
    corrupted[0] ^= 0xff;
    let error = wallet
        .zsi_verify(ZsiVerifyRequest {
            operation: request.operation,
            record: request.record.clone(),
            proof: corrupted,
        })
        .expect_err("corrupted proof rejected");
    match error {
        WalletError::Zsi(inner) => match inner {
            rpp_wallet::wallet::ZsiError::Backend(_) => {}
            other => panic!("unexpected ZSI error: {other}"),
        },
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn binding_rejected_for_watch_only_and_disabled_modes() {
    let mut zsi_enabled = WalletZsiConfig::default();
    zsi_enabled.enabled = true;
    zsi_enabled.backend = Some("mock".into());
    let watch_only_backend = mock_backend();
    let watch_only_wallet = WalletHarness::new(
        WalletMode::WatchOnly(rpp_wallet::modes::watch_only::WatchOnlyRecord::new(
            "wpkh(descriptor)",
        )),
        zsi_enabled.clone(),
        Some(watch_only_backend),
    );

    let request = sample_request(ZsiOperation::Audit);
    let error = watch_only_wallet
        .wallet
        .zsi_bind_account(request.clone())
        .expect_err("watch-only binding should fail");
    match error {
        WalletError::WatchOnly(WatchOnlyError::SigningDisabled) => {}
        other => panic!("unexpected watch-only error: {other}"),
    }

    let disabled_wallet = WalletHarness::new(
        WalletMode::Full {
            root_seed: [7u8; 32],
        },
        WalletZsiConfig::default(),
        Some(mock_backend()),
    );
    let error = disabled_wallet
        .wallet
        .zsi_bind_account(request)
        .expect_err("zsi disabled");
    match error {
        WalletError::Zsi(rpp_wallet::wallet::ZsiError::Disabled) => {}
        other => panic!("unexpected zsi error: {other}"),
    }
}

#[test]
fn cli_wallet_args_roundtrip_with_mock_backend() {
    use rpp_wallet::cli::zsi::{
        ZsiWalletBindArgs, ZsiWalletProofArgs, ZsiWalletProveArgs, ZsiWalletVerifyArgs,
    };

    let harness = WalletHarness::with_zsi_enabled();
    let wallet = &harness.wallet;
    let approvals = vec![sample_approval()];

    let base_args = ZsiWalletProofArgs {
        operation: "issue".into(),
        identity: "alice".into(),
        genesis_id: "genesis-1".into(),
        attestation: "initial-proof".into(),
        approvals: approvals.clone(),
    };

    let prove_request = ZsiWalletProveArgs {
        proof: base_args.clone(),
    }
    .into_request()
    .expect("prove args");
    let proof = wallet.zsi_prove(prove_request.clone()).expect("prove");

    let verify_args = ZsiWalletVerifyArgs {
        proof: base_args.clone(),
        proof_hex: hex::encode(&proof.raw_proof),
    };
    let verify_request = verify_args.into_request().expect("verify args");
    wallet
        .zsi_verify(verify_request)
        .expect("verify from cli args");

    let bind_request = ZsiWalletBindArgs { proof: base_args }
        .into_request()
        .expect("bind args");
    let binding = wallet
        .zsi_bind_account(bind_request)
        .expect("cli bind request");
    let expected_address: [u8; 32] =
        rpp_wallet::proof_backend::Blake2sHasher::hash(b"alice").into();
    assert_eq!(binding.inputs.wallet_address, expected_address);
    assert_eq!(
        binding.inputs.vrf_tag,
        hash_hex("initial-proof").into_bytes(),
    );
    assert_eq!(binding.record.identity, "alice");
}

#[test]
fn rpc_router_handles_zsi_binding_and_proof_paths() {
    use rpp_wallet::rpc::dto::{
        JsonRpcRequest, ZsiBindResponse, ZsiProofParams, ZsiProveResponse, ZsiVerifyParams,
        ZsiVerifyResponse, JSONRPC_VERSION,
    };
    use rpp_wallet::rpc::WalletRpcRouter;

    let harness = WalletHarness::with_zsi_enabled();
    let wallet = Arc::clone(&harness.wallet);
    let metrics = RuntimeMetrics::noop();
    let router = WalletRpcRouter::new(wallet, None, metrics);

    let params = ZsiProofParams {
        operation: ZsiOperation::Issue,
        record: sample_record(),
    };
    let bind_response = router.handle(JsonRpcRequest {
        jsonrpc: Some(JSONRPC_VERSION.to_string()),
        id: Some(serde_json::json!(1)),
        method: "zsi.bind_account".into(),
        params: Some(serde_json::to_value(params.clone()).unwrap()),
    });
    assert!(
        bind_response.error.is_none(),
        "bind response error: {:?}",
        bind_response.error
    );
    let bind: ZsiBindResponse = serde_json::from_value(bind_response.result.unwrap()).unwrap();

    let prove_response = router.handle(JsonRpcRequest {
        jsonrpc: Some(JSONRPC_VERSION.to_string()),
        id: Some(serde_json::json!(2)),
        method: "zsi.prove".into(),
        params: Some(serde_json::to_value(params.clone()).unwrap()),
    });
    assert!(
        prove_response.error.is_none(),
        "prove response error: {:?}",
        prove_response.error
    );
    let proved: ZsiProveResponse =
        serde_json::from_value(prove_response.result.unwrap()).expect("parse prove response");

    let verify_response = router.handle(JsonRpcRequest {
        jsonrpc: Some(JSONRPC_VERSION.to_string()),
        id: Some(serde_json::json!(3)),
        method: "zsi.verify".into(),
        params: Some(
            serde_json::to_value(ZsiVerifyParams {
                operation: ZsiOperation::Issue,
                record: sample_record(),
                proof: proved.proof.raw_proof.clone(),
            })
            .unwrap(),
        ),
    });
    assert!(
        verify_response.error.is_none(),
        "verify response error: {:?}",
        verify_response.error
    );
    let verify: ZsiVerifyResponse =
        serde_json::from_value(verify_response.result.unwrap()).expect("parse verify response");
    assert!(verify.valid);

    assert_eq!(bind.binding.operation, ZsiOperation::Issue);
    assert_eq!(bind.binding.record.identity, "alice");
    assert_eq!(proved.proof.backend, "mock");
}
