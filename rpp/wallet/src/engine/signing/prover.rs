use std::convert::TryFrom;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::wallet::{WalletProverBackend, WalletProverConfig};

use super::{
    DraftProverContext, ProveResult, ProverError, ProverIdentity, ProverMeta, WalletProver,
    WitnessPlan,
};
use crate::engine::DraftTransaction;
use metrics::{counter, histogram};
use prover_backend_interface::{
    Blake2sHasher, ProofBytes, ProofHeader, ProofSystemKind, WitnessBytes, WitnessHeader,
};
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task;
use tokio::time::{timeout_at, Instant as TokioInstant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeroize::Zeroize;

#[cfg(feature = "prover-stwo")]
use crate::engine::SpendModel;
#[cfg(feature = "prover-stwo")]
use ed25519_dalek::SigningKey;
#[cfg(feature = "prover-stwo")]
use prover_backend_interface::Blake2sHasher;
#[cfg(feature = "prover-stwo")]
use prover_backend_interface::{ProvingKey, TxCircuitDef};
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::backend::StwoBackend;
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::official::circuit::transaction::TransactionWitness;
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::reputation::{ReputationProfile, ReputationWeights, Tier};
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::types::{Account, SignedTransaction, Stake, Transaction};

const MOCK_CIRCUIT_ID: &str = "wallet.tx";
#[cfg(feature = "prover-stwo")]
const STWO_CIRCUIT_ID: &str = "transaction";
#[cfg(feature = "prover-stwo")]
const STWO_WITNESS_CIRCUIT: &str = "tx";

pub fn build_wallet_prover(
    config: &WalletProverConfig,
) -> Result<Arc<dyn WalletProver>, ProverError> {
    if !config.enabled {
        return Ok(Arc::new(DisabledWalletProver::new(
            "wallet prover backend disabled",
        )));
    }
    match config.backend {
        WalletProverBackend::Mock => {
            #[cfg(feature = "prover-mock")]
            {
                Ok(Arc::new(MockWalletProver::new(config)))
            }
            #[cfg(not(feature = "prover-mock"))]
            {
                Err(ProverError::Unsupported(
                    "mock prover requested but feature disabled",
                ))
            }
        }
        WalletProverBackend::Stwo => {
            #[cfg(feature = "prover-stwo")]
            {
                Ok(Arc::new(StwoWalletProver::new(config)?))
            }
            #[cfg(not(feature = "prover-stwo"))]
            {
                Err(ProverError::Unsupported(
                    "STWO prover requested but feature disabled",
                ))
            }
        }
    }
}

#[cfg(feature = "prover-mock")]
struct MockWalletProver {
    jobs: ProverJobManager,
}

#[cfg(feature = "prover-mock")]
impl MockWalletProver {
    fn new(config: &WalletProverConfig) -> Self {
        Self {
            jobs: ProverJobManager::new(config),
        }
    }
}

#[cfg(feature = "prover-mock")]
impl WalletProver for MockWalletProver {
    fn identity(&self) -> ProverIdentity {
        ProverIdentity::new("mock", false)
    }

    fn prepare_witness(&self, ctx: &DraftProverContext<'_>) -> Result<WitnessPlan, ProverError> {
        let backend = self.identity().backend;
        let result = (|| {
            let witness_header = WitnessHeader::new(ProofSystemKind::Mock, MOCK_CIRCUIT_ID);
            let mut payload = bincode::serialize(ctx.draft())
                .map_err(|err| ProverError::Serialization(err.to_string()))?;
            let witness = WitnessBytes::encode(&witness_header, &payload)?;
            payload.zeroize();
            debug_assert_zeroized(&payload);
            let witness_bytes = witness.as_slice().len();
            self.jobs.ensure_witness_capacity(backend, witness_bytes)?;
            Ok((witness, witness_bytes))
        })();

        result
            .map(|(witness, _)| {
                let plan = WitnessPlan::with_parts(witness, Instant::now());
                record_prepare_success(backend, plan.witness_bytes());
                plan
            })
            .map_err(|err| {
                record_prepare_error(backend, &err);
                err
            })
    }

    fn prove(
        &self,
        _ctx: &DraftProverContext<'_>,
        plan: WitnessPlan,
    ) -> Result<ProveResult, ProverError> {
        let backend = self.identity().backend;
        let result = prove_with_plan(backend, &self.jobs, plan, move |mut witness| {
            let proof_header = ProofHeader::new(ProofSystemKind::Mock, MOCK_CIRCUIT_ID);
            let proof = ProofBytes::encode(&proof_header, witness.as_slice())?;
            let mut witness_buffer = witness.into_inner();
            witness_buffer.zeroize();
            debug_assert_zeroized(&witness_buffer);
            Ok(proof)
        });

        result
            .map(|result| {
                record_prove_success(backend, &result);
                result
            })
            .map_err(|err| {
                record_prove_error(backend, &err);
                err
            })
    }

    fn attest_metadata(
        &self,
        _ctx: &DraftProverContext<'_>,
        result: &ProveResult,
    ) -> Result<ProverMeta, ProverError> {
        Ok(attest_default(self.identity().backend, result))
    }
}

#[cfg(feature = "prover-stwo")]
struct StwoWalletProver {
    backend: Arc<StwoBackend>,
    proving_key: Arc<ProvingKey>,
    jobs: ProverJobManager,
}

#[cfg(feature = "prover-stwo")]
impl StwoWalletProver {
    fn new(config: &WalletProverConfig) -> Result<Self, ProverError> {
        let backend = StwoBackend::new();
        let circuit = TxCircuitDef::new(STWO_CIRCUIT_ID);
        let (proving_key, _verifying_key) = backend.keygen_tx(&circuit)?;
        Ok(Self {
            backend: Arc::new(backend),
            proving_key: Arc::new(proving_key),
            jobs: ProverJobManager::new(config),
        })
    }
}

#[cfg(feature = "prover-stwo")]
impl WalletProver for StwoWalletProver {
    fn identity(&self) -> ProverIdentity {
        ProverIdentity::new("stwo", false)
    }

    fn prepare_witness(&self, ctx: &DraftProverContext<'_>) -> Result<WitnessPlan, ProverError> {
        let backend = self.identity().backend;
        let result = build_stwo_witness(ctx.draft()).and_then(|(witness, witness_bytes)| {
            self.jobs.ensure_witness_capacity(backend, witness_bytes)?;
            Ok((witness, witness_bytes))
        });

        result
            .map(|(witness, _)| {
                let plan = WitnessPlan::with_parts(witness, Instant::now());
                record_prepare_success(backend, plan.witness_bytes());
                plan
            })
            .map_err(|err| {
                record_prepare_error(backend, &err);
                err
            })
    }

    fn prove(
        &self,
        _ctx: &DraftProverContext<'_>,
        plan: WitnessPlan,
    ) -> Result<ProveResult, ProverError> {
        let backend_label = self.identity().backend;
        let backend = Arc::clone(&self.backend);
        let proving_key = Arc::clone(&self.proving_key);
        let result = prove_with_plan(backend_label, &self.jobs, plan, move |mut witness| {
            let proof = backend.prove_tx(&proving_key, &witness)?;
            let mut witness_buffer = witness.into_inner();
            witness_buffer.zeroize();
            debug_assert_zeroized(&witness_buffer);
            Ok(proof)
        });

        result
            .map(|result| {
                record_prove_success(backend_label, &result);
                result
            })
            .map_err(|err| {
                record_prove_error(backend_label, &err);
                err
            })
    }

    fn attest_metadata(
        &self,
        _ctx: &DraftProverContext<'_>,
        result: &ProveResult,
    ) -> Result<ProverMeta, ProverError> {
        Ok(attest_default(self.identity().backend, result))
    }
}

struct DisabledWalletProver {
    reason: &'static str,
}

impl DisabledWalletProver {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl WalletProver for DisabledWalletProver {
    fn identity(&self) -> ProverIdentity {
        ProverIdentity::new("disabled", true)
    }

    fn prepare_witness(&self, _ctx: &DraftProverContext<'_>) -> Result<WitnessPlan, ProverError> {
        Err(ProverError::Unsupported(self.reason))
    }

    fn prove(
        &self,
        _ctx: &DraftProverContext<'_>,
        _plan: WitnessPlan,
    ) -> Result<ProveResult, ProverError> {
        Err(ProverError::Unsupported(self.reason))
    }

    fn attest_metadata(
        &self,
        _ctx: &DraftProverContext<'_>,
        _result: &ProveResult,
    ) -> Result<ProverMeta, ProverError> {
        Err(ProverError::Unsupported(self.reason))
    }
}

pub(crate) struct ProverJobManager {
    semaphore: Option<Arc<Semaphore>>,
    timeout: Option<Duration>,
    witness_limit: u64,
}

impl ProverJobManager {
    pub(crate) fn new(config: &WalletProverConfig) -> Self {
        let semaphore = if config.max_concurrency == 0 {
            None
        } else {
            let permits = usize::try_from(config.max_concurrency).unwrap_or(usize::MAX);
            Some(Arc::new(Semaphore::new(permits)))
        };
        let timeout = if config.timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(config.timeout_secs))
        };
        Self {
            semaphore,
            timeout,
            witness_limit: config.max_witness_bytes,
        }
    }

    fn ensure_witness_capacity(
        &self,
        backend: &'static str,
        witness_bytes: usize,
    ) -> Result<(), ProverError> {
        if self.witness_limit > 0 && (witness_bytes as u64) > self.witness_limit {
            warn!(
                backend,
                witness_bytes,
                limit = self.witness_limit,
                "wallet prover witness exceeds configured limit"
            );
            return Err(ProverError::WitnessTooLarge {
                size: witness_bytes,
                limit: self.witness_limit,
            });
        }
        Ok(())
    }

    fn acquire(&self) -> Result<ProverJobPermit, ProverError> {
        let permit = if let Some(semaphore) = &self.semaphore {
            Some(
                semaphore
                    .try_acquire_owned()
                    .map_err(|_| ProverError::Busy)?,
            )
        } else {
            None
        };
        let deadline = self.timeout.map(|timeout| Instant::now() + timeout);
        Ok(ProverJobPermit {
            _permit: permit,
            deadline,
            timeout: self.timeout,
            token: CancellationToken::new(),
        })
    }
}

struct ProverJobPermit {
    _permit: Option<OwnedSemaphorePermit>,
    deadline: Option<Instant>,
    timeout: Option<Duration>,
    token: CancellationToken,
}

impl ProverJobPermit {
    fn cancellation_token(&self) -> CancellationToken {
        self.token.clone()
    }

    async fn wait<F, T>(self, future: F) -> Result<T, ProverError>
    where
        F: Future<Output = Result<T, ProverError>>,
    {
        if let Some(deadline) = self.deadline {
            let deadline = TokioInstant::from_std(deadline);
            match timeout_at(deadline, future).await {
                Ok(result) => result,
                Err(_) => {
                    self.token.cancel();
                    let secs = self
                        .timeout
                        .map(|value| value.as_secs())
                        .unwrap_or_default();
                    warn!(timeout_secs = secs, "wallet prover job exceeded timeout");
                    Err(ProverError::Timeout(secs))
                }
            }
        } else {
            future.await
        }
    }
}

#[cfg(feature = "prover-stwo")]
fn build_stwo_witness(draft: &DraftTransaction) -> Result<(WitnessBytes, usize), ProverError> {
    use std::convert::TryInto;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut encoded =
        bincode::serialize(draft).map_err(|err| ProverError::Serialization(err.to_string()))?;
    let mut entropy: [u8; 32] = Blake2sHasher::hash(&encoded).into();
    encoded.zeroize();
    debug_assert_zeroized(&encoded);
    let signing_key = SigningKey::from_bytes(&entropy);
    let verifying_key = signing_key.verifying_key();
    let sender_address = wallet_address_from_public_key(&verifying_key);

    let mut nonce = u64::from_le_bytes(entropy[0..8].try_into().expect("slice length 8"));
    if nonce == 0 {
        nonce = 1;
    }
    let timestamp_seed = u64::from_le_bytes(entropy[8..16].try_into().expect("slice length 8"));
    let timestamp = if timestamp_seed == 0 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    } else {
        1_700_000_000u64.saturating_add(timestamp_seed % 1_000_000)
    };

    let (recipient_address, amount) = select_recipient(draft);
    let fee = u64::try_from(draft.fee)
        .map_err(|_| ProverError::Serialization("draft fee exceeds u64".into()))?;
    let total = amount
        .checked_add(u128::from(fee))
        .ok_or_else(|| ProverError::Serialization("draft amount overflow".into()))?;
    let mut sender_balance = draft.total_input_value();
    if sender_balance < total {
        sender_balance = total;
    }

    let receiver_balance = if matches!(draft.spend_model, SpendModel::Account { .. }) {
        amount.saturating_mul(2)
    } else {
        amount
    };

    let payload = Transaction {
        from: sender_address.clone(),
        to: recipient_address.clone(),
        amount,
        fee,
        nonce,
        memo: None,
        timestamp,
    };
    let signature = signing_key.sign(&payload.canonical_bytes());
    let signed_tx = SignedTransaction::new(payload, signature, &verifying_key);

    let mut sender_account = Account::new(sender_address.clone(), sender_balance, Stake::default());
    sender_account.nonce = nonce.saturating_sub(1);
    sender_account.reputation = ReputationProfile::new(&signed_tx.public_key);
    sender_account.reputation.zsi.validated = true;
    sender_account.reputation.timetokes.balance = 24;
    sender_account
        .reputation
        .recompute_score(&ReputationWeights::default(), timestamp);
    sender_account.reputation.update_decay_reference(timestamp);

    let mut receiver_account = Account::new(
        recipient_address.clone(),
        receiver_balance,
        Stake::default(),
    );
    receiver_account.reputation = ReputationProfile::new(&signed_tx.public_key);
    receiver_account.reputation.wallet_commitment = Some(recipient_address.clone());
    receiver_account.reputation.zsi.validated = true;
    receiver_account
        .reputation
        .recompute_score(&ReputationWeights::default(), timestamp);
    receiver_account
        .reputation
        .update_decay_reference(timestamp);

    let witness = TransactionWitness {
        signed_tx,
        sender_account,
        receiver_account: Some(receiver_account),
        required_tier: Tier::Tl1,
        reputation_weights: ReputationWeights::default(),
    };
    let header = WitnessHeader::new(ProofSystemKind::Stwo, STWO_WITNESS_CIRCUIT);
    let witness_bytes = WitnessBytes::encode(&header, &witness)?;
    let len = witness_bytes.as_slice().len();
    entropy.zeroize();
    debug_assert_zeroized(&entropy);
    Ok((witness_bytes, len))
}

#[cfg(feature = "prover-stwo")]
fn select_recipient(draft: &DraftTransaction) -> (String, u128) {
    let mut recipients = draft
        .outputs
        .iter()
        .filter(|output| !output.change)
        .collect::<Vec<_>>();
    if recipients.is_empty() {
        recipients = draft.outputs.iter().collect();
    }
    let address = recipients
        .first()
        .map(|output| output.address.clone())
        .unwrap_or_else(|| "wallet.recipient".to_string());
    let amount = recipients.iter().map(|output| output.value).sum::<u128>();
    (address, amount)
}

#[cfg(feature = "prover-stwo")]
fn wallet_address_from_public_key(key: &ed25519_dalek::VerifyingKey) -> String {
    let hash: [u8; 32] = Blake2sHasher::hash(key.as_bytes()).into();
    hex::encode(hash)
}

fn debug_assert_zeroized(buf: &[u8]) {
    debug_assert!(
        buf.iter().all(|byte| *byte == 0),
        "sensitive prover buffer should be zeroized",
    );
}

fn prove_with_plan<F>(
    backend: &'static str,
    jobs: &ProverJobManager,
    plan: WitnessPlan,
    prove_fn: F,
) -> Result<ProveResult, ProverError>
where
    F: FnOnce(WitnessBytes) -> Result<ProofBytes, ProverError> + Send + 'static,
{
    let witness_bytes = plan.witness_bytes();
    let witness = plan.into_witness().ok_or_else(|| {
        ProverError::Runtime(format!("{backend} witness unavailable during proving"))
    })?;
    let permit = jobs.acquire()?;
    let handle = Handle::try_current().map_err(|err| {
        ProverError::Runtime(format!("tokio runtime handle not available: {err}"))
    })?;
    handle.block_on(async move {
        let token = permit.cancellation_token();
        let started_at = Instant::now();
        let job = task::spawn_blocking(move || {
            if token.is_cancelled() {
                return Err(ProverError::Cancelled);
            }
            prove_fn(witness)
        });
        let proof = permit
            .wait(async move { job.await.map_err(map_blocking_error)? })
            .await?;
        let finished_at = Instant::now();
        let duration_ms = finished_at
            .checked_duration_since(started_at)
            .unwrap_or_default()
            .as_millis() as u64;
        info!(
            backend,
            witness_bytes,
            proof_bytes = proof.as_ref().len(),
            duration_ms,
            "wallet prover job completed"
        );
        Ok(ProveResult::new(
            Some(proof),
            witness_bytes,
            started_at,
            finished_at,
        ))
    })
}

fn attest_default(backend: &'static str, result: &ProveResult) -> ProverMeta {
    let proof_bytes = result.proof().map(|proof| proof.as_ref().len());
    let proof_hash = result.proof().map(|proof| {
        let digest: [u8; 32] = Blake2sHasher::hash(proof.as_ref()).into();
        digest
    });
    ProverMeta {
        backend,
        witness_bytes: result.witness_bytes(),
        proof_bytes,
        proof_hash,
        duration_ms: result.duration().as_millis() as u64,
    }
}

fn record_prepare_success(backend: &'static str, witness_bytes: usize) {
    counter!(
        "wallet.prover.jobs",
        "backend" => backend,
        "stage" => "prepare",
        "result" => "ok"
    )
    .increment(1);
    histogram!("wallet.prover.witness_bytes", "backend" => backend).record(witness_bytes as f64);
}

fn record_prepare_error(backend: &'static str, error: &ProverError) {
    counter!(
        "wallet.prover.jobs",
        "backend" => backend,
        "stage" => "prepare",
        "result" => "err",
        "error" => error_label(error)
    )
    .increment(1);
}

fn record_prove_success(backend: &'static str, result: &ProveResult) {
    counter!(
        "wallet.prover.jobs",
        "backend" => backend,
        "stage" => "prove",
        "result" => "ok"
    )
    .increment(1);
    histogram!("wallet.prover.duration_ms", "backend" => backend)
        .record(result.duration().as_millis() as f64);
    if let Some(bytes) = result.proof().map(|proof| proof.as_ref().len()) {
        histogram!("wallet.prover.proof_bytes", "backend" => backend).record(bytes as f64);
    }
}

fn record_prove_error(backend: &'static str, error: &ProverError) {
    counter!(
        "wallet.prover.jobs",
        "backend" => backend,
        "stage" => "prove",
        "result" => "err",
        "error" => error_label(error)
    )
    .increment(1);
}

fn error_label(error: &ProverError) -> &'static str {
    match error {
        ProverError::Backend(_) => "backend",
        ProverError::Serialization(_) => "serialization",
        ProverError::Unsupported(_) => "unsupported",
        ProverError::Runtime(_) => "runtime",
        ProverError::Timeout(_) => "timeout",
        ProverError::Cancelled => "cancelled",
        ProverError::Busy => "busy",
        ProverError::WitnessTooLarge { .. } => "witness_too_large",
    }
}

fn map_blocking_error(err: task::JoinError) -> ProverError {
    if err.is_cancelled() {
        ProverError::Cancelled
    } else if err.is_panic() {
        warn!("wallet prover job panicked");
        ProverError::Runtime("prover task panicked".into())
    } else {
        ProverError::Runtime(format!("prover task failed: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::wallet::WalletProverConfig;
    use crate::db::UtxoOutpoint;
    use crate::engine::{DraftInput, DraftOutput, DraftTransaction, SpendModel};

    fn sample_draft() -> DraftTransaction {
        DraftTransaction {
            inputs: vec![DraftInput {
                outpoint: UtxoOutpoint::new([1u8; 32], 0),
                value: 50_000,
                confirmations: 1,
            }],
            outputs: vec![DraftOutput::new("receiver", 10_000, false)],
            fee_rate: 1,
            fee: 1_000,
            spend_model: SpendModel::Exact { amount: 10_000 },
        }
    }

    #[test]
    fn job_permit_aborts_when_timeout_is_exceeded() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let _guard = runtime.enter();

        let mut config = WalletProverConfig::default();
        config.timeout_secs = 1;
        config.max_concurrency = 1;
        let manager = ProverJobManager::new(&config);
        let permit = manager.acquire().expect("permit");

        let result = runtime.block_on(async move {
            permit
                .wait(async {
                    task::spawn_blocking(|| {
                        std::thread::sleep(Duration::from_millis(1_500));
                        Ok::<(), ProverError>(())
                    })
                    .await
                    .map_err(map_blocking_error)
                })
                .await
        });

        assert!(matches!(result, Err(ProverError::Timeout(1))));
    }

    #[cfg(feature = "prover-mock")]
    #[test]
    fn mock_prover_rejects_witnesses_over_configured_cap() {
        let mut config = WalletProverConfig::default();
        config.max_witness_bytes = 1;
        let prover = MockWalletProver::new(&config);
        let draft = sample_draft();

        let ctx = DraftProverContext::new(&draft);
        let err = prover.prepare_witness(&ctx).expect_err("witness too large");
        assert!(matches!(
            err,
            ProverError::WitnessTooLarge {
                size: _,
                limit
            } if limit == 1
        ));
    }

    #[cfg(feature = "prover-stwo")]
    #[test]
    fn stwo_prover_rejects_witnesses_over_configured_cap() {
        let mut config = WalletProverConfig::default();
        config.max_witness_bytes = 1;
        config.backend = WalletProverBackend::Stwo;
        config.require_proof = true;
        let prover = StwoWalletProver::new(&config).expect("stwo prover");
        let draft = sample_draft();

        let ctx = DraftProverContext::new(&draft);
        let err = prover.prepare_witness(&ctx).expect_err("witness too large");
        assert!(matches!(
            err,
            ProverError::WitnessTooLarge {
                size: _,
                limit
            } if limit == 1
        ));
    }
}
