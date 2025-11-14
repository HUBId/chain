use std::convert::TryFrom;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::wallet::WalletProverConfig;

use super::{ProverError, ProverOutput, WalletProver};
use crate::engine::DraftTransaction;
use prover_backend_interface::{
    ProofBytes, ProofHeader, ProofSystemKind, WitnessBytes, WitnessHeader,
};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task;
use tracing::{info, warn};

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
    if config.enabled {
        #[cfg(feature = "prover-stwo")]
        {
            return Ok(Arc::new(StwoWalletProver::new(config)?));
        }
        #[cfg(not(feature = "prover-stwo"))]
        {
            if !config.mock_fallback {
                return Ok(Arc::new(DisabledWalletProver::new(
                    "STWO prover requested but feature disabled",
                )));
            }
        }
    }
    #[cfg(feature = "prover-mock")]
    {
        return Ok(Arc::new(MockWalletProver::new(config)));
    }
    Ok(Arc::new(DisabledWalletProver::new(
        "wallet prover backend disabled",
    )))
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
    fn backend(&self) -> &'static str {
        "mock"
    }

    fn prove(&self, draft: &DraftTransaction) -> Result<ProverOutput, ProverError> {
        let draft = draft.clone();
        let limit = self.jobs.witness_limit();
        self.jobs.run_job(move || {
            let start = Instant::now();
            let witness_header = WitnessHeader::new(ProofSystemKind::Mock, MOCK_CIRCUIT_ID);
            let payload = bincode::serialize(&draft)
                .map_err(|err| ProverError::Serialization(err.to_string()))?;
            let witness = WitnessBytes::encode(&witness_header, &payload)?;
            let witness_bytes = witness.as_slice().len();
            if limit > 0 && (witness_bytes as u64) > limit {
                warn!(
                    backend = "mock",
                    witness_bytes, limit, "wallet prover witness exceeds configured limit"
                );
                return Err(ProverError::WitnessTooLarge {
                    size: witness_bytes,
                    limit,
                });
            }
            let proof_header = ProofHeader::new(ProofSystemKind::Mock, MOCK_CIRCUIT_ID);
            let proof = ProofBytes::encode(&proof_header, witness.as_slice())?;
            let proof_len = proof.as_ref().len();
            let duration_ms = start.elapsed().as_millis() as u64;
            info!(
                backend = "mock",
                witness_bytes,
                proof_bytes = proof_len,
                duration_ms,
                "wallet prover job completed"
            );
            Ok(ProverOutput {
                backend: "mock".to_string(),
                proof: Some(proof),
                witness_bytes,
                duration_ms,
            })
        })
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
    fn backend(&self) -> &'static str {
        "stwo"
    }

    fn prove(&self, draft: &DraftTransaction) -> Result<ProverOutput, ProverError> {
        let draft = draft.clone();
        let backend = Arc::clone(&self.backend);
        let proving_key = Arc::clone(&self.proving_key);
        let limit = self.jobs.witness_limit();
        self.jobs.run_job(move || {
            let start = Instant::now();
            let (witness, witness_bytes) = build_stwo_witness(&draft)?;
            if limit > 0 && (witness_bytes as u64) > limit {
                warn!(
                    backend = "stwo",
                    witness_bytes, limit, "wallet prover witness exceeds configured limit"
                );
                return Err(ProverError::WitnessTooLarge {
                    size: witness_bytes,
                    limit,
                });
            }
            let proof = backend.prove_tx(&proving_key, &witness)?;
            let proof_len = proof.as_ref().len();
            let duration_ms = start.elapsed().as_millis() as u64;
            info!(
                backend = "stwo",
                witness_bytes,
                proof_bytes = proof_len,
                duration_ms,
                "wallet prover job completed"
            );
            Ok(ProverOutput {
                backend: "stwo".to_string(),
                proof: Some(proof),
                witness_bytes,
                duration_ms,
            })
        })
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
    fn backend(&self) -> &'static str {
        "disabled"
    }

    fn prove(&self, _draft: &DraftTransaction) -> Result<ProverOutput, ProverError> {
        Err(ProverError::Unsupported(self.reason))
    }
}

struct ProverJobManager {
    semaphore: Option<Arc<Semaphore>>,
    timeout: Option<Duration>,
    witness_limit: u64,
}

impl ProverJobManager {
    fn new(config: &WalletProverConfig) -> Self {
        let semaphore = if config.max_concurrency == 0 {
            None
        } else {
            let permits = usize::try_from(config.max_concurrency).unwrap_or(usize::MAX);
            Some(Arc::new(Semaphore::new(permits)))
        };
        let timeout = if config.job_timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(config.job_timeout_secs))
        };
        Self {
            semaphore,
            timeout,
            witness_limit: config.max_witness_bytes,
        }
    }

    fn witness_limit(&self) -> u64 {
        self.witness_limit
    }

    fn run_job<F>(&self, job: F) -> Result<ProverOutput, ProverError>
    where
        F: FnOnce() -> Result<ProverOutput, ProverError> + Send + 'static,
    {
        let handle = Handle::try_current().map_err(|err| {
            ProverError::Runtime(format!("tokio runtime handle not available: {err}"))
        })?;
        let semaphore = self.semaphore.clone();
        let timeout = self.timeout;
        handle.block_on(async move {
            let _permit = if let Some(semaphore) = semaphore {
                Some(
                    semaphore
                        .acquire_owned()
                        .await
                        .map_err(|_| ProverError::Cancelled)?,
                )
            } else {
                None
            };

            let job_future = async {
                task::spawn_blocking(job).await.map_err(|err| {
                    if err.is_cancelled() {
                        ProverError::Cancelled
                    } else if err.is_panic() {
                        warn!("wallet prover job panicked");
                        ProverError::Runtime("prover task panicked".into())
                    } else {
                        ProverError::Runtime(format!("prover task failed: {err}"))
                    }
                })?
            };

            if let Some(timeout) = timeout {
                match tokio::time::timeout(timeout, job_future).await {
                    Ok(result) => result,
                    Err(_) => {
                        warn!(
                            timeout_secs = timeout.as_secs(),
                            "wallet prover job exceeded timeout"
                        );
                        Err(ProverError::Timeout(timeout.as_secs()))
                    }
                }
            } else {
                job_future.await
            }
        })
    }
}

#[cfg(feature = "prover-stwo")]
fn build_stwo_witness(draft: &DraftTransaction) -> Result<(WitnessBytes, usize), ProverError> {
    use std::convert::TryInto;
    use std::time::{SystemTime, UNIX_EPOCH};

    let encoded =
        bincode::serialize(draft).map_err(|err| ProverError::Serialization(err.to_string()))?;
    let entropy: [u8; 32] = Blake2sHasher::hash(&encoded).into();
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
