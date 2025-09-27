use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::errors::{ChainError, ChainResult};
use crate::reputation::Tier;
use crate::rpp::{AssetType, UtxoOutpoint, UtxoRecord};
use crate::types::{Account, Address, IdentityDeclaration, TransactionProofBundle, UptimeProof};

use super::tabs::SendPreview;
use super::wallet::Wallet;

#[derive(Clone, Debug, Serialize)]
pub struct ReputationStatus {
    pub tier: Tier,
    pub score: f64,
    pub timetoke_hours: u64,
    pub zsi_validated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransactionPolicy {
    pub required_tier: Tier,
    pub status: ReputationStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityGenesisPhase {
    pub request_id: String,
    pub attestation_digest: String,
    pub public_key_commitment: String,
    pub declaration: IdentityDeclaration,
    pub submitted_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityQuorumPhase {
    pub request_id: String,
    pub attestation_digest: String,
    pub quorum_met: bool,
    pub quorum_votes: usize,
    pub observers: Vec<Address>,
    pub last_vote_height: Option<u64>,
    pub last_vote_round: Option<u64>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityFinalizationPhase {
    pub request_id: String,
    pub finalised: bool,
    pub height: Option<u64>,
    pub block_hash: Option<String>,
    pub error: Option<String>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityWorkflowState {
    pub request_id: String,
    pub genesis: IdentityGenesisPhase,
    pub quorum: IdentityQuorumPhase,
    pub finalization: IdentityFinalizationPhase,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityWorkflow {
    pub declaration: IdentityDeclaration,
    pub attestation_digest: String,
    pub public_key_commitment: String,
    pub vrf_tag: String,
    pub epoch_nonce: String,
    pub state_root: String,
    pub identity_root: String,
    pub state: IdentityWorkflowState,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransactionWorkflow {
    pub preview: SendPreview,
    pub bundle: TransactionProofBundle,
    pub utxo_inputs: Vec<UtxoRecord>,
    pub planned_outputs: Vec<UtxoRecord>,
    pub sender_post_utxo: UtxoRecord,
    pub recipient_pre_utxo: Option<UtxoRecord>,
    pub recipient_post_utxo: UtxoRecord,
    pub total_input_value: u128,
    pub total_output_value: u128,
    pub fee: u64,
    pub policy: TransactionPolicy,
    pub state_root: String,
    pub tx_hash: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct UptimeWorkflow {
    pub proof: UptimeProof,
    pub credited_hours: u64,
    pub status: ReputationStatus,
}

pub struct WalletWorkflows<'a> {
    wallet: &'a Wallet,
}

impl<'a> WalletWorkflows<'a> {
    pub fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    pub fn identity_attestation(&self) -> ChainResult<IdentityWorkflow> {
        let declaration = self.wallet.build_identity_declaration()?;
        let attestation_digest = hex::encode(declaration.hash()?);
        let request_id = attestation_digest.clone();
        let public_key_commitment = declaration.genesis.public_key_commitment()?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut state = IdentityWorkflowState {
            request_id: request_id.clone(),
            genesis: IdentityGenesisPhase {
                request_id: request_id.clone(),
                attestation_digest: attestation_digest.clone(),
                public_key_commitment: public_key_commitment.clone(),
                declaration: declaration.clone(),
                submitted_at: timestamp,
            },
            quorum: IdentityQuorumPhase {
                request_id: request_id.clone(),
                attestation_digest: attestation_digest.clone(),
                quorum_met: false,
                quorum_votes: 0,
                observers: Vec::new(),
                last_vote_height: None,
                last_vote_round: None,
                updated_at: timestamp,
            },
            finalization: IdentityFinalizationPhase {
                request_id: request_id.clone(),
                finalised: false,
                height: None,
                block_hash: None,
                error: None,
                updated_at: timestamp,
            },
        };
        if let Some(mut persisted) = self
            .wallet
            .load_identity_workflow_state::<IdentityWorkflowState>()?
        {
            if persisted.request_id == request_id {
                persisted.genesis.declaration = declaration.clone();
                persisted.genesis.attestation_digest = attestation_digest.clone();
                persisted.genesis.public_key_commitment = public_key_commitment.clone();
                state = persisted;
            }
        }
        self.wallet
            .persist_identity_workflow_state(&state)
            .map_err(|err| {
                ChainError::Config(format!("unable to persist identity workflow state: {err}"))
            })?;
        Ok(IdentityWorkflow {
            vrf_tag: declaration.genesis.vrf_tag().to_string(),
            epoch_nonce: declaration.genesis.epoch_nonce.clone(),
            state_root: declaration.genesis.state_root.clone(),
            identity_root: declaration.genesis.identity_root.clone(),
            attestation_digest,
            public_key_commitment,
            state,
            declaration,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transaction_bundle(
        &self,
        to: Address,
        amount: u128,
        fee: u64,
        memo: Option<String>,
    ) -> ChainResult<TransactionWorkflow> {
        let preview = self
            .wallet
            .preview_send(to.clone(), amount, fee, memo.clone())?;
        let sender_account = self
            .wallet
            .account_by_address(self.wallet.address())?
            .ok_or_else(|| ChainError::Config("wallet account not found".into()))?;
        if !sender_account.reputation.zsi.validated {
            return Err(ChainError::Transaction(
                "wallet identity must be ZSI-validated".into(),
            ));
        }
        let status = status_from_account(&sender_account);
        let transaction = self
            .wallet
            .build_transaction(to.clone(), amount, fee, memo)?;
        let signed = self.wallet.sign_transaction(transaction.clone());
        let bundle = self.wallet.prove_transaction(&signed)?;
        let tx_hash_bytes = bundle.transaction.hash();
        let tx_hash = hex::encode(tx_hash_bytes);
        let fee_u128 = u128::from(fee);
        let total_debit = amount
            .checked_add(fee_u128)
            .ok_or_else(|| ChainError::Transaction("transaction amount overflow".into()))?;
        if sender_account.balance < total_debit {
            return Err(ChainError::Transaction(
                "insufficient balance for requested transfer".into(),
            ));
        }
        let utxo_inputs = select_inputs_from_available(
            self.wallet.unspent_utxos(self.wallet.address())?,
            total_debit,
        )?;
        let total_input_value = sum_values(&utxo_inputs)?;
        let remaining = total_input_value
            .checked_sub(total_debit)
            .ok_or_else(|| ChainError::Transaction("selected inputs insufficient".into()))?;
        let mut planned_outputs = Vec::new();
        planned_outputs.push(planned_utxo(&tx_hash_bytes, 0, &to, amount));
        if remaining > 0 {
            planned_outputs.push(planned_utxo(
                &tx_hash_bytes,
                1,
                self.wallet.address(),
                remaining,
            ));
        }
        let total_output_value = sum_values(&planned_outputs)?;
        if total_input_value < total_output_value + fee_u128 {
            return Err(ChainError::Transaction(
                "UTXO selection underfunded requested outputs".into(),
            ));
        }
        let recipient_account = self.wallet.account_by_address(&to)?;
        let (recipient_pre_utxo, recipient_balance_before) = match recipient_account {
            Some(ref account) => (
                Some(ledger_snapshot_utxo(
                    &account.address,
                    account.balance,
                    None,
                )),
                account.balance,
            ),
            None => (None, 0u128),
        };
        let recipient_balance_after = recipient_balance_before
            .checked_add(amount)
            .ok_or_else(|| ChainError::Transaction("recipient balance overflow".into()))?;
        let recipient_post_utxo =
            ledger_snapshot_utxo(&to, recipient_balance_after, Some(tx_hash_bytes));
        let sender_post_utxo = ledger_snapshot_utxo(
            self.wallet.address(),
            sender_account.balance - total_debit,
            Some(tx_hash_bytes),
        );
        let policy = TransactionPolicy {
            required_tier: Tier::Tl0,
            status,
        };
        let state_root = self.wallet.firewood_state_root()?;
        Ok(TransactionWorkflow {
            preview,
            bundle,
            utxo_inputs,
            planned_outputs,
            sender_post_utxo,
            recipient_pre_utxo,
            recipient_post_utxo,
            total_input_value,
            total_output_value,
            fee,
            policy,
            state_root,
            tx_hash,
            nonce: transaction.nonce,
        })
    }

    pub fn uptime_proof(&self) -> ChainResult<UptimeWorkflow> {
        let proof = self.wallet.generate_uptime_proof()?;
        let sender_account = self
            .wallet
            .account_by_address(self.wallet.address())?
            .ok_or_else(|| ChainError::Config("wallet account not found".into()))?;
        let status = status_from_account(&sender_account);
        let credited_hours = credited_hours(&proof);
        Ok(UptimeWorkflow {
            proof,
            credited_hours,
            status,
        })
    }
}

impl Wallet {
    pub fn workflows(&self) -> WalletWorkflows<'_> {
        WalletWorkflows::new(self)
    }
}

fn status_from_account(account: &Account) -> ReputationStatus {
    ReputationStatus {
        tier: account.reputation.tier.clone(),
        score: account.reputation.score,
        timetoke_hours: account.reputation.timetokes.hours_online,
        zsi_validated: account.reputation.zsi.validated,
    }
}

fn ledger_snapshot_utxo(
    address: &Address,
    value: u128,
    tx_id_override: Option<[u8; 32]>,
) -> UtxoRecord {
    let mut script_seed = address.as_bytes().to_vec();
    script_seed.extend_from_slice(&0u32.to_be_bytes());
    let script_hash: [u8; 32] = Blake2sHasher::hash(&script_seed).into();
    let mut record = UtxoRecord {
        outpoint: UtxoOutpoint {
            tx_id: tx_id_override.unwrap_or([0u8; 32]),
            index: 0,
        },
        owner: address.clone(),
        value,
        asset_type: AssetType::Native,
        script_hash,
        timelock: None,
    };
    if let Some(tx_id) = tx_id_override {
        record.outpoint.tx_id = tx_id;
    }
    record.value = value;
    record
}

fn planned_utxo(tx_hash: &[u8; 32], index: u32, owner: &Address, value: u128) -> UtxoRecord {
    let mut script_seed = owner.as_bytes().to_vec();
    script_seed.extend_from_slice(&index.to_be_bytes());
    let script_hash: [u8; 32] = Blake2sHasher::hash(&script_seed).into();
    UtxoRecord {
        outpoint: UtxoOutpoint {
            tx_id: *tx_hash,
            index,
        },
        owner: owner.clone(),
        value,
        asset_type: AssetType::Native,
        script_hash,
        timelock: None,
    }
}

fn select_inputs_from_available(
    mut available: Vec<UtxoRecord>,
    target: u128,
) -> ChainResult<Vec<UtxoRecord>> {
    if available.is_empty() {
        return Err(ChainError::Transaction(
            "wallet inputs unavailable for requested owner".into(),
        ));
    }
    available.sort_by(|a, b| match b.value.cmp(&a.value) {
        Ordering::Equal => a.outpoint.cmp(&b.outpoint),
        other => other,
    });
    let mut selected = Vec::new();
    let mut total = 0u128;
    for record in available {
        if total >= target {
            break;
        }
        total = total
            .checked_add(record.value)
            .ok_or_else(|| ChainError::Transaction("input value overflow".into()))?;
        selected.push(record);
    }
    if total < target {
        return Err(ChainError::Transaction(
            "insufficient input liquidity for requested amount".into(),
        ));
    }
    selected.sort_by(|a, b| a.outpoint.cmp(&b.outpoint));
    Ok(selected)
}

fn sum_values(records: &[UtxoRecord]) -> ChainResult<u128> {
    let mut total = 0u128;
    for record in records {
        total = total
            .checked_add(record.value)
            .ok_or_else(|| ChainError::Transaction("utxo value overflow".into()))?;
    }
    Ok(total)
}

fn credited_hours(proof: &UptimeProof) -> u64 {
    if proof.window_end <= proof.window_start {
        return 0;
    }
    proof.window_end.saturating_sub(proof.window_start) / 3600
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::address_from_public_key;
    use crate::errors::ChainError;
    use crate::ledger::{DEFAULT_EPOCH_LENGTH, Ledger};
    use crate::reputation::{Tier, TimetokeBalance};
    use crate::storage::Storage;
    use crate::types::Stake;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn wallet_fixture(balance: u128) -> (Wallet, Address, Storage, tempfile::TempDir) {
        let tempdir = tempdir().expect("temp dir");
        let storage = Storage::open(tempdir.path()).expect("open storage");
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let address = address_from_public_key(&keypair.public);
        let mut account = Account::new(address.clone(), balance, Stake::default());
        account.reputation.tier = Tier::Tl5;
        account.reputation.score = 10.0;
        account.reputation.timetokes = TimetokeBalance {
            hours_online: 10_000,
            ..TimetokeBalance::default()
        };
        account.reputation.zsi.validate("proof");
        storage.persist_account(&account).expect("persist account");
        let wallet = Wallet::new(storage.clone(), keypair);
        (wallet, address, storage, tempdir)
    }

    #[test]
    fn wallet_utxo_view_matches_ledger() {
        let (wallet, address, storage, _tempdir) = wallet_fixture(75_000);
        let wallet_utxos = wallet.unspent_utxos(&address).expect("wallet utxo query");
        let accounts = storage.load_accounts().expect("load accounts");
        let ledger = Ledger::load(accounts, DEFAULT_EPOCH_LENGTH);
        let ledger_utxos = ledger.utxos_for_owner(&address);
        assert_eq!(wallet_utxos.len(), ledger_utxos.len());
        for (wallet_record, ledger_record) in wallet_utxos.iter().zip(ledger_utxos.iter()) {
            assert_eq!(wallet_record.outpoint, ledger_record.outpoint);
            assert_eq!(wallet_record.owner, ledger_record.owner);
            assert_eq!(wallet_record.value, ledger_record.value);
        }
    }

    #[test]
    fn wallet_rejects_conflicting_transaction_bundle() {
        let (wallet, address, storage, _tempdir) = wallet_fixture(80_000);
        let recipient = "recipient-address".to_string();
        let first_amount = 30_000u128;
        let fee = 100u64;

        let workflow = wallet
            .workflows()
            .transaction_bundle(recipient.clone(), first_amount, fee, None)
            .expect("initial bundle");
        assert!(!workflow.utxo_inputs.is_empty());

        let mut account = storage
            .read_account(&address)
            .expect("read account")
            .expect("account exists");
        let debit = first_amount + u128::from(fee);
        account.balance = account.balance.saturating_sub(debit);
        account.nonce += 1;
        storage.persist_account(&account).expect("persist updated");

        let conflict_amount = 80_000u128;
        let result = wallet
            .workflows()
            .transaction_bundle(recipient, conflict_amount, fee, None);
        assert!(matches!(
            result,
            Err(ChainError::Transaction(message)) if message.contains("insufficient")
        ));
    }
}
