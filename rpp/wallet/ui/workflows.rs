use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::{ChainError, ChainResult};
use crate::ledger::Ledger;
use crate::reputation::{
    minimum_transaction_tier, transaction_tier_requirement, Tier, TierRequirementError,
};
use crate::rpp::{AssetType, UtxoOutpoint, UtxoRecord};
use crate::state::utxo::{locking_script_hash, StoredUtxo, UtxoState};
use crate::types::{Account, Address, IdentityDeclaration, TransactionProofBundle, UptimeProof};
use serde::{Deserialize, Serialize};

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
    pub sender_post_utxos: Vec<UtxoRecord>,
    pub recipient_pre_utxos: Vec<UtxoRecord>,
    pub recipient_post_utxos: Vec<UtxoRecord>,
    pub total_input_value: u128,
    pub total_output_value: u128,
    pub fee: u64,
    pub policy: TransactionPolicy,
    pub state_root: String,
    pub utxo_commitment: String,
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
        let accounts = self.wallet.accounts_snapshot()?;
        let (ledger, has_snapshot) = self.wallet.load_ledger_from_accounts(accounts)?;
        if !has_snapshot {
            return Err(ChainError::Config(
                "wallet utxo snapshot not available".into(),
            ));
        }
        let thresholds = ledger.reputation_params().tier_thresholds;
        let minimum_tier = minimum_transaction_tier(&thresholds);
        let derived_tier = transaction_tier_requirement(&sender_account.reputation, &thresholds)
            .map_err(map_tier_requirement_error)?;
        if sender_account.reputation.tier < minimum_tier {
            return Err(ChainError::Transaction(format!(
                "wallet reputation tier {:?} below governance minimum {:?}",
                sender_account.reputation.tier, minimum_tier
            )));
        }
        let required_tier = derived_tier.max(minimum_tier);
        if sender_account.reputation.tier < required_tier {
            return Err(ChainError::Transaction(format!(
                "wallet reputation tier {:?} below required {:?}",
                sender_account.reputation.tier, required_tier
            )));
        }
        let mut sender_pre_utxos = ledger.utxos_for_owner(self.wallet.address());
        if sender_pre_utxos.is_empty() {
            return Err(ChainError::Transaction(
                "wallet inputs unavailable for requested owner".into(),
            ));
        }
        sender_pre_utxos.sort_by(|a, b| {
            a.outpoint
                .index
                .cmp(&b.outpoint.index)
                .then_with(|| a.outpoint.tx_id.cmp(&b.outpoint.tx_id))
        });
        let ledger_inputs = select_input_outpoints(&sender_pre_utxos, total_debit)?;
        let sender_pre_map: BTreeMap<_, _> = sender_pre_utxos
            .iter()
            .cloned()
            .map(|record| (record.outpoint.clone(), record))
            .collect();
        let mut utxo_inputs = Vec::new();
        for outpoint in &ledger_inputs {
            let record = sender_pre_map.get(outpoint).ok_or_else(|| {
                ChainError::Transaction("ledger selected input not present in snapshot".into())
            })?;
            utxo_inputs.push(record.clone());
        }
        let total_input_value = sum_values(&utxo_inputs)?;
        let remaining = total_input_value
            .checked_sub(total_debit)
            .ok_or_else(|| ChainError::Transaction("selected inputs insufficient".into()))?;
        let mut planned_outputs = Vec::new();
        if amount > 0 {
            planned_outputs.push(planned_utxo(
                &tx_hash_bytes,
                planned_outputs.len() as u32,
                &to,
                amount,
            ));
        }
        if remaining > 0 {
            planned_outputs.push(planned_utxo(
                &tx_hash_bytes,
                planned_outputs.len() as u32,
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
        if let Some(ref account) = recipient_account {
            account
                .balance
                .checked_add(amount)
                .ok_or_else(|| ChainError::Transaction("recipient balance overflow".into()))?;
        }
        let mut recipient_pre_utxos = ledger.utxos_for_owner(&to);
        let is_self_transfer = self.wallet.address() == &to;
        if recipient_account.is_none() {
            recipient_pre_utxos.clear();
        }
        let spent_outpoints: BTreeSet<_> = ledger_inputs.into_iter().collect();
        let sender_post_utxos = project_post_utxos(
            &sender_pre_utxos,
            &spent_outpoints,
            &planned_outputs,
            self.wallet.address(),
        );
        let recipient_post_utxos = if is_self_transfer {
            recipient_pre_utxos = sender_pre_utxos.clone();
            sender_post_utxos.clone()
        } else {
            project_post_utxos(
                &recipient_pre_utxos,
                &spent_outpoints,
                &planned_outputs,
                &to,
            )
        };
        let policy = TransactionPolicy {
            required_tier,
            status,
        };
        let state_root = self.wallet.firewood_state_root()?;
        let ledger_commitment = ledger.global_commitments().utxo_root;
        let reconstructed_commitment = rebuild_utxo_commitment(&ledger);
        if ledger_commitment != reconstructed_commitment {
            return Err(ChainError::Config(
                "wallet utxo snapshot mismatches ledger commitment".into(),
            ));
        }
        let utxo_commitment = hex::encode(reconstructed_commitment);
        Ok(TransactionWorkflow {
            preview,
            bundle,
            utxo_inputs,
            planned_outputs,
            sender_post_utxos,
            recipient_pre_utxos,
            recipient_post_utxos,
            total_input_value,
            total_output_value,
            fee,
            policy,
            state_root,
            utxo_commitment,
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

fn select_input_outpoints(records: &[UtxoRecord], target: u128) -> ChainResult<Vec<UtxoOutpoint>> {
    let mut total = 0u128;
    let mut selected = Vec::new();
    for record in records {
        total = total
            .checked_add(record.value)
            .ok_or_else(|| ChainError::Transaction("input value overflow".into()))?;
        selected.push(record.outpoint.clone());
        if total >= target {
            break;
        }
    }
    if total < target {
        return Err(ChainError::Transaction(
            "insufficient input liquidity for requested amount".into(),
        ));
    }
    Ok(selected)
}

fn planned_utxo(tx_hash: &[u8; 32], index: u32, owner: &Address, value: u128) -> UtxoRecord {
    let script_hash = locking_script_hash(owner, value);
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

fn map_tier_requirement_error(err: TierRequirementError) -> ChainError {
    match err {
        TierRequirementError::MissingZsiValidation => {
            ChainError::Transaction("wallet identity must be ZSI-validated".into())
        }
        TierRequirementError::InsufficientTimetoke {
            required,
            available,
        } => ChainError::Transaction(format!(
            "wallet timetoke balance {available}h below required {required}h"
        )),
    }
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

fn project_post_utxos(
    pre: &[UtxoRecord],
    spent: &BTreeSet<UtxoOutpoint>,
    planned: &[UtxoRecord],
    owner: &Address,
) -> Vec<UtxoRecord> {
    let mut remaining: Vec<UtxoRecord> = pre
        .iter()
        .filter(|record| !spent.contains(&record.outpoint))
        .cloned()
        .collect();
    remaining.extend(
        planned
            .iter()
            .filter(|record| record.owner == *owner)
            .cloned(),
    );
    remaining.sort_by(|a, b| a.outpoint.cmp(&b.outpoint));
    remaining
}

fn rebuild_utxo_commitment(ledger: &Ledger) -> [u8; 32] {
    let mirror = UtxoState::new();
    for account in ledger.accounts_snapshot() {
        for record in ledger.utxos_for_owner(&account.address) {
            mirror.insert(
                record.outpoint.clone(),
                StoredUtxo::new(record.owner.clone(), record.value),
            );
        }
    }
    mirror.commitment()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::address_from_public_key;
    use crate::errors::ChainError;
    use crate::ledger::{Ledger, DEFAULT_EPOCH_LENGTH};
    use crate::reputation::{Tier, TimetokeBalance};
    use crate::storage::Storage;
    use crate::types::Stake;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn wallet_fixture_with_utxos(
        balance: u128,
        utxo_values: &[u128],
    ) -> (
        Wallet,
        Address,
        Storage,
        tempfile::TempDir,
        Vec<(UtxoOutpoint, StoredUtxo)>,
    ) {
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
        let snapshot: Vec<_> = utxo_values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let mut tx_id = [0u8; 32];
                tx_id[0] = (index as u8).wrapping_add(1);
                (
                    UtxoOutpoint {
                        tx_id,
                        index: index as u32,
                    },
                    StoredUtxo::new(address.clone(), *value),
                )
            })
            .collect();
        storage
            .persist_utxo_snapshot(&snapshot)
            .expect("persist utxo snapshot");
        let wallet = Wallet::new(storage.clone(), keypair);
        (wallet, address, storage, tempdir, snapshot)
    }

    fn wallet_fixture_legacy(balance: u128) -> (Wallet, Address, Storage, tempfile::TempDir) {
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

    fn snapshot_records(snapshot: &[(UtxoOutpoint, StoredUtxo)]) -> Vec<UtxoRecord> {
        snapshot
            .iter()
            .map(|(outpoint, stored)| stored.to_record(outpoint))
            .collect()
    }

    #[test]
    fn transaction_bundle_rejects_when_tier_below_minimum() {
        let (wallet, address, storage, _tempdir, _snapshot) =
            wallet_fixture_with_utxos(100_000, &[60_000]);
        let mut account = storage
            .read_account(&address)
            .expect("read account")
            .expect("account present");
        account.reputation.tier = Tier::Tl1;
        account.reputation.timetokes.hours_online = 48;
        storage.persist_account(&account).expect("persist");

        let error = wallet
            .build_transaction(address.clone(), 10_000, 100, None)
            .expect_err("tier check should fail");
        assert!(matches!(
            error,
            ChainError::Transaction(message) if message.contains("governance minimum")
        ));

        let error = wallet
            .workflows()
            .transaction_bundle(address.clone(), 10_000, 100, None)
            .expect_err("workflow tier check should fail");
        assert!(matches!(
            error,
            ChainError::Transaction(message) if message.contains("governance minimum")
        ));
    }

    #[test]
    fn transaction_bundle_rejects_when_timetoke_below_threshold() {
        let (wallet, address, storage, _tempdir, _snapshot) =
            wallet_fixture_with_utxos(120_000, &[80_000, 40_000]);
        let mut account = storage
            .read_account(&address)
            .expect("read account")
            .expect("account present");
        account.reputation.timetokes.hours_online = 12;
        storage.persist_account(&account).expect("persist");

        let error = wallet
            .build_transaction(address.clone(), 10_000, 100, None)
            .expect_err("timetoke check should fail");
        assert!(matches!(
            error,
            ChainError::Transaction(message) if message.contains("timetoke")
        ));

        let error = wallet
            .workflows()
            .transaction_bundle(address.clone(), 10_000, 100, None)
            .expect_err("workflow timetoke check should fail");
        assert!(matches!(
            error,
            ChainError::Transaction(message) if message.contains("timetoke")
        ));
    }

    #[test]
    fn transaction_bundle_succeeds_with_high_score() {
        let (wallet, address, storage, _tempdir, _snapshot) =
            wallet_fixture_with_utxos(150_000, &[90_000, 60_000]);
        let mut account = storage
            .read_account(&address)
            .expect("read account")
            .expect("account present");
        account.reputation.timetokes.hours_online = 72;
        account.reputation.consensus_success = 200;
        account.reputation.score = 0.9;
        account.reputation.tier = Tier::Tl5;
        storage.persist_account(&account).expect("persist");

        wallet
            .build_transaction(address.clone(), 20_000, 150, None)
            .expect("transaction should build");

        let workflow = wallet
            .workflows()
            .transaction_bundle(address.clone(), 20_000, 150, None)
            .expect("workflow should succeed");
        assert!(workflow.policy.required_tier >= Tier::Tl2);
        assert_eq!(workflow.policy.status.tier, Tier::Tl5);
    }

    #[test]
    fn wallet_utxo_view_matches_ledger() {
        let utxo_values = [30_000, 25_000, 20_000];
        let (wallet, address, storage, _tempdir, snapshot) =
            wallet_fixture_with_utxos(75_000, &utxo_values);
        let expected = snapshot_records(&snapshot);
        let wallet_utxos = wallet.unspent_utxos(&address).expect("wallet utxo query");
        assert_eq!(wallet_utxos.len(), expected.len());
        for (actual, record) in wallet_utxos.iter().zip(expected.iter()) {
            assert_eq!(actual.outpoint, record.outpoint);
            assert_eq!(actual.owner, record.owner);
            assert_eq!(actual.value, record.value);
            assert_eq!(
                actual.script_hash,
                locking_script_hash(&record.owner, record.value)
            );
        }

        let accounts = storage.load_accounts().expect("load accounts");
        let utxo_snapshot = storage
            .load_utxo_snapshot()
            .expect("load utxo snapshot")
            .expect("snapshot present");
        let ledger = Ledger::load(accounts, utxo_snapshot, DEFAULT_EPOCH_LENGTH);
        let commitment = rebuild_utxo_commitment(&ledger);
        let reconstructed = hex::encode(commitment);
        let workflow = wallet
            .workflows()
            .transaction_bundle(address.clone(), 25_000, 100, None)
            .expect("self-transfer bundle");
        assert_eq!(workflow.utxo_commitment, reconstructed);
        let expected_inputs =
            select_input_outpoints(&expected, 25_000 + 100).expect("select expected inputs");
        let actual_inputs: Vec<_> = workflow
            .utxo_inputs
            .iter()
            .map(|record| record.outpoint.clone())
            .collect();
        assert_eq!(actual_inputs, expected_inputs);
    }

    #[test]
    fn wallet_rejects_conflicting_transaction_bundle() {
        let utxo_values = [20_000, 30_000, 30_000];
        let (wallet, address, storage, _tempdir, snapshot) =
            wallet_fixture_with_utxos(80_000, &utxo_values);
        let expected_records = snapshot_records(&snapshot);
        let recipient = "recipient-address".to_string();
        let first_amount = 30_000u128;
        let fee = 100u64;

        let workflow = wallet
            .workflows()
            .transaction_bundle(recipient.clone(), first_amount, fee, None)
            .expect("initial bundle");
        assert_eq!(workflow.utxo_inputs.len(), 2);
        let expected_inputs =
            select_input_outpoints(&expected_records, first_amount + u128::from(fee))
                .expect("select inputs");
        let actual_inputs: Vec<_> = workflow
            .utxo_inputs
            .iter()
            .map(|record| record.outpoint.clone())
            .collect();
        assert_eq!(actual_inputs, expected_inputs);
        assert!(workflow
            .planned_outputs
            .iter()
            .enumerate()
            .all(|(index, record)| record.outpoint.index == index as u32));

        let accounts = storage.load_accounts().expect("load accounts");
        let utxo_snapshot = storage
            .load_utxo_snapshot()
            .expect("load utxo snapshot")
            .expect("snapshot present");
        let ledger = Ledger::load(accounts, utxo_snapshot, DEFAULT_EPOCH_LENGTH);
        let expected_commitment = rebuild_utxo_commitment(&ledger);
        assert_eq!(workflow.utxo_commitment, hex::encode(expected_commitment));

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

    #[test]
    fn wallet_errors_without_utxo_snapshot() {
        let (wallet, address, storage, _tempdir) = wallet_fixture_legacy(60_000);
        assert!(storage
            .load_utxo_snapshot()
            .expect("load snapshot")
            .is_none());
        let error = wallet
            .unspent_utxos(&address)
            .expect_err("missing snapshot should error");
        if let ChainError::Config(message) = error {
            assert!(message.contains("snapshot"));
        } else {
            panic!("unexpected error: {error:?}");
        }
    }
}
