use std::path::Path;

use rocksdb::IteratorMode;
use serde::{Deserialize, Serialize};

use crate::consensus::{ConsensusCertificate, SignedBftVote};
use crate::errors::{ChainError, ChainResult};
use crate::rpp::{ModuleWitnessBundle, ProofArtifact};
use crate::storage::{CF_BLOCKS, CF_METADATA, SCHEMA_VERSION_KEY, STORAGE_SCHEMA_VERSION, Storage};
use crate::types::{
    Block, BlockHeader, BlockStarkProofs, IdentityDeclaration, PruningProof, RecursiveProof,
    ReputationUpdate, SignedTransaction, StoredBlock, TimetokeUpdate, UptimeProof,
};

/// Outcome of executing storage migrations.
#[derive(Clone, Debug, Default)]
pub struct MigrationReport {
    pub from_version: u32,
    pub to_version: u32,
    pub upgraded_blocks: usize,
    pub already_current_blocks: usize,
    pub dry_run: bool,
}

impl MigrationReport {
    pub fn is_noop(&self) -> bool {
        self.from_version == self.to_version && self.upgraded_blocks == 0
    }
}

/// Upgrade an existing RocksDB storage directory to the latest schema.
pub fn migrate_storage(path: &Path, dry_run: bool) -> ChainResult<MigrationReport> {
    if !path.exists() {
        return Err(ChainError::Config(format!(
            "storage path {:?} does not exist",
            path
        )));
    }

    let db = Storage::open_db(path)?;
    let current_version = Storage::read_schema_version_raw(&db)?.unwrap_or(0);
    let mut report = MigrationReport {
        from_version: current_version,
        to_version: current_version,
        dry_run,
        ..Default::default()
    };

    if current_version >= STORAGE_SCHEMA_VERSION {
        report.to_version = current_version;
        return Ok(report);
    }

    let (converted, already_current) = migrate_block_records(&db, dry_run)?;
    report.upgraded_blocks += converted;
    report.already_current_blocks += already_current;

    if !dry_run {
        Storage::write_schema_version_raw(&db, STORAGE_SCHEMA_VERSION)?;
    }
    report.to_version = STORAGE_SCHEMA_VERSION;

    Ok(report)
}

fn migrate_block_records(
    db: &rocksdb::DBWithThreadMode<rocksdb::MultiThreaded>,
    dry_run: bool,
) -> ChainResult<(usize, usize)> {
    let blocks_cf = db
        .cf_handle(CF_BLOCKS)
        .ok_or_else(|| ChainError::Config("missing blocks column family".into()))?;
    let mut iterator = db.iterator_cf(&blocks_cf, IteratorMode::Start);
    let mut converted = 0usize;
    let mut already_current = 0usize;

    while let Some(entry) = iterator.next() {
        let (key, value) = entry?;

        if bincode::deserialize::<StoredBlock>(&value).is_ok() {
            already_current += 1;
            continue;
        }

        if let Ok(block) = bincode::deserialize::<Block>(&value) {
            if !dry_run {
                let stored = StoredBlock::from_block(&block);
                let bytes = bincode::serialize(&stored)?;
                db.put_cf(&blocks_cf, key, bytes)?;
            }
            converted += 1;
            continue;
        }

        let legacy: LegacyBlockV0 = bincode::deserialize(&value)?;
        let block = legacy.into_block();
        if !dry_run {
            let stored = StoredBlock::from_block(&block);
            let bytes = bincode::serialize(&stored)?;
            db.put_cf(&blocks_cf, key, bytes)?;
        }
        converted += 1;
    }

    Ok((converted, already_current))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LegacyBlockHeaderV0 {
    pub height: u64,
    pub previous_hash: String,
    pub tx_root: String,
    pub state_root: String,
    pub total_stake: String,
    pub randomness: String,
    pub vrf_proof: String,
    pub timestamp: u64,
    pub proposer: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LegacyBlockV0 {
    pub header: LegacyBlockHeaderV0,
    pub identities: Vec<IdentityDeclaration>,
    pub transactions: Vec<SignedTransaction>,
    #[serde(default)]
    pub uptime_proofs: Vec<UptimeProof>,
    #[serde(default)]
    pub timetoke_updates: Vec<TimetokeUpdate>,
    #[serde(default)]
    pub reputation_updates: Vec<ReputationUpdate>,
    #[serde(default)]
    pub bft_votes: Vec<SignedBftVote>,
    pub module_witnesses: ModuleWitnessBundle,
    pub proof_artifacts: Vec<ProofArtifact>,
    pub pruning_proof: PruningProof,
    pub recursive_proof: RecursiveProof,
    pub stark: BlockStarkProofs,
    pub signature: String,
    pub consensus: ConsensusCertificate,
    pub hash: String,
    #[serde(default)]
    pub pruned: bool,
}

impl LegacyBlockV0 {
    fn into_block(self) -> Block {
        let LegacyBlockV0 {
            header,
            identities,
            transactions,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            bft_votes,
            module_witnesses,
            proof_artifacts,
            pruning_proof,
            recursive_proof,
            stark,
            signature,
            consensus,
            hash,
            pruned,
        } = self;

        let header = BlockHeader {
            height: header.height,
            previous_hash: header.previous_hash,
            tx_root: header.tx_root,
            state_root: header.state_root.clone(),
            utxo_root: header.state_root.clone(),
            reputation_root: header.state_root.clone(),
            timetoke_root: header.state_root.clone(),
            zsi_root: header.state_root.clone(),
            proof_root: header.state_root,
            total_stake: header.total_stake,
            randomness: header.randomness,
            vrf_proof: header.vrf_proof,
            timestamp: header.timestamp,
            proposer: header.proposer,
        };

        Block {
            header,
            identities,
            transactions,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            bft_votes,
            module_witnesses,
            proof_artifacts,
            pruning_proof,
            recursive_proof,
            stark,
            signature,
            consensus,
            hash,
            pruned,
        }
    }
}

/// Utility exposing whether a storage directory already advertises the
/// expected schema version.
pub fn storage_is_current(path: &Path) -> ChainResult<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    let cf_descriptors = vec![rocksdb::ColumnFamilyDescriptor::new(
        CF_METADATA,
        rocksdb::Options::default(),
    )];
    let db = rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::open_cf_descriptors(
        &opts,
        path,
        cf_descriptors,
    )?;
    let version = Storage::read_schema_version_raw(&db)?.unwrap_or(0);
    Ok(version >= STORAGE_SCHEMA_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, signature_to_hex};
    use crate::reputation::{ReputationWeights, Tier};
    use crate::rpp::ProofModule;
    use crate::stwo::circuit::{
        ExecutionTrace, TraceSegment, pruning::PruningWitness, recursive::RecursiveWitness,
        state::StateWitness,
    };
    use crate::stwo::proof::{FriProof, ProofKind, ProofPayload, StarkProof};
    use ed25519_dalek::Signer;
    use tempfile::tempdir;

    fn dummy_proof(kind: ProofKind) -> StarkProof {
        let payload = match kind {
            ProofKind::State => ProofPayload::State(StateWitness {
                prev_state_root: "11".repeat(32),
                new_state_root: "22".repeat(32),
                identities: Vec::new(),
                transactions: Vec::new(),
                accounts_before: Vec::new(),
                accounts_after: Vec::new(),
                required_tier: Tier::default(),
                reputation_weights: ReputationWeights::default(),
            }),
            ProofKind::Pruning => ProofPayload::Pruning(PruningWitness {
                previous_tx_root: "00".repeat(32),
                pruned_tx_root: "33".repeat(32),
                original_transactions: vec!["44".repeat(32), "55".repeat(32)],
                removed_transactions: vec!["55".repeat(32)],
            }),
            ProofKind::Recursive => ProofPayload::Recursive(RecursiveWitness {
                previous_commitment: Some("66".repeat(32)),
                aggregated_commitment: "77".repeat(32),
                identity_commitments: vec!["88".repeat(32)],
                tx_commitments: vec!["99".repeat(32)],
                state_commitment: "aa".repeat(32),
                pruning_commitment: "bb".repeat(32),
                block_height: 1,
            }),
            _ => ProofPayload::State(StateWitness {
                prev_state_root: "11".repeat(32),
                new_state_root: "22".repeat(32),
                identities: Vec::new(),
                transactions: Vec::new(),
                accounts_before: Vec::new(),
                accounts_after: Vec::new(),
                required_tier: Tier::default(),
                reputation_weights: ReputationWeights::default(),
            }),
        };
        StarkProof {
            kind,
            commitment: "aa".repeat(32),
            public_inputs: Vec::new(),
            payload,
            trace: ExecutionTrace::single(
                TraceSegment::new("dummy", vec!["column".to_string()], Vec::new()).unwrap(),
            )
            .unwrap(),
            fri_proof: FriProof {
                commitments: Vec::new(),
                challenges: Vec::new(),
            },
        }
    }

    fn legacy_block() -> LegacyBlockV0 {
        let keypair = generate_keypair();
        let header = LegacyBlockHeaderV0 {
            height: 1,
            previous_hash: "00".repeat(32),
            tx_root: "11".repeat(32),
            state_root: "22".repeat(32),
            total_stake: "1000".to_string(),
            randomness: "33".repeat(32),
            vrf_proof: "44".repeat(32),
            timestamp: 42,
            proposer: "validator-1".into(),
        };
        let pruning = PruningProof::genesis(&header.state_root);
        let recursive = RecursiveProof::genesis(
            &BlockHeader {
                height: header.height,
                previous_hash: header.previous_hash.clone(),
                tx_root: header.tx_root.clone(),
                state_root: header.state_root.clone(),
                utxo_root: header.state_root.clone(),
                reputation_root: header.state_root.clone(),
                timetoke_root: header.state_root.clone(),
                zsi_root: header.state_root.clone(),
                proof_root: header.state_root.clone(),
                total_stake: header.total_stake.clone(),
                randomness: header.randomness.clone(),
                vrf_proof: header.vrf_proof.clone(),
                timestamp: header.timestamp,
                proposer: header.proposer.clone(),
            },
            &pruning,
        );
        let signature = keypair.sign(b"legacy");
        LegacyBlockV0 {
            header,
            identities: Vec::new(),
            transactions: Vec::new(),
            uptime_proofs: Vec::new(),
            timetoke_updates: Vec::new(),
            reputation_updates: Vec::new(),
            bft_votes: Vec::new(),
            module_witnesses: ModuleWitnessBundle::default(),
            proof_artifacts: vec![ProofArtifact {
                module: ProofModule::BlockWitness,
                commitment: [0u8; 32],
                proof: Vec::new(),
                verification_key: None,
            }],
            pruning_proof: pruning,
            recursive_proof: recursive,
            stark: BlockStarkProofs {
                transaction_proofs: vec![dummy_proof(ProofKind::Transaction)],
                state_proof: dummy_proof(ProofKind::State),
                pruning_proof: dummy_proof(ProofKind::Pruning),
                recursive_proof: dummy_proof(ProofKind::Recursive),
            },
            signature: signature_to_hex(&signature),
            consensus: ConsensusCertificate::genesis(),
            hash: "ff".repeat(32),
            pruned: false,
        }
    }

    #[test]
    fn migrates_legacy_block_records() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("db");
        std::fs::create_dir_all(&db_path).unwrap();

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cf_descriptors = vec![
            rocksdb::ColumnFamilyDescriptor::new(CF_BLOCKS, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_METADATA, rocksdb::Options::default()),
        ];
        let db = rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::open_cf_descriptors(
            &opts,
            &db_path,
            cf_descriptors,
        )
        .unwrap();
        {
            let blocks_cf = db.cf_handle(CF_BLOCKS).unwrap();
            let legacy = legacy_block();
            let bytes = bincode::serialize(&legacy).unwrap();
            db.put_cf(&blocks_cf, 1u64.to_be_bytes(), bytes).unwrap();
        }
        drop(db);

        let report = migrate_storage(&db_path, false).unwrap();
        assert_eq!(report.from_version, 0);
        assert_eq!(report.to_version, STORAGE_SCHEMA_VERSION);
        assert_eq!(report.upgraded_blocks, 1);

        let storage = Storage::open(&db_path).unwrap();
        let block = storage.read_block(1).unwrap().unwrap();
        assert_eq!(block.header.height, 1);
        assert!(!block.pruned);
    }

    #[test]
    fn dry_run_does_not_persist_changes() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("db");
        std::fs::create_dir_all(&db_path).unwrap();

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cf_descriptors = vec![
            rocksdb::ColumnFamilyDescriptor::new(CF_BLOCKS, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_METADATA, rocksdb::Options::default()),
        ];
        let db = rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::open_cf_descriptors(
            &opts,
            &db_path,
            cf_descriptors,
        )
        .unwrap();
        {
            let blocks_cf = db.cf_handle(CF_BLOCKS).unwrap();
            let legacy = legacy_block();
            let bytes = bincode::serialize(&legacy).unwrap();
            db.put_cf(&blocks_cf, 1u64.to_be_bytes(), bytes).unwrap();
        }
        drop(db);

        let report = migrate_storage(&db_path, true).unwrap();
        assert_eq!(report.upgraded_blocks, 1);

        let db = Storage::open_db(&db_path).unwrap();
        let metadata_cf = db.cf_handle(CF_METADATA).unwrap();
        assert!(
            db.get_cf(&metadata_cf, SCHEMA_VERSION_KEY)
                .unwrap()
                .is_none()
        );
    }
}
