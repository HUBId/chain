use std::path::Path;

use serde::{Deserialize, Serialize};
use storage_firewood::kv::FirewoodKv;

use crate::consensus::{ConsensusCertificate, SignedBftVote};
use crate::errors::{ChainError, ChainResult};
use crate::rpp::{ModuleWitnessBundle, ProofArtifact};
use crate::storage::{STORAGE_SCHEMA_VERSION, Storage};
use crate::types::{
    AttestedIdentityRequest, Block, BlockHeader, BlockProofBundle, IdentityDeclaration,
    ProofSystem, PruningProof, PruningProofExt, RecursiveProof, ReputationUpdate, SignedTransaction,
    StoredBlock, TimetokeUpdate, UptimeProof, canonical_pruning_from_block,
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

    let mut kv = Storage::open_db(path)?;
    let current_version = Storage::read_schema_version_raw(&kv)?.unwrap_or(0);
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

    let (converted, already_current) = migrate_block_records(&mut kv, dry_run)?;
    report.upgraded_blocks += converted;
    report.already_current_blocks += already_current;

    if !dry_run {
        Storage::write_schema_version_raw(&mut kv, STORAGE_SCHEMA_VERSION)?;
    }
    report.to_version = STORAGE_SCHEMA_VERSION;

    Ok(report)
}

fn migrate_block_records(kv: &mut FirewoodKv, dry_run: bool) -> ChainResult<(usize, usize)> {
    let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[b'b']).collect();
    let mut converted = 0usize;
    let mut already_current = 0usize;
    let mut mutated = false;

    for (key, value) in entries {
        if bincode::deserialize::<StoredBlock>(&value).is_ok() {
            already_current += 1;
            continue;
        }

        if let Ok(block) = bincode::deserialize::<Block>(&value) {
            if !dry_run {
                let stored = StoredBlock::from_block(&block);
                let bytes = bincode::serialize(&stored)?;
                kv.put(key.clone(), bytes);
                mutated = true;
            }
            converted += 1;
            continue;
        }

        let legacy: LegacyBlockV0 = bincode::deserialize(&value)?;
        let block = legacy.into_block()?;
        if !dry_run {
            let stored = StoredBlock::from_block(&block);
            let bytes = bincode::serialize(&stored)?;
            kv.put(key.clone(), bytes);
            mutated = true;
        }
        converted += 1;
    }

    if mutated {
        kv.commit()?;
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
struct LegacyRecursiveProof {
    pub system: ProofSystem,
    pub proof_commitment: String,
    pub previous_proof_commitment: String,
    pub previous_chain_commitment: String,
    pub chain_commitment: String,
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
    pub recursive_proof: LegacyRecursiveProof,
    pub stark: BlockProofBundle,
    pub signature: String,
    pub consensus: ConsensusCertificate,
    pub hash: String,
    #[serde(default)]
    pub pruned: bool,
}

impl LegacyBlockV0 {
    fn into_block(self) -> ChainResult<Block> {
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
            vrf_public_key: String::new(),
            vrf_preoutput: String::new(),
            vrf_proof: header.vrf_proof,
            timestamp: header.timestamp,
            proposer: header.proposer,
            leader_tier: "Committed".into(),
            leader_timetoke: 0,
        };

        let previous_commitment = Some(recursive_proof.previous_chain_commitment.clone());
        let recursive = RecursiveProof::from_parts(
            recursive_proof.system,
            recursive_proof.chain_commitment,
            previous_commitment,
            stark.recursive_proof.clone(),
        )?;

        let identities: Vec<AttestedIdentityRequest> = identities
            .into_iter()
            .map(|declaration| AttestedIdentityRequest {
                declaration,
                attested_votes: Vec::new(),
                gossip_confirmations: Vec::new(),
            })
            .collect();

        Ok(Block {
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
            recursive_proof: recursive,
            consensus_proof: None,
            stark,
            signature,
            consensus,
            hash,
            pruned,
        })
    }
}

/// Utility exposing whether a storage directory already advertises the
/// expected schema version.
pub fn storage_is_current(path: &Path) -> ChainResult<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let kv = Storage::open_db(path)?;
    let version = Storage::read_schema_version_raw(&kv)?.unwrap_or(0);
    Ok(version >= STORAGE_SCHEMA_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, signature_to_hex};
    use crate::reputation::{ReputationWeights, Tier};
    use crate::rpp::ProofModule;
    use crate::storage::SCHEMA_VERSION_KEY;
    use crate::stwo::circuit::{
        ExecutionTrace, TraceSegment,
        consensus::{ConsensusWitness, VotePower},
        pruning::PruningWitness,
        recursive::RecursiveWitness,
        state::StateWitness,
        uptime::UptimeWitness,
    };
    use crate::stwo::proof::{
        CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
    };
    use crate::types::ChainProof;
    use ed25519_dalek::Signer;
    use tempfile::tempdir;

    fn dummy_recursive_chain_proof(
        header: &BlockHeader,
        pruning: &PruningProof,
        previous: Option<String>,
    ) -> ChainProof {
        let aggregated_commitment = "77".repeat(32);
        ChainProof::Stwo(StarkProof {
            kind: ProofKind::Recursive,
            commitment: aggregated_commitment.clone(),
            public_inputs: Vec::new(),
            payload: ProofPayload::Recursive(RecursiveWitness {
                previous_commitment: previous.or_else(|| Some(RecursiveProof::anchor())),
                aggregated_commitment,
                identity_commitments: Vec::new(),
                tx_commitments: Vec::new(),
                uptime_commitments: Vec::new(),
                consensus_commitments: Vec::new(),
                state_commitment: header.state_root.clone(),
                global_state_root: header.state_root.clone(),
                utxo_root: header.utxo_root.clone(),
                reputation_root: header.reputation_root.clone(),
                timetoke_root: header.timetoke_root.clone(),
                zsi_root: header.zsi_root.clone(),
                proof_root: header.proof_root.clone(),
                pruning_commitment: pruning.binding_digest_hex(),
                block_height: header.height,
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        })
    }

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
                previous_commitment: Some(RecursiveProof::anchor()),
                aggregated_commitment: "77".repeat(32),
                identity_commitments: vec!["88".repeat(32)],
                tx_commitments: vec!["99".repeat(32)],
                uptime_commitments: vec!["aa".repeat(32)],
                consensus_commitments: vec!["bb".repeat(32)],
                state_commitment: "aa".repeat(32),
                global_state_root: "cc".repeat(32),
                utxo_root: "dd".repeat(32),
                reputation_root: "ee".repeat(32),
                timetoke_root: "ff".repeat(32),
                zsi_root: "11".repeat(32),
                proof_root: "22".repeat(32),
                pruning_commitment: "bb".repeat(32),
                block_height: 1,
            }),
            ProofKind::Uptime => ProofPayload::Uptime(UptimeWitness {
                wallet_address: "alice".into(),
                node_clock: 10_000,
                epoch: 1,
                head_hash: "11".repeat(32),
                window_start: 5_000,
                window_end: 8_600,
                commitment: "22".repeat(32),
            }),
            ProofKind::Consensus => ProofPayload::Consensus(ConsensusWitness {
                block_hash: "33".repeat(32),
                round: 1,
                leader_proposal: "33".repeat(32),
                quorum_threshold: 1,
                pre_votes: vec![VotePower {
                    voter: "alice".into(),
                    weight: 1,
                }],
                pre_commits: vec![VotePower {
                    voter: "alice".into(),
                    weight: 1,
                }],
                commit_votes: vec![VotePower {
                    voter: "alice".into(),
                    weight: 1,
                }],
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
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
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
        let pruning = canonical_pruning_from_block(None, &header)
            .expect("construct canonical pruning proof");
        let converted_header = BlockHeader {
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
            vrf_public_key: String::new(),
            vrf_preoutput: String::new(),
            vrf_proof: header.vrf_proof.clone(),
            timestamp: header.timestamp,
            proposer: header.proposer.clone(),
            leader_tier: "Committed".into(),
            leader_timetoke: 0,
        };
        let recursive_chain_proof = dummy_recursive_chain_proof(&converted_header, &pruning, None);
        let previous_commitment = RecursiveProof::anchor();
        let proof_commitment = match &recursive_chain_proof {
            ChainProof::Stwo(proof) => proof.commitment.clone(),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(value) => value
                .get("payload")
                .and_then(|payload| payload.get("commitment"))
                .and_then(|commitment| commitment.as_str())
                .map(|commitment| commitment.to_string())
                .expect("plonky3 recursive payload commitment"),
        };
        let chain_commitment = proof_commitment.clone();
        let legacy_recursive = LegacyRecursiveProof {
            system: ProofSystem::Stwo,
            proof_commitment: proof_commitment.clone(),
            previous_proof_commitment: proof_commitment,
            previous_chain_commitment: previous_commitment.clone(),
            chain_commitment,
        };
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
            recursive_proof: legacy_recursive,
            stark: BlockProofBundle {
                transaction_proofs: vec![ChainProof::Stwo(dummy_proof(ProofKind::Transaction))],
                state_proof: ChainProof::Stwo(dummy_proof(ProofKind::State)),
                pruning_proof: ChainProof::Stwo(dummy_proof(ProofKind::Pruning)),
                recursive_proof: recursive_chain_proof,
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
        let mut kv = Storage::open_db(&db_path).unwrap();
        let legacy = legacy_block();
        let bytes = bincode::serialize(&legacy).unwrap();
        let mut key = vec![b'b'];
        key.extend_from_slice(&1u64.to_be_bytes());
        kv.put(key, bytes);
        kv.commit().unwrap();
        drop(kv);

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
        let mut kv = Storage::open_db(&db_path).unwrap();
        let legacy = legacy_block();
        let bytes = bincode::serialize(&legacy).unwrap();
        let mut key = vec![b'b'];
        key.extend_from_slice(&1u64.to_be_bytes());
        kv.put(key, bytes);
        kv.commit().unwrap();
        drop(kv);

        let report = migrate_storage(&db_path, true).unwrap();
        assert_eq!(report.upgraded_blocks, 1);

        let kv = Storage::open_db(&db_path).unwrap();
        let mut schema_key = vec![b'm'];
        schema_key.extend_from_slice(SCHEMA_VERSION_KEY);
        assert!(kv.get(&schema_key).is_none());
    }
}
