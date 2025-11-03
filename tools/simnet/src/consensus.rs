use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use libp2p::PeerId;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use rpp_chain::consensus::{
    ConsensusCertificate, ConsensusProofMetadata, ConsensusProofMetadataVrf, ConsensusVrfEntry,
    ConsensusVrfPoseidonInput, TalliedVote,
};
use rpp_chain::consensus_engine::messages::BlockId;
use rpp_chain::errors::ChainError;
use rpp_chain::plonky3::proof::Plonky3Proof;
use rpp_chain::plonky3::prover::Plonky3Prover;
use rpp_chain::plonky3::verifier::Plonky3Verifier;
use rpp_chain::proof_system::ProofProver;
use rpp_chain::proof_system::ProofVerifier;
use rpp_chain::types::ChainProof;
use rpp_chain::vrf::{generate_vrf, generate_vrf_keypair, vrf_public_key_to_hex, PoseidonVrfInput};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::ConsensusLoadConfig;

const DEFAULT_SEED: u64 = 0x706C_6F6E_6B33_3032;
const DEFAULT_REPUTATION_ROOTS: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantileStats {
    pub min: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
    pub mean: f64,
}

impl QuantileStats {
    fn from_samples(samples: &[f64]) -> Self {
        if samples.is_empty() {
            return Self {
                min: 0.0,
                p50: 0.0,
                p90: 0.0,
                p95: 0.0,
                p99: 0.0,
                max: 0.0,
                mean: 0.0,
            };
        }

        let mut values = samples.to_vec();
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let len = values.len() as f64;
        let mean = values.iter().copied().sum::<f64>() / len;

        Self {
            min: *values.first().unwrap(),
            p50: percentile(&values, 0.50),
            p90: percentile(&values, 0.90),
            p95: percentile(&values, 0.95),
            p99: percentile(&values, 0.99),
            max: *values.last().unwrap(),
            mean,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperSummary {
    pub attempts: u64,
    pub rejected: u64,
    pub unexpected_accepts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusLoadSummary {
    #[serde(rename = "kind")]
    pub kind: String,
    pub runs: u64,
    pub validators: usize,
    pub witness_commitments: usize,
    pub security_bits: u32,
    pub use_gpu: bool,
    pub seed: u64,
    pub summary_path: PathBuf,
    pub csv_path: Option<PathBuf>,
    pub prove_ms: QuantileStats,
    pub verify_ms: QuantileStats,
    pub proof_bytes: QuantileStats,
    pub failures: Vec<String>,
    pub tamper_vrf: Option<TamperSummary>,
    pub tamper_quorum: Option<TamperSummary>,
}

#[derive(Debug)]
struct RunRecord {
    run: u64,
    prove_ms: f64,
    verify_ms: Option<f64>,
    proof_bytes: f64,
}

pub fn run_consensus_load(
    config: ConsensusLoadConfig,
    summary_path: PathBuf,
    csv_path: Option<PathBuf>,
) -> Result<ConsensusLoadSummary> {
    let mut prover = Plonky3Prover::new();
    if let Some(bits) = config.security_bits {
        prover.params.security_bits = bits;
    }
    if let Some(use_gpu) = config.use_gpu {
        prover.params.use_gpu_acceleration = use_gpu;
    }
    let verifier = Plonky3Verifier::default();
    let seed = config.seed.unwrap_or(DEFAULT_SEED);
    let mut rng = StdRng::seed_from_u64(seed);

    let mut prove_samples = Vec::with_capacity(config.runs as usize);
    let mut verify_samples = Vec::with_capacity(config.runs as usize);
    let mut proof_sizes = Vec::with_capacity(config.runs as usize);
    let mut records = Vec::with_capacity(config.runs as usize);
    let mut failures = Vec::new();

    let mut vrf_tamper = TamperTracker::new(config.tamper.vrf, config.tamper.every_n);
    let mut quorum_tamper = TamperTracker::new(config.tamper.quorum_roots, config.tamper.every_n);

    for run_idx in 0..config.runs {
        let certificate = generate_certificate(&mut rng, &config, run_idx);
        let block_hash = certificate.block_hash.0.clone();
        let witness = match prover.build_consensus_witness(&block_hash, &certificate) {
            Ok(witness) => witness,
            Err(err) => {
                failures.push(format!("run {run_idx} failed to build witness: {err}"));
                continue;
            }
        };

        let prove_start = Instant::now();
        let proof = match prover.prove_consensus(witness) {
            Ok(proof) => proof,
            Err(err) => {
                failures.push(format!("run {run_idx} failed to prove consensus: {err}"));
                continue;
            }
        };
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
        prove_samples.push(prove_ms);

        let proof_bytes = serde_json::to_vec(&proof)
            .context("serialize consensus proof for size accounting")?
            .len() as f64;
        proof_sizes.push(proof_bytes);

        let verify_start = Instant::now();
        if let Err(err) = verifier.verify_consensus(&proof) {
            failures.push(format!(
                "run {run_idx} failed to verify consensus proof: {err}"
            ));
            records.push(RunRecord {
                run: run_idx,
                prove_ms,
                verify_ms: None,
                proof_bytes,
            });
            continue;
        }
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
        verify_samples.push(verify_ms);
        records.push(RunRecord {
            run: run_idx,
            prove_ms,
            verify_ms: Some(verify_ms),
            proof_bytes,
        });

        if let Err(err) = vrf_tamper.maybe_attempt(run_idx, &proof, &verifier, tamper_vrf_payload) {
            failures.push(format!("run {run_idx} vrf tamper failed: {err}"));
        }
        if let Err(err) =
            quorum_tamper.maybe_attempt(run_idx, &proof, &verifier, tamper_quorum_payload)
        {
            failures.push(format!("run {run_idx} quorum tamper failed: {err}"));
        }
    }

    let summary = write_summary(
        &summary_path,
        &records,
        &config,
        &prove_samples,
        &verify_samples,
        &proof_sizes,
        &failures,
        &vrf_tamper,
        &quorum_tamper,
        seed,
        csv_path.clone(),
    )
    .with_context(|| format!("write consensus summary to {}", summary_path.display()))?;

    Ok(summary)
}

fn write_summary(
    summary_path: &PathBuf,
    records: &[RunRecord],
    config: &ConsensusLoadConfig,
    prove_samples: &[f64],
    verify_samples: &[f64],
    proof_sizes: &[f64],
    failures: &[String],
    vrf_tamper: &TamperTracker,
    quorum_tamper: &TamperTracker,
    seed: u64,
    csv_path: Option<PathBuf>,
) -> Result<ConsensusLoadSummary> {
    let summary = ConsensusLoadSummary {
        kind: "consensus-load".to_string(),
        runs: config.runs,
        validators: config.validators,
        witness_commitments: config.witness_commitments,
        security_bits: config
            .security_bits
            .unwrap_or_else(|| Plonky3Prover::new().params.security_bits),
        use_gpu: config.use_gpu.unwrap_or(false),
        seed,
        summary_path: summary_path.clone(),
        csv_path: csv_path.clone(),
        prove_ms: QuantileStats::from_samples(prove_samples),
        verify_ms: QuantileStats::from_samples(verify_samples),
        proof_bytes: QuantileStats::from_samples(proof_sizes),
        failures: failures.to_vec(),
        tamper_vrf: vrf_tamper.summary(),
        tamper_quorum: quorum_tamper.summary(),
    };

    let json = serde_json::to_vec_pretty(&summary).context("serialize consensus load summary")?;
    std::fs::write(summary_path, json).context("write consensus summary file")?;

    if let Some(path) = csv_path {
        write_csv(&path, records)?;
    }

    Ok(summary)
}

fn write_csv(path: &PathBuf, records: &[RunRecord]) -> Result<()> {
    let mut file = File::create(path).context("create consensus CSV")?;
    writeln!(file, "run,prove_ms,verify_ms,proof_bytes").context("write csv header")?;
    for record in records {
        let verify = record
            .verify_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "".to_string());
        writeln!(
            file,
            "{},{:.6},{},{}",
            record.run, record.prove_ms, verify, record.proof_bytes
        )
        .context("write csv row")?;
    }
    Ok(())
}

fn percentile(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let rank = percentile.clamp(0.0, 1.0) * ((values.len() - 1) as f64);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    if lower == upper {
        values[lower]
    } else {
        let weight = rank - lower as f64;
        values[lower] * (1.0 - weight) + values[upper] * weight
    }
}

fn generate_certificate(
    rng: &mut StdRng,
    config: &ConsensusLoadConfig,
    round: u64,
) -> ConsensusCertificate {
    let block_hash_bytes = random_array::<32>(rng);
    let block_hash_hex = hex::encode(block_hash_bytes);
    let mut votes = Vec::with_capacity(config.validators);
    let mut total_power = 0u64;
    for index in 0..config.validators {
        let voting_power = rng.gen_range(5..25) as u64;
        total_power += voting_power;
        votes.push(TalliedVote {
            validator_id: format!("validator-{index:04}"),
            peer_id: PeerId::random(),
            signature: random_bytes(rng, 96),
            voting_power,
        });
    }
    let quorum_threshold = ((total_power * 2) / 3).saturating_add(1);

    let vrf_entries = (0..config.validators)
        .map(|_| build_vrf_entry(rng, round, &block_hash_bytes, &block_hash_hex))
        .collect();

    let metadata = build_metadata(
        vrf_entries,
        (0..config.witness_commitments)
            .map(|_| random_hex(rng, 32))
            .collect(),
        (0..DEFAULT_REPUTATION_ROOTS)
            .map(|_| random_hex(rng, 32))
            .collect(),
        round / 32,
        round,
        random_hex(rng, 32),
        random_hex(rng, 32),
    );

    ConsensusCertificate {
        block_hash: BlockId(block_hash_hex),
        height: round,
        round,
        total_power,
        quorum_threshold,
        prevote_power: total_power,
        precommit_power: total_power,
        commit_power: total_power,
        prevotes: votes.clone(),
        precommits: votes,
        metadata,
    }
}

fn random_hex(rng: &mut StdRng, bytes: usize) -> String {
    hex::encode(random_bytes(rng, bytes))
}

fn random_bytes(rng: &mut StdRng, bytes: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; bytes];
    rng.fill_bytes(&mut buffer);
    buffer
}

fn random_array<const N: usize>(rng: &mut StdRng) -> [u8; N] {
    let mut buffer = [0u8; N];
    rng.fill_bytes(&mut buffer);
    buffer
}

fn build_vrf_entry(
    rng: &mut StdRng,
    round: u64,
    block_hash_bytes: &[u8; 32],
    block_hash_hex: &str,
) -> ConsensusVrfEntry {
    let epoch = round / 32;
    let keypair = generate_vrf_keypair();
    let tier_seed = random_array::<32>(rng);
    let input = PoseidonVrfInput::new(*block_hash_bytes, epoch, tier_seed);
    let output = generate_vrf(&input, &keypair.secret).expect("generate vrf output");

    ConsensusVrfEntry {
        randomness: hex::encode(output.randomness),
        pre_output: hex::encode(output.preoutput),
        proof: hex::encode(output.proof),
        public_key: vrf_public_key_to_hex(&keypair.public),
        poseidon: ConsensusVrfPoseidonInput {
            digest: input.poseidon_digest_hex(),
            last_block_header: block_hash_hex.to_string(),
            epoch: epoch.to_string(),
            tier_seed: hex::encode(tier_seed),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn build_metadata(
    vrf_entries: Vec<ConsensusVrfEntry>,
    witness_commitments: Vec<String>,
    reputation_roots: Vec<String>,
    epoch: u64,
    slot: u64,
    quorum_bitmap_root: String,
    quorum_signature_root: String,
) -> ConsensusProofMetadata {
    ConsensusProofMetadata {
        vrf: ConsensusProofMetadataVrf {
            entries: vrf_entries,
        },
        witness_commitments,
        reputation_roots,
        epoch,
        slot,
        quorum_bitmap_root,
        quorum_signature_root,
    }
}

fn tamper_vrf_payload(map: &mut Map<String, Value>) {
    if let Some(Value::Array(entries)) = map.get_mut("vrf_entries") {
        if entries.len() > 1 {
            entries.rotate_left(1);
            return;
        }

        if let Some(Value::Object(first)) = entries.first_mut() {
            if let Some(Value::String(randomness)) = first.get_mut("randomness") {
                *randomness = randomness.chars().rev().collect();
            }

            if let Some(Value::Object(poseidon)) =
                first.get_mut("poseidon").and_then(Value::as_object_mut)
            {
                poseidon.insert("digest".into(), Value::String("deadbeef".repeat(8)));
            }
        }
    }
}

fn tamper_quorum_payload(map: &mut Map<String, Value>) {
    map.insert(
        "quorum_bitmap_root".into(),
        Value::String("deadbeef".into()),
    );
}

struct TamperTracker {
    enabled: bool,
    every_n: u64,
    attempts: u64,
    rejected: u64,
    unexpected_accepts: u64,
}

impl TamperTracker {
    fn new(enabled: bool, every_n: u64) -> Self {
        Self {
            enabled,
            every_n: if every_n == 0 { 1 } else { every_n },
            attempts: 0,
            rejected: 0,
            unexpected_accepts: 0,
        }
    }

    fn maybe_attempt(
        &mut self,
        run_idx: u64,
        proof: &ChainProof,
        verifier: &Plonky3Verifier,
        mutator: fn(&mut Map<String, Value>),
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if run_idx % self.every_n != 0 {
            return Ok(());
        }
        self.attempts += 1;
        let tampered = tamper_proof(proof, mutator)?;
        match verifier.verify_consensus(&tampered) {
            Ok(_) => {
                self.unexpected_accepts += 1;
            }
            Err(_) => {
                self.rejected += 1;
            }
        }
        Ok(())
    }

    fn summary(&self) -> Option<TamperSummary> {
        if !self.enabled || self.attempts == 0 {
            return None;
        }
        Some(TamperSummary {
            attempts: self.attempts,
            rejected: self.rejected,
            unexpected_accepts: self.unexpected_accepts,
        })
    }
}

fn tamper_proof(proof: &ChainProof, mutator: fn(&mut Map<String, Value>)) -> Result<ChainProof> {
    match proof {
        ChainProof::Plonky3(value) => {
            let mut parsed = Plonky3Proof::from_value(value)?;
            let witness = parsed
                .public_inputs
                .get_mut("witness")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| anyhow!("consensus witness payload missing"))?;
            mutator(witness);
            let value = parsed.into_value()?;
            Ok(ChainProof::Plonky3(value))
        }
        _ => Err(anyhow!("expected Plonky3 proof")),
    }
}

impl From<ChainError> for anyhow::Error {
    fn from(value: ChainError) -> Self {
        anyhow!(value.to_string())
    }
}
