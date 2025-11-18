use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use tracing::{instrument, trace_span};

#[derive(Clone, Debug)]
pub struct WalletPerfConfig {
    pub addresses: usize,
    pub utxos_per_address: usize,
    pub sync_batch: usize,
    pub selection_amount: u128,
    pub min_confirmations: u32,
    pub fee_cache_ttl_secs: u64,
    pub prover_iterations: u32,
    pub prover_jobs: usize,
    pub prover_witness_bytes: usize,
}

impl Default for WalletPerfConfig {
    fn default() -> Self {
        Self {
            addresses: 4_096,
            utxos_per_address: 6,
            sync_batch: 64,
            selection_amount: 2_500_000,
            min_confirmations: 2,
            fee_cache_ttl_secs: 0,
            prover_iterations: 4,
            prover_jobs: 4,
            prover_witness_bytes: 256 * 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MockAddress {
    pub label: String,
    pub scripthash: [u8; 32],
    pub utxos: Vec<MockUtxo>,
}

#[derive(Clone, Debug)]
pub struct MockUtxo {
    pub value: u128,
    pub confirmations: u32,
    pub pending: bool,
}

#[derive(Clone, Debug)]
pub struct LargeWallet {
    pub addresses: Vec<MockAddress>,
}

#[instrument(name = "wallet.perf.build", skip(config))]
pub fn build_wallet(config: &WalletPerfConfig) -> LargeWallet {
    let mut rng = StdRng::seed_from_u64(0xfeed_cafe_u64);
    let mut addresses = Vec::with_capacity(config.addresses);
    for index in 0..config.addresses {
        let mut hasher = Sha256::new();
        hasher.update(index.to_le_bytes());
        hasher.update((config.utxos_per_address as u64).to_le_bytes());
        let scripthash: [u8; 32] = hasher.finalize().into();
        let mut utxos = Vec::with_capacity(config.utxos_per_address);
        for _ in 0..config.utxos_per_address {
            let value = rng.random_range(25_000..250_000) as u128;
            let confirmations = rng.random_range(0..150);
            let pending = rng.random_bool(0.04);
            utxos.push(MockUtxo {
                value,
                confirmations,
                pending,
            });
        }
        addresses.push(MockAddress {
            label: format!("addr-{index:04}"),
            scripthash,
            utxos,
        });
    }
    LargeWallet { addresses }
}

#[derive(Clone, Copy, Debug)]
pub struct SyncStats {
    pub elapsed: Duration,
    pub visited: usize,
    pub utxos: usize,
}

#[instrument(name = "wallet.perf.sync", skip(wallet), fields(batch = batch_size))]
pub fn simulate_sync(wallet: &LargeWallet, batch_size: usize) -> SyncStats {
    let start = Instant::now();
    let mut visited = 0usize;
    let mut utxos = 0usize;
    for chunk in wallet.addresses.chunks(batch_size.max(1)) {
        let span = trace_span!("wallet.perf.sync_batch", addresses = chunk.len());
        let _guard = span.enter();
        for address in chunk {
            visited += 1;
            utxos += address.utxos.len();
            let mut hasher = Sha256::new();
            hasher.update(address.scripthash);
            for utxo in &address.utxos {
                hasher.update(utxo.value.to_le_bytes());
                hasher.update(utxo.confirmations.to_le_bytes());
            }
            let digest = hasher.finalize();
            let _ = digest[0];
        }
    }
    SyncStats {
        elapsed: start.elapsed(),
        visited,
        utxos,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SelectionStats {
    pub elapsed: Duration,
    pub selected_inputs: usize,
    pub total_value: u128,
}

#[instrument(name = "wallet.perf.coin_selection", skip(wallet))]
pub fn simulate_coin_selection(
    wallet: &LargeWallet,
    amount: u128,
    min_confirmations: u32,
) -> SelectionStats {
    let candidates: Vec<CandidateUtxo> = wallet
        .addresses
        .iter()
        .flat_map(|address| {
            address.utxos.iter().map(|utxo| CandidateUtxo {
                value: utxo.value,
                confirmations: utxo.confirmations,
                pending: utxo.pending,
            })
        })
        .collect();
    let start = Instant::now();
    let result = select_coins(&candidates, amount, min_confirmations);
    SelectionStats {
        elapsed: start.elapsed(),
        selected_inputs: result.len(),
        total_value: result.iter().map(|candidate| candidate.value).sum(),
    }
}

#[derive(Clone, Debug)]
pub struct CandidateUtxo {
    value: u128,
    confirmations: u32,
    pending: bool,
}

fn select_coins<'a>(
    candidates: &'a [CandidateUtxo],
    amount: u128,
    min_confirmations: u32,
) -> Vec<&'a CandidateUtxo> {
    let mut available: Vec<&CandidateUtxo> = candidates.iter().filter(|c| !c.pending).collect();
    let mut confirmed: Vec<&CandidateUtxo> = available
        .iter()
        .copied()
        .filter(|c| c.confirmations >= min_confirmations)
        .collect();

    confirmed.sort_by(|a, b| b.value.cmp(&a.value));
    let mut total = 0u128;
    let mut selected = Vec::new();
    for candidate in &confirmed {
        total = total.saturating_add(candidate.value);
        selected.push(*candidate);
        if total >= amount {
            return selected;
        }
    }

    available.sort_by(|a, b| b.value.cmp(&a.value));
    for candidate in &available {
        total = total.saturating_add(candidate.value);
        selected.push(*candidate);
        if total >= amount {
            break;
        }
    }

    selected
}

#[derive(Clone, Debug)]
pub struct SimMempool {
    pub utilization: f64,
    pub min_rate: u64,
    pub max_rate: u64,
    pub block_medians: Vec<u64>,
}

impl Default for SimMempool {
    fn default() -> Self {
        Self {
            utilization: 0.72,
            min_rate: 2,
            max_rate: 250,
            block_medians: (0..48).map(|h| 15 + (h % 11) as u64).collect(),
        }
    }
}

#[derive(Debug)]
pub struct FeeEstimatorSim {
    cache_ttl: Duration,
    cache: Mutex<Option<(Instant, u64)>>,
}

impl FeeEstimatorSim {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache_ttl: ttl,
            cache: Mutex::new(None),
        }
    }

    #[instrument(name = "wallet.perf.fee_estimator", skip(self, mempool))]
    pub fn resolve(&self, mempool: &SimMempool) -> u64 {
        if let Some((created, rate)) = self.cache.lock().ok().and_then(|guard| *guard) {
            if self.cache_ttl.is_zero() || created.elapsed() <= self.cache_ttl {
                return rate;
            }
        }
        let mut samples = mempool.block_medians.clone();
        samples.sort_unstable();
        let mut rate = samples
            .get(samples.len() / 2)
            .copied()
            .unwrap_or(mempool.min_rate);
        if mempool.utilization > 0.85 {
            rate = rate.saturating_mul(2);
        } else if mempool.utilization > 0.65 {
            rate = rate.saturating_add(rate / 2);
        }
        rate = rate.clamp(mempool.min_rate, mempool.max_rate);
        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some((Instant::now(), rate));
        }
        rate
    }
}

#[derive(Clone, Debug)]
pub struct ProverSimConfig {
    pub iterations: u32,
    pub jobs: usize,
    pub witness_bytes: usize,
}

impl From<&WalletPerfConfig> for ProverSimConfig {
    fn from(config: &WalletPerfConfig) -> Self {
        Self {
            iterations: config.prover_iterations,
            jobs: config.prover_jobs,
            witness_bytes: config.prover_witness_bytes,
        }
    }
}

#[instrument(name = "wallet.perf.prover", skip_all)]
pub fn simulate_prover_jobs(config: &ProverSimConfig) -> Duration {
    let start = Instant::now();
    let jobs = config.jobs;
    let witness_len = config.witness_bytes.max(1024);
    let iterations = config.iterations.max(1);
    let mut handles = Vec::with_capacity(jobs);
    for job in 0..jobs {
        handles.push(thread::spawn(move || {
            let mut buffer = vec![job as u8; witness_len];
            for round in 0..iterations {
                let mut hasher = Sha256::new();
                hasher.update(&buffer);
                hasher.update(job.to_le_bytes());
                hasher.update(round.to_le_bytes());
                let digest = hasher.finalize();
                for chunk in buffer.chunks_mut(digest.len()) {
                    for (value, byte) in chunk.iter_mut().zip(digest.iter().cycle()) {
                        *value = value.wrapping_add(*byte);
                    }
                }
            }
            buffer[0]
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    start.elapsed()
}
