use std::convert::TryFrom;
use std::fs;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::wallet::{WalletProverBackend, WalletProverConfig};

use super::{
    DraftProverContext, ProveResult, ProverError, ProverIdentity, ProverMeta, WalletProver,
    WitnessPlan,
};
use crate::engine::DraftTransaction;
use metrics::{counter, gauge, histogram};
use prover_backend_interface::{
    Blake2sHasher, ProofBytes, ProofHeader, ProofSystemKind, WitnessBytes, WitnessHeader,
};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task;
use tokio::time::{timeout_at, Instant as TokioInstant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeroize::Zeroize;

#[cfg(feature = "prover-stwo")]
use super::stwo::StwoWitnessAdapter;
#[cfg(feature = "prover-stwo")]
use prover_backend_interface::{ProvingKey, TxCircuitDef};
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::backend::StwoBackend;

const MOCK_CIRCUIT_ID: &str = "wallet.tx";
#[cfg(feature = "prover-stwo")]
const STWO_CIRCUIT_ID: &str = "transaction";

#[derive(Clone, Debug, Default)]
struct ResourceUsage {
    cpu_percent: f32,
    memory_bytes: u64,
    memory_limit_bytes: Option<u64>,
}

trait ResourceProbe: Send + Sync {
    fn sample(&self) -> ResourceUsage;
}

#[derive(Default)]
struct SysinfoProbe {
    system: Mutex<System>,
}

impl SysinfoProbe {
    fn refresh_limits(&self) -> ResourceUsage {
        let mut guard = self.system.lock().expect("sysinfo mutex poisoned");
        guard.refresh_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::new().with_ram().with_swap()),
        );
        // sysinfo reports memory usage in KiB; normalize to bytes for limit comparisons.
        let memory_bytes = guard.used_memory() * 1024;
        let cpu_percent = guard.global_cpu_info().cpu_usage();
        ResourceUsage {
            cpu_percent,
            memory_bytes,
            memory_limit_bytes: detect_cgroup_memory_limit(),
        }
    }
}

impl ResourceProbe for SysinfoProbe {
    fn sample(&self) -> ResourceUsage {
        self.refresh_limits()
    }
}

struct ResourceLimiter {
    cpu_limit_percent: Option<f32>,
    memory_limit_bytes: Option<u64>,
    warn_ratio: f32,
    backoff: Duration,
    retries: u16,
    probe: Arc<dyn ResourceProbe>,
}

impl ResourceLimiter {
    fn new(config: &WalletProverConfig, probe: Arc<dyn ResourceProbe>) -> Self {
        let warn_ratio = (config.limit_warn_percent as f32) / 100.0;
        Self {
            cpu_limit_percent: if config.cpu_quota_percent == 0 {
                None
            } else {
                Some(config.cpu_quota_percent as f32)
            },
            memory_limit_bytes: if config.memory_quota_bytes == 0 {
                None
            } else {
                Some(config.memory_quota_bytes)
            },
            warn_ratio,
            backoff: config.limit_backoff(),
            retries: config.limit_retries,
            probe,
        }
    }

    fn throttle_if_needed(&self, backend: &'static str) -> Result<Option<Duration>, ProverError> {
        if self.cpu_limit_percent.is_none() && self.memory_limit_bytes.is_none() {
            return Ok(None);
        }

        let mut attempts: u16 = 0;
        loop {
            let usage = self.probe.sample();
            let memory_limit = self.active_memory_limit(&usage);

            let mut should_throttle = false;
            let mut warn_only = false;

            if let Some(limit) = self.cpu_limit_percent {
                if usage.cpu_percent >= limit {
                    should_throttle = true;
                } else if usage.cpu_percent >= limit * self.warn_ratio {
                    warn_only = true;
                }
            }

            if let Some(limit_bytes) = memory_limit {
                if usage.memory_bytes >= limit_bytes {
                    should_throttle = true;
                } else if usage.memory_bytes >= (limit_bytes as f32 * self.warn_ratio) as u64 {
                    warn_only = true;
                }
            }

            if should_throttle {
                attempts = attempts.saturating_add(1);
                counter!(
                    "wallet.prover.resource.throttled",
                    "backend" => backend,
                    "limit" => self.describe_limits(memory_limit)
                )
                .increment(1);
                warn!(
                    backend,
                    cpu_percent = usage.cpu_percent,
                    memory_bytes = usage.memory_bytes,
                    memory_limit_bytes = memory_limit,
                    attempts,
                    "wallet prover throttling due to resource limit"
                );
                if attempts > self.retries {
                    return Err(ProverError::Busy);
                }
                std::thread::sleep(self.backoff);
                continue;
            }

            if warn_only {
                counter!(
                    "wallet.prover.resource.warning",
                    "backend" => backend,
                    "limit" => self.describe_limits(memory_limit)
                )
                .increment(1);
                warn!(
                    backend,
                    cpu_percent = usage.cpu_percent,
                    memory_bytes = usage.memory_bytes,
                    memory_limit_bytes = memory_limit,
                    "wallet prover nearing resource limits"
                );
            }

            let delay = if warn_only { Some(self.backoff) } else { None };
            return Ok(delay);
        }
    }

    fn active_memory_limit(&self, usage: &ResourceUsage) -> Option<u64> {
        match (self.memory_limit_bytes, usage.memory_limit_bytes) {
            (Some(configured), Some(cgroup)) => Some(configured.min(cgroup)),
            (Some(configured), None) => Some(configured),
            (None, Some(cgroup)) => Some(cgroup),
            (None, None) => None,
        }
    }

    fn describe_limits(&self, memory_limit: Option<u64>) -> String {
        let cpu = self
            .cpu_limit_percent
            .map(|v| format!("cpu:{v:.0}%"))
            .unwrap_or_else(|| "cpu:none".to_string());
        let memory = memory_limit
            .map(|bytes| format!("mem:{}", bytes))
            .unwrap_or_else(|| "mem:none".to_string());
        format!("{cpu},{memory}")
    }
}

fn detect_cgroup_memory_limit() -> Option<u64> {
    read_cgroup_limit("/sys/fs/cgroup/memory.max")
        .or_else(|| read_cgroup_limit("/sys/fs/cgroup/memory.limit_in_bytes"))
}

fn read_cgroup_limit(path: &str) -> Option<u64> {
    let contents = fs::read_to_string(path).ok()?;
    let trimmed = contents.trim();
    if trimmed.eq_ignore_ascii_case("max") {
        return None;
    }
    trimmed.parse::<u64>().ok()
}

fn build_backend(
    config: &WalletProverConfig,
    backend: WalletProverBackend,
) -> Result<Arc<dyn WalletProver>, ProverError> {
    match backend {
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

struct FallbackWalletProver {
    primary: Arc<dyn WalletProver>,
    fallback: Arc<dyn WalletProver>,
    primary_backend: &'static str,
    fallback_backend: &'static str,
}

impl FallbackWalletProver {
    fn new(primary: Arc<dyn WalletProver>, fallback: Arc<dyn WalletProver>) -> Self {
        let primary_backend = primary.identity().backend;
        let fallback_backend = fallback.identity().backend;
        Self {
            primary,
            fallback,
            primary_backend,
            fallback_backend,
        }
    }

    fn overload_reason(&self, error: &ProverError) -> Option<&'static str> {
        match error {
            ProverError::Busy => Some("busy"),
            ProverError::Timeout(_) => Some("timeout"),
            _ => None,
        }
    }

    fn record_fallback(&self, stage: &'static str, reason: &'static str) {
        record_fallback_event(self.primary_backend, self.fallback_backend, stage, reason);
        warn!(
            stage,
            reason,
            primary = self.primary_backend,
            fallback = self.fallback_backend,
            "wallet prover falling back to secondary backend",
        );
    }

    fn prover_for_backend(&self, backend: &str) -> &Arc<dyn WalletProver> {
        if backend == self.fallback_backend {
            &self.fallback
        } else {
            &self.primary
        }
    }
}

impl WalletProver for FallbackWalletProver {
    fn identity(&self) -> ProverIdentity {
        ProverIdentity::new("fallback-router", false)
    }

    fn prepare_witness(&self, ctx: &DraftProverContext<'_>) -> Result<WitnessPlan, ProverError> {
        match self.primary.prepare_witness(ctx) {
            Ok(plan) => Ok(plan.with_backend(self.primary_backend)),
            Err(err) => {
                if let Some(reason) = self.overload_reason(&err) {
                    self.record_fallback("prepare", reason);
                    let plan = self
                        .fallback
                        .prepare_witness(ctx)?
                        .with_backend(self.fallback_backend);
                    Ok(plan)
                } else {
                    Err(err)
                }
            }
        }
    }

    fn prove(
        &self,
        ctx: &DraftProverContext<'_>,
        plan: WitnessPlan,
    ) -> Result<ProveResult, ProverError> {
        let target_backend = plan.backend();
        let prover = self.prover_for_backend(target_backend);
        let result = prover.prove(ctx, plan);

        match result {
            Ok(result) => Ok(result),
            Err(err) => {
                if target_backend == self.primary_backend {
                    if let Some(reason) = self.overload_reason(&err) {
                        self.record_fallback("prove", reason);
                        let plan = self
                            .fallback
                            .prepare_witness(ctx)?
                            .with_backend(self.fallback_backend);
                        return self.fallback.prove(ctx, plan);
                    }
                }
                Err(err)
            }
        }
    }

    fn attest_metadata(
        &self,
        ctx: &DraftProverContext<'_>,
        result: &ProveResult,
    ) -> Result<ProverMeta, ProverError> {
        let backend = result.backend();
        let prover = self.prover_for_backend(backend);
        prover.attest_metadata(ctx, result)
    }
}

pub fn build_wallet_prover(
    config: &WalletProverConfig,
) -> Result<Arc<dyn WalletProver>, ProverError> {
    if !config.enabled {
        return Ok(Arc::new(DisabledWalletProver::new(
            "wallet prover backend disabled",
        )));
    }
    let primary = build_backend(config, config.backend)?;
    if let Some(fallback_backend) = config.fallback_backend {
        let mut fallback_config = config.clone();
        fallback_config.backend = fallback_backend;
        let fallback = build_backend(&fallback_config, fallback_backend)?;
        Ok(Arc::new(FallbackWalletProver::new(primary, fallback)))
    } else {
        Ok(primary)
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
            self.jobs
                .ensure_witness_capacity(backend, witness_bytes, None)?;
            Ok((witness, witness_bytes))
        })();

        result
            .map(|(witness, _)| {
                let plan = WitnessPlan::with_parts(witness, Instant::now()).with_backend(backend);
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
    adapter: StwoWitnessAdapter,
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
            adapter: StwoWitnessAdapter::new(config.max_stwo_witness_bytes()),
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
        let result = self.adapter.prepare_witness(&self.jobs, ctx.draft());

        result
            .map(|plan| {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProverPriority {
    ConsensusCritical,
    Background,
}

impl ProverPriority {
    fn as_label(&self) -> &'static str {
        match self {
            ProverPriority::ConsensusCritical => "consensus",
            ProverPriority::Background => "background",
        }
    }
}

#[derive(Default)]
struct QueueTelemetry {
    waiting_consensus: AtomicU64,
    waiting_background: AtomicU64,
    inflight_consensus: AtomicUsize,
    inflight_background: AtomicUsize,
}

impl QueueTelemetry {
    fn record_enqueue(&self, priority: ProverPriority, backend: &'static str) {
        match priority {
            ProverPriority::ConsensusCritical => {
                self.waiting_consensus.fetch_add(1, Ordering::Relaxed);
            }
            ProverPriority::Background => {
                self.waiting_background.fetch_add(1, Ordering::Relaxed);
            }
        }
        counter!(
            "wallet.prover.queue.enqueued",
            "backend" => backend,
            "class" => priority.as_label()
        )
        .increment(1);
        gauge!(
            "wallet.prover.queue.pending",
            "backend" => backend,
            "class" => priority.as_label()
        )
        .increment(1.0);
    }

    fn record_start(&self, priority: ProverPriority, backend: &'static str) {
        self.record_waiting_delta(priority, backend, -1.0);
        match priority {
            ProverPriority::ConsensusCritical => {
                self.inflight_consensus.fetch_add(1, Ordering::Relaxed);
            }
            ProverPriority::Background => {
                self.inflight_background.fetch_add(1, Ordering::Relaxed);
            }
        }
        gauge!(
            "wallet.prover.queue.depth",
            "backend" => backend,
            "class" => priority.as_label()
        )
        .increment(1.0);
    }

    fn record_finish(&self, priority: ProverPriority, backend: &'static str) {
        match priority {
            ProverPriority::ConsensusCritical => {
                self.inflight_consensus
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        value.checked_sub(1)
                    })
                    .ok();
            }
            ProverPriority::Background => {
                self.inflight_background
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        value.checked_sub(1)
                    })
                    .ok();
            }
        }
        gauge!(
            "wallet.prover.queue.depth",
            "backend" => backend,
            "class" => priority.as_label()
        )
        .decrement(1.0);
    }

    fn record_drop(&self, priority: ProverPriority, backend: &'static str) {
        self.record_waiting_delta(priority, backend, -1.0);
        counter!(
            "wallet.prover.queue.dropped",
            "backend" => backend,
            "class" => priority.as_label()
        )
        .increment(1);
    }

    fn record_waiting_delta(&self, priority: ProverPriority, backend: &'static str, delta: f64) {
        match priority {
            ProverPriority::ConsensusCritical => {
                if delta.is_sign_positive() {
                    self.waiting_consensus
                        .fetch_add(delta as u64, Ordering::Relaxed);
                } else {
                    self.waiting_consensus
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                            value.checked_sub(delta.abs() as u64)
                        })
                        .ok();
                }
            }
            ProverPriority::Background => {
                if delta.is_sign_positive() {
                    self.waiting_background
                        .fetch_add(delta as u64, Ordering::Relaxed);
                } else {
                    self.waiting_background
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                            value.checked_sub(delta.abs() as u64)
                        })
                        .ok();
                }
            }
        }
        gauge!(
            "wallet.prover.queue.pending",
            "backend" => backend,
            "class" => priority.as_label()
        )
        .increment(delta);
    }

    fn inflight_background(&self) -> usize {
        self.inflight_background.load(Ordering::Relaxed)
    }
}

pub(crate) struct ProverJobManager {
    max_concurrency: usize,
    priority_slots: usize,
    semaphore: Option<Arc<Semaphore>>,
    timeout: Option<Duration>,
    witness_limit: u64,
    limiter: ResourceLimiter,
    queue: Arc<QueueTelemetry>,
}

impl ProverJobManager {
    pub(crate) fn new(config: &WalletProverConfig) -> Self {
        let probe = Arc::new(SysinfoProbe::default());
        Self::with_probe(config, probe)
    }

    fn with_probe(config: &WalletProverConfig, probe: Arc<dyn ResourceProbe>) -> Self {
        let max_concurrency = usize::try_from(config.max_concurrency).unwrap_or(usize::MAX);
        let priority_slots = usize::try_from(config.priority_slots).unwrap_or(max_concurrency);
        let semaphore = if max_concurrency == 0 {
            None
        } else {
            Some(Arc::new(Semaphore::new(max_concurrency)))
        };
        let timeout = if config.timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(config.timeout_secs))
        };
        let limiter = ResourceLimiter::new(config, probe);
        Self {
            max_concurrency,
            priority_slots,
            semaphore,
            timeout,
            witness_limit: config.max_witness_bytes,
            limiter,
            queue: Arc::new(QueueTelemetry::default()),
        }
    }

    fn ensure_witness_capacity(
        &self,
        backend: &'static str,
        witness_bytes: usize,
        override_cap: Option<u64>,
    ) -> Result<(), ProverError> {
        let limit = override_cap.unwrap_or(self.witness_limit);
        if limit > 0 && (witness_bytes as u64) > limit {
            warn!(
                backend,
                witness_bytes, limit, "wallet prover witness exceeds configured limit"
            );
            return Err(ProverError::WitnessTooLarge {
                size: witness_bytes,
                limit,
            });
        }
        Ok(())
    }

    fn acquire(
        &self,
        backend: &'static str,
        priority: ProverPriority,
    ) -> Result<ProverJobPermit, ProverError> {
        if let Some(delay) = self.limiter.throttle_if_needed(backend)? {
            std::thread::sleep(delay);
        }
        self.queue.record_enqueue(priority, backend);
        if matches!(priority, ProverPriority::Background)
            && self.queue.inflight_background() >= self.available_background_capacity()
        {
            self.queue.record_drop(priority, backend);
            return Err(ProverError::Busy);
        }
        let permit = if let Some(semaphore) = &self.semaphore {
            Some(semaphore.try_acquire_owned().map_err(|_| {
                self.queue.record_drop(priority, backend);
                if matches!(priority, ProverPriority::ConsensusCritical) {
                    counter!(
                        "wallet.prover.queue.backpressure",
                        "backend" => backend,
                        "class" => priority.as_label()
                    )
                    .increment(1);
                    warn!(
                        backend,
                        priority_slots = self.priority_slots,
                        inflight = self.queue.inflight_background(),
                        "consensus-critical prover queue saturated"
                    );
                }
                ProverError::Busy
            })?)
        } else {
            self.queue.record_enqueue(priority, backend);
            None
        };
        let deadline = self.timeout.map(|timeout| Instant::now() + timeout);
        self.queue.record_start(priority, backend);
        Ok(ProverJobPermit {
            _permit: permit,
            deadline,
            timeout: self.timeout,
            token: CancellationToken::new(),
            backend,
            priority,
            queue: Arc::clone(&self.queue),
        })
    }

    fn available_background_capacity(&self) -> usize {
        self.max_concurrency.saturating_sub(self.priority_slots)
    }
}

struct ProverJobPermit {
    _permit: Option<OwnedSemaphorePermit>,
    deadline: Option<Instant>,
    timeout: Option<Duration>,
    token: CancellationToken,
    backend: &'static str,
    priority: ProverPriority,
    queue: Arc<QueueTelemetry>,
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

impl Drop for ProverJobPermit {
    fn drop(&mut self) {
        self.queue.record_finish(self.priority, self.backend);
    }
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
    let permit = jobs.acquire(backend, ProverPriority::ConsensusCritical)?;
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
            backend,
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

fn record_fallback_event(
    primary: &'static str,
    fallback: &'static str,
    stage: &'static str,
    reason: &'static str,
) {
    counter!(
        "wallet.prover.fallback",
        "primary" => primary,
        "fallback" => fallback,
        "stage" => stage,
        "reason" => reason
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
    use metrics::{
        Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, Metadata, Recorder,
        SharedString, Unit,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::runtime::Builder;

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

    #[derive(Clone, Copy)]
    enum StubMode {
        Ok,
        Busy,
        Timeout,
        WitnessTooLarge,
    }

    struct StubProver {
        backend: &'static str,
        prepare_mode: StubMode,
        prove_mode: StubMode,
    }

    impl StubProver {
        fn new(backend: &'static str, prepare_mode: StubMode, prove_mode: StubMode) -> Self {
            Self {
                backend,
                prepare_mode,
                prove_mode,
            }
        }

        fn map_mode<T>(&self, mode: StubMode, ok: impl FnOnce() -> T) -> Result<T, ProverError> {
            match mode {
                StubMode::Ok => Ok(ok()),
                StubMode::Busy => Err(ProverError::Busy),
                StubMode::Timeout => Err(ProverError::Timeout(1)),
                StubMode::WitnessTooLarge => Err(ProverError::WitnessTooLarge {
                    size: 1024,
                    limit: 512,
                }),
            }
        }
    }

    impl WalletProver for StubProver {
        fn identity(&self) -> ProverIdentity {
            ProverIdentity::new(self.backend, false)
        }

        fn prepare_witness(
            &self,
            _ctx: &DraftProverContext<'_>,
        ) -> Result<WitnessPlan, ProverError> {
            self.map_mode(self.prepare_mode, || {
                WitnessPlan::with_parts(WitnessBytes(vec![1, 2, 3]), Instant::now())
                    .with_backend(self.backend)
            })
        }

        fn prove(
            &self,
            _ctx: &DraftProverContext<'_>,
            plan: WitnessPlan,
        ) -> Result<ProveResult, ProverError> {
            self.map_mode(self.prove_mode, || {
                ProveResult::new(
                    self.backend,
                    Some(ProofBytes(vec![4, 5, 6])),
                    plan.witness_bytes(),
                    Instant::now(),
                    Instant::now(),
                )
            })
        }

        fn attest_metadata(
            &self,
            _ctx: &DraftProverContext<'_>,
            result: &ProveResult,
        ) -> Result<ProverMeta, ProverError> {
            Ok(attest_default(self.backend, result))
        }
    }

    #[test]
    fn job_permit_aborts_when_timeout_is_exceeded() {
        let runtime = Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let _guard = runtime.enter();

        let mut config = WalletProverConfig::default();
        config.timeout_secs = 1;
        config.max_concurrency = 1;
        let manager = ProverJobManager::new(&config);
        let permit = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect("permit");

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

    #[test]
    fn job_permit_cancels_blocking_work() {
        let runtime = Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let _guard = runtime.enter();

        let mut config = WalletProverConfig::default();
        config.timeout_secs = 0;
        config.max_concurrency = 1;
        let manager = ProverJobManager::new(&config);
        let permit = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect("permit");
        let cancel_token = permit.cancellation_token();
        let worker_token = cancel_token.clone();

        let result = runtime.block_on(async move {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(25)).await;
                cancel_token.cancel();
            });

            permit
                .wait(async move {
                    task::spawn_blocking(move || loop {
                        if worker_token.is_cancelled() {
                            return Err(ProverError::Cancelled);
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    })
                    .await
                    .map_err(map_blocking_error)
                })
                .await
        });

        assert!(matches!(result, Err(ProverError::Cancelled)));
    }

    #[test]
    fn resource_limiter_warns_and_recovers() {
        let mut config = WalletProverConfig::default();
        config.cpu_quota_percent = 90;
        config.limit_warn_percent = 80;
        config.limit_retries = 2;
        config.limit_backoff_ms = 0;
        let probe = Arc::new(MockProbe::new(vec![
            usage_sample(85.0, 50, Some(100)),
            usage_sample(30.0, 20, Some(100)),
        ]));
        let manager = ProverJobManager::with_probe(&config, probe);

        let permit = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect("permit");
        drop(permit);
    }

    #[test]
    fn resource_limiter_returns_busy_after_retries() {
        let mut config = WalletProverConfig::default();
        config.cpu_quota_percent = 50;
        config.memory_quota_bytes = 32;
        config.limit_retries = 1;
        config.limit_backoff_ms = 0;
        let probe = Arc::new(MockProbe::new(vec![
            usage_sample(75.0, 64, Some(32)),
            usage_sample(70.0, 64, Some(32)),
        ]));
        let manager = ProverJobManager::with_probe(&config, probe);

        let result = manager.acquire("mock", ProverPriority::ConsensusCritical);
        assert!(matches!(result, Err(ProverError::Busy)));
    }

    fn usage_sample(
        cpu_percent: f32,
        memory_bytes: u64,
        memory_limit_bytes: Option<u64>,
    ) -> ResourceUsage {
        ResourceUsage {
            cpu_percent,
            memory_bytes,
            memory_limit_bytes,
        }
    }

    struct MockProbe {
        samples: Mutex<Vec<ResourceUsage>>,
    }

    impl MockProbe {
        fn new(samples: Vec<ResourceUsage>) -> Self {
            Self {
                samples: Mutex::new(samples),
            }
        }
    }

    impl ResourceProbe for MockProbe {
        fn sample(&self) -> ResourceUsage {
            let mut guard = self.samples.lock().expect("samples poisoned");
            if guard.len() > 1 {
                guard.remove(0)
            } else {
                guard.first().cloned().unwrap_or_default()
            }
        }
    }

    #[test]
    fn job_manager_rejects_when_backend_busy() {
        let mut config = WalletProverConfig::default();
        config.max_concurrency = 1;
        let manager = ProverJobManager::new(&config);
        let _permit = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect("first permit");
        let err = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect_err("second permit should fail");
        assert!(matches!(err, ProverError::Busy));
    }

    #[test]
    fn background_jobs_respect_reserved_capacity() {
        let metrics = TestRecorder::install();
        TestRecorder::reset(&metrics);

        let mut config = WalletProverConfig::default();
        config.max_concurrency = 2;
        config.priority_slots = 1;
        let manager = ProverJobManager::new(&config);

        let background = manager
            .acquire("mock", ProverPriority::Background)
            .expect("background slot available");
        let critical = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect("priority slot available");
        let err = manager
            .acquire("mock", ProverPriority::Background)
            .expect_err("background should respect reserved capacity");
        assert!(matches!(err, ProverError::Busy));

        assert_eq!(
            TestRecorder::counter_value(
                &metrics,
                "wallet.prover.queue.dropped{backend=mock,class=background}",
            ),
            Some(1),
        );

        drop(critical);
        drop(background);
    }

    #[test]
    fn consensus_backpressure_metric_tracks_drops() {
        let metrics = TestRecorder::install();
        TestRecorder::reset(&metrics);

        let mut config = WalletProverConfig::default();
        config.max_concurrency = 1;
        config.priority_slots = 1;
        let manager = ProverJobManager::new(&config);

        let _permit = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect("first permit");
        let err = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect_err("second permit should fail");
        assert!(matches!(err, ProverError::Busy));

        assert_eq!(
            TestRecorder::counter_value(
                &metrics,
                "wallet.prover.queue.backpressure{backend=mock,class=consensus}",
            ),
            Some(1),
        );
    }

    #[test]
    fn fallback_router_switches_on_prepare_overload_and_records_metrics() {
        let metrics = TestRecorder::install();
        TestRecorder::reset(&metrics);

        let primary = Arc::new(StubProver::new("primary", StubMode::Busy, StubMode::Ok));
        let fallback = Arc::new(StubProver::new("secondary", StubMode::Ok, StubMode::Ok));
        let router = FallbackWalletProver::new(primary, fallback);
        let draft = sample_draft();
        let ctx = DraftProverContext::new(&draft);

        let plan = router.prepare_witness(&ctx).expect("fallback plan");
        assert_eq!(plan.backend(), "secondary");

        let result = router.prove(&ctx, plan).expect("fallback proof");
        assert_eq!(result.backend(), "secondary");
        let meta = router
            .attest_metadata(&ctx, &result)
            .expect("fallback metadata");
        assert_eq!(meta.backend, "secondary");

        assert_eq!(
            TestRecorder::counter_value(
                &metrics,
                "wallet.prover.fallback{fallback=secondary,primary=primary,reason=busy,stage=prepare}",
            ),
            Some(1),
        );
    }

    #[test]
    fn fallback_router_switches_on_prove_overload() {
        let metrics = TestRecorder::install();
        TestRecorder::reset(&metrics);

        let primary = Arc::new(StubProver::new("primary", StubMode::Ok, StubMode::Busy));
        let fallback = Arc::new(StubProver::new("secondary", StubMode::Ok, StubMode::Ok));
        let router = FallbackWalletProver::new(primary, fallback);
        let draft = sample_draft();
        let ctx = DraftProverContext::new(&draft);

        let plan = router.prepare_witness(&ctx).expect("primary plan");
        assert_eq!(plan.backend(), "primary");

        let result = router.prove(&ctx, plan).expect("fallback proof");
        assert_eq!(result.backend(), "secondary");
        assert_eq!(
            TestRecorder::counter_value(
                &metrics,
                "wallet.prover.fallback{fallback=secondary,primary=primary,reason=busy,stage=prove}",
            ),
            Some(1),
        );
    }

    #[test]
    fn fallback_router_preserves_size_gates() {
        let metrics = TestRecorder::install();
        TestRecorder::reset(&metrics);

        let primary = Arc::new(StubProver::new(
            "primary",
            StubMode::WitnessTooLarge,
            StubMode::Ok,
        ));
        let fallback = Arc::new(StubProver::new("secondary", StubMode::Ok, StubMode::Ok));
        let router = FallbackWalletProver::new(primary, fallback);
        let draft = sample_draft();
        let ctx = DraftProverContext::new(&draft);

        let err = router
            .prepare_witness(&ctx)
            .expect_err("size gate should fail before fallback");
        assert!(matches!(err, ProverError::WitnessTooLarge { .. }));
        assert_eq!(
            TestRecorder::counter_value(
                &metrics,
                "wallet.prover.fallback{fallback=secondary,primary=primary,reason=busy,stage=prepare}",
            ),
            None,
        );
    }

    #[test]
    fn job_queue_depth_tracks_backlog_per_backend() {
        let metrics = TestRecorder::install();
        TestRecorder::reset(&metrics);

        let mut config = WalletProverConfig::default();
        config.max_concurrency = 1;
        let manager = ProverJobManager::new(&config);

        let permit = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect("first permit");
        assert_eq!(
            TestRecorder::gauge_value(
                &metrics,
                "wallet.prover.queue.depth{backend=mock,class=consensus}",
            ),
            Some(1.0)
        );

        let err = manager
            .acquire("mock", ProverPriority::ConsensusCritical)
            .expect_err("second permit should be rejected while backlog active");
        assert!(matches!(err, ProverError::Busy));

        drop(permit);
        assert_eq!(
            TestRecorder::gauge_value(
                &metrics,
                "wallet.prover.queue.depth{backend=mock,class=consensus}",
            ),
            Some(0.0)
        );
    }

    #[cfg(feature = "prover-mock")]
    #[test]
    fn mock_prover_rejects_witnesses_over_configured_cap_and_records_telemetry() {
        let metrics = TestRecorder::install();
        TestRecorder::reset(&metrics);

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

        assert_eq!(
            TestRecorder::counter_value(
                &metrics,
                "wallet.prover.jobs{backend=mock,error=witness_too_large,result=err,stage=prepare}"
            ),
            Some(1)
        );
    }

    #[cfg(feature = "prover-mock")]
    #[test]
    fn mock_prover_emits_metadata_and_telemetry() {
        let metrics = TestRecorder::install();
        TestRecorder::reset(&metrics);

        let config = WalletProverConfig::default();
        let prover = MockWalletProver::new(&config);
        let draft = sample_draft();
        let ctx = DraftProverContext::new(&draft);

        let plan = prover.prepare_witness(&ctx).expect("prepare witness");
        assert!(plan.witness_bytes() > 0);
        assert_eq!(
            TestRecorder::counter_value(
                &metrics,
                "wallet.prover.jobs{backend=mock,result=ok,stage=prepare}"
            ),
            Some(1)
        );
        assert_eq!(
            TestRecorder::histogram_values(&metrics, "wallet.prover.witness_bytes{backend=mock}"),
            vec![plan.witness_bytes() as f64]
        );

        let prove_result = prover.prove(&ctx, plan).expect("prove");
        let proof_bytes = prove_result
            .proof()
            .map(|proof| proof.as_ref().len())
            .unwrap();
        assert!(proof_bytes > 0);
        assert!(TestRecorder::counter_value(
            &metrics,
            "wallet.prover.jobs{backend=mock,result=ok,stage=prove}"
        )
        .is_some());
        assert!(!TestRecorder::histogram_values(
            &metrics,
            "wallet.prover.duration_ms{backend=mock}"
        )
        .is_empty());
        assert_eq!(
            TestRecorder::histogram_values(&metrics, "wallet.prover.proof_bytes{backend=mock}"),
            vec![proof_bytes as f64]
        );

        let meta = prover
            .attest_metadata(&ctx, &prove_result)
            .expect("attest metadata");
        assert_eq!(meta.backend, "mock");
        assert_eq!(meta.witness_bytes, prove_result.witness_bytes());
        assert_eq!(meta.proof_bytes, Some(proof_bytes));
        assert!(meta.proof_hash.is_some());
        assert!(meta.duration_ms > 0);
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

    #[cfg(feature = "prover-stwo")]
    #[test]
    fn stwo_adapter_builds_witness_from_draft() {
        use prover_stwo_backend::backend::io::decode_tx_witness;

        let mut config = WalletProverConfig::default();
        config.backend = WalletProverBackend::Stwo;
        let prover = StwoWalletProver::new(&config).expect("stwo prover");
        let draft = sample_draft();

        let ctx = DraftProverContext::new(&draft);
        let mut plan = prover.prepare_witness(&ctx).expect("witness plan");
        let witness = plan.take_witness().expect("encoded witness");
        let (_header, witness) = decode_tx_witness(&witness).expect("decode witness");

        assert_eq!(witness.signed_tx.payload.amount, 10_000);
        assert_eq!(witness.signed_tx.payload.to, "receiver");
        assert!(witness.sender_account.balance >= draft.total_output_value());
    }
}

#[derive(Default, Clone)]
struct TestRecorderInner {
    counters: Mutex<HashMap<String, u64>>,
    histograms: Mutex<HashMap<String, Vec<f64>>>,
    gauges: Mutex<HashMap<String, f64>>,
}

#[derive(Clone)]
struct TestRecorder {
    inner: Arc<TestRecorderInner>,
}

impl TestRecorder {
    fn install() -> Arc<TestRecorderInner> {
        static RECORDER: OnceLock<Arc<TestRecorderInner>> = OnceLock::new();
        RECORDER
            .get_or_init(|| {
                let inner = Arc::new(TestRecorderInner::default());
                let recorder = TestRecorder {
                    inner: Arc::clone(&inner),
                };
                metrics::set_boxed_recorder(Box::new(recorder)).expect("set recorder");
                inner
            })
            .clone()
    }

    fn reset(inner: &Arc<TestRecorderInner>) {
        inner.counters.lock().unwrap().clear();
        inner.histograms.lock().unwrap().clear();
        inner.gauges.lock().unwrap().clear();
    }

    fn counter_value(inner: &Arc<TestRecorderInner>, key: &str) -> Option<u64> {
        inner.counters.lock().unwrap().get(key).copied()
    }

    fn histogram_values(inner: &Arc<TestRecorderInner>, key: &str) -> Vec<f64> {
        inner
            .histograms
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    fn gauge_value(inner: &Arc<TestRecorderInner>, key: &str) -> Option<f64> {
        inner.gauges.lock().unwrap().get(key).copied()
    }
}

impl Recorder for TestRecorder {
    fn describe_counter(&self, _: Key, _: Option<Unit>, _: SharedString) {}

    fn describe_gauge(&self, _: Key, _: Option<Unit>, _: SharedString) {}

    fn describe_histogram(&self, _: Key, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        let formatted = format_key(key);
        Counter::from_arc(Arc::new(TestCounterHandle {
            key: formatted,
            inner: Arc::clone(&self.inner),
        }))
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        let formatted = format_key(key);
        Gauge::from_arc(Arc::new(TestGaugeHandle {
            key: formatted,
            inner: Arc::clone(&self.inner),
        }))
    }

    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        let formatted = format_key(key);
        Histogram::from_arc(Arc::new(TestHistogramHandle {
            key: formatted,
            inner: Arc::clone(&self.inner),
        }))
    }
}

struct TestCounterHandle {
    key: String,
    inner: Arc<TestRecorderInner>,
}

impl CounterFn for TestCounterHandle {
    fn increment(&self, value: u64) {
        let mut counters = self.inner.counters.lock().unwrap();
        let entry = counters.entry(self.key.clone()).or_default();
        *entry = entry.saturating_add(value);
    }

    fn absolute(&self, value: u64) {
        let mut counters = self.inner.counters.lock().unwrap();
        let entry = counters.entry(self.key.clone()).or_default();
        *entry = (*entry).max(value);
    }
}

struct TestGaugeHandle {
    key: String,
    inner: Arc<TestRecorderInner>,
}

impl GaugeFn for TestGaugeHandle {
    fn increment(&self, value: f64) {
        let mut gauges = self.inner.gauges.lock().unwrap();
        let entry = gauges.entry(self.key.clone()).or_default();
        *entry += value;
    }

    fn decrement(&self, value: f64) {
        let mut gauges = self.inner.gauges.lock().unwrap();
        let entry = gauges.entry(self.key.clone()).or_default();
        *entry -= value;
    }

    fn set(&self, value: f64) {
        let mut gauges = self.inner.gauges.lock().unwrap();
        gauges.insert(self.key.clone(), value);
    }
}

struct TestHistogramHandle {
    key: String,
    inner: Arc<TestRecorderInner>,
}

impl HistogramFn for TestHistogramHandle {
    fn record(&self, value: f64) {
        let mut histograms = self.inner.histograms.lock().unwrap();
        histograms.entry(self.key.clone()).or_default().push(value);
    }
}

fn format_key(key: &Key) -> String {
    let mut labels: Vec<_> = key
        .labels()
        .map(|label| (label.key().to_owned(), label.value().to_owned()))
        .collect();
    labels.sort_by(|a, b| a.0.cmp(&b.0));
    if labels.is_empty() {
        key.name().to_owned()
    } else {
        let joined = labels
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        format!("{}{{{joined}}}", key.name())
    }
}
