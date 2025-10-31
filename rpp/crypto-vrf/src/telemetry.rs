use std::convert::TryFrom;
use std::sync::{Mutex, OnceLock};

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider};
use opentelemetry::KeyValue;

use crate::VrfSelectionMetrics;

const METER_NAME: &str = "rpp-crypto-vrf";

#[derive(Clone)]
pub struct VrfTelemetry {
    pool_entries: Histogram<u64>,
    target_validator_count: Histogram<u64>,
    unique_addresses: Histogram<u64>,
    participation_rate: Histogram<f64>,
    success_rate: Histogram<f64>,
    threshold_ratio: Histogram<f64>,
    verified_total: Counter<u64>,
    accepted_total: Counter<u64>,
    rejected_total: Counter<u64>,
    fallback_total: Counter<u64>,
    latest_epoch: Histogram<u64>,
    latest_round: Histogram<u64>,
    threshold_transitions: Counter<u64>,
    rejection_reasons: Counter<u64>,
}

struct TelemetryState {
    provider: *const dyn MeterProvider,
    metrics: VrfTelemetry,
}

impl TelemetryState {
    fn new(provider: *const dyn MeterProvider) -> Self {
        let meter = global::meter(METER_NAME);
        Self {
            provider,
            metrics: VrfTelemetry::from_meter(meter),
        }
    }
}

static TELEMETRY: OnceLock<Mutex<TelemetryState>> = OnceLock::new();

impl VrfTelemetry {
    fn from_meter(meter: Meter) -> Self {
        let pool_entries = meter
            .u64_histogram("rpp.crypto_vrf.selection.pool_entries")
            .with_description("Number of VRF submissions evaluated in a selection round")
            .with_unit("1")
            .build();
        let target_validator_count = meter
            .u64_histogram("rpp.crypto_vrf.selection.target_validator_count")
            .with_description("Target validator count configured for the active epoch")
            .with_unit("1")
            .build();
        let unique_addresses = meter
            .u64_histogram("rpp.crypto_vrf.selection.unique_addresses")
            .with_description("Unique validator addresses contained in the submission pool")
            .with_unit("1")
            .build();
        let participation_rate = meter
            .f64_histogram("rpp.crypto_vrf.selection.participation_rate")
            .with_description("Participation rate of verified validators in the selection round")
            .with_unit("1")
            .build();
        let success_rate = meter
            .f64_histogram("rpp.crypto_vrf.selection.success_rate")
            .with_description(
                "Share of configured committee slots filled during the selection round",
            )
            .with_unit("1")
            .build();
        let threshold_ratio = meter
            .f64_histogram("rpp.crypto_vrf.selection.threshold_ratio")
            .with_description("Normalised ratio between the active VRF acceptance threshold and the randomness domain")
            .with_unit("1")
            .build();
        let verified_total = meter
            .u64_counter("rpp.crypto_vrf.selection.verified_total")
            .with_description("Total verified VRF submissions per selection round")
            .with_unit("1")
            .build();
        let accepted_total = meter
            .u64_counter("rpp.crypto_vrf.selection.accepted_total")
            .with_description("Total accepted validators selected by the VRF threshold")
            .with_unit("1")
            .build();
        let rejected_total = meter
            .u64_counter("rpp.crypto_vrf.selection.rejected_total")
            .with_description("Total rejected VRF submissions per selection round")
            .with_unit("1")
            .build();
        let fallback_total = meter
            .u64_counter("rpp.crypto_vrf.selection.fallback_total")
            .with_description("Count of selection rounds that required a fallback candidate")
            .with_unit("1")
            .build();
        let latest_epoch = meter
            .u64_histogram("rpp.crypto_vrf.selection.latest_epoch")
            .with_description("Epoch identifier of the latest processed VRF submissions")
            .with_unit("1")
            .build();
        let latest_round = meter
            .u64_histogram("rpp.crypto_vrf.selection.latest_round")
            .with_description("Consensus round number reported with the selection metrics")
            .with_unit("1")
            .build();
        let threshold_transitions = meter
            .u64_counter("rpp.crypto_vrf.selection.threshold_transitions")
            .with_description("Number of epochs that published a VRF acceptance threshold")
            .with_unit("1")
            .build();
        let rejection_reasons = meter
            .u64_counter("rpp.crypto_vrf.selection.rejection_reason_total")
            .with_description("Total rejected submissions grouped by reason")
            .with_unit("1")
            .build();

        Self {
            pool_entries,
            target_validator_count,
            unique_addresses,
            participation_rate,
            success_rate,
            threshold_ratio,
            verified_total,
            accepted_total,
            rejected_total,
            fallback_total,
            latest_epoch,
            latest_round,
            threshold_transitions,
            rejection_reasons,
        }
    }

    fn state() -> &'static Mutex<TelemetryState> {
        TELEMETRY.get_or_init(|| {
            let provider = global::meter_provider() as *const dyn MeterProvider;
            Mutex::new(TelemetryState::new(provider))
        })
    }

    pub fn global() -> Self {
        let provider = global::meter_provider() as *const dyn MeterProvider;
        let state = Self::state();
        let mut guard = state.lock().expect("VRF telemetry state poisoned");
        if guard.provider != provider {
            *guard = TelemetryState::new(provider);
        }
        guard.metrics.clone()
    }

    pub fn record_selection(&self, metrics: &VrfSelectionMetrics) {
        self.pool_entries.record(to_u64(metrics.pool_entries), &[]);
        self.target_validator_count
            .record(to_u64(metrics.target_validator_count), &[]);
        self.unique_addresses
            .record(to_u64(metrics.unique_addresses), &[]);
        if metrics.participation_rate.is_finite() {
            let rate = metrics.participation_rate.clamp(0.0, 1.0);
            self.participation_rate.record(rate, &[]);
        }
        if metrics.success_rate.is_finite() {
            let rate = metrics.success_rate.clamp(0.0, 1.0);
            self.success_rate.record(rate, &[]);
        }
        if let Some(ratio) = metrics.active_threshold_ratio {
            if ratio.is_finite() {
                self.threshold_ratio.record(ratio.clamp(0.0, 1.0), &[]);
            }
        }
        self.verified_total
            .add(to_u64(metrics.verified_submissions), &[]);
        self.accepted_total
            .add(to_u64(metrics.accepted_validators), &[]);
        self.rejected_total
            .add(to_u64(metrics.rejected_candidates), &[]);
        for (reason, count) in &metrics.rejections_by_reason {
            self.rejection_reasons
                .add(to_u64(*count), &[KeyValue::new("reason", reason.clone())]);
        }
        if metrics.fallback_selected {
            self.fallback_total.add(1, &[]);
        }
        if let Some(epoch) = metrics.latest_epoch {
            self.latest_epoch.record(epoch, &[]);
        }
        if let Some(round) = metrics.latest_round {
            self.latest_round.record(round, &[]);
        }
        if let Some(threshold) = metrics.active_epoch_threshold.as_ref() {
            if !threshold.trim().is_empty() {
                self.threshold_transitions
                    .add(1, &[KeyValue::new("threshold", threshold.clone())]);
            }
        }
    }
}

fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
