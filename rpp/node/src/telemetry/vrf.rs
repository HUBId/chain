use rpp_chain::config::VrfTelemetryThresholds;
use rpp_crypto_vrf::{telemetry::VrfTelemetry, VrfSelectionMetrics};
use tracing::{info, warn};

pub use rpp_crypto_vrf::telemetry::*;

fn rejection_rate(metrics: &VrfSelectionMetrics) -> f64 {
    if metrics.verified_submissions == 0 {
        0.0
    } else {
        (metrics.rejected_candidates as f64) / (metrics.verified_submissions as f64)
    }
}

pub fn log_selection(metrics: &VrfSelectionMetrics, thresholds: &VrfTelemetryThresholds) {
    let rejection_rate = rejection_rate(metrics);
    let fallback_ratio = if metrics.fallback_selected { 1.0 } else { 0.0 };
    info!(
        target = "telemetry.vrf",
        epoch = metrics.latest_epoch.unwrap_or_default(),
        round = metrics.latest_round.unwrap_or_default(),
        pool_entries = metrics.pool_entries,
        accepted = metrics.accepted_validators,
        rejected = metrics.rejected_candidates,
        participation_rate = metrics.participation_rate,
        success_rate = metrics.success_rate,
        rejection_rate,
        fallback_selected = metrics.fallback_selected,
        threshold_value = metrics
            .active_epoch_threshold
            .as_deref()
            .unwrap_or(""),
        threshold_ratio = metrics.active_threshold_ratio.unwrap_or(0.0),
        ?metrics.rejections_by_reason,
        "vrf selection metrics"
    );

    if metrics.participation_rate < thresholds.min_participation_rate {
        warn!(
            target = "telemetry.vrf",
            participation_rate = metrics.participation_rate,
            min_allowed = thresholds.min_participation_rate,
            "vrf participation dropped below threshold"
        );
    }

    if rejection_rate > thresholds.max_rejection_rate {
        warn!(
            target = "telemetry.vrf",
            rejection_rate,
            max_allowed = thresholds.max_rejection_rate,
            ?metrics.rejections_by_reason,
            "vrf rejection rate exceeded limit"
        );
    }

    if fallback_ratio > thresholds.max_fallback_ratio {
        warn!(
            target = "telemetry.vrf",
            fallback_ratio,
            max_allowed = thresholds.max_fallback_ratio,
            "vrf fallback ratio exceeded limit"
        );
    }
}

pub fn metrics() -> VrfTelemetry {
    VrfTelemetry::global()
}
