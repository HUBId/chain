from dataclasses import dataclass

from tools.alerts.settings import UptimeServiceLevel


@dataclass(frozen=True)
class UptimeBaselines:
    participation_ratio: float
    participation_warning_buffer: float
    participation_critical_buffer: float
    observation_gap_seconds: float
    observation_warning_buffer: float
    observation_critical_buffer: float
    epoch_age_seconds: float
    epoch_warning_buffer: float
    epoch_critical_buffer: float
    timetoke_rate_per_second: float
    timetoke_rate_buffer: float


@dataclass(frozen=True)
class UptimeBaselineThresholds:
    participation_warning: float
    participation_critical: float
    observation_warning_seconds: float
    observation_critical_seconds: float
    epoch_warning_seconds: float
    epoch_critical_seconds: float
    timetoke_rate_per_second: float


UPTIME_BASELINES = UptimeBaselines(
    participation_ratio=0.993,
    participation_warning_buffer=0.023,
    participation_critical_buffer=0.053,
    observation_gap_seconds=300.0,
    observation_warning_buffer=600.0,
    observation_critical_buffer=1500.0,
    epoch_age_seconds=1800.0,
    epoch_warning_buffer=1800.0,
    epoch_critical_buffer=3600.0,
    timetoke_rate_per_second=0.00055,
    timetoke_rate_buffer=0.0003,
)


def compute_uptime_thresholds(sla: UptimeServiceLevel) -> UptimeBaselineThresholds:
    participation_warning = max(
        sla.participation_warning_ratio,
        UPTIME_BASELINES.participation_ratio - UPTIME_BASELINES.participation_warning_buffer,
    )
    participation_critical = max(
        sla.participation_critical_ratio,
        UPTIME_BASELINES.participation_ratio - UPTIME_BASELINES.participation_critical_buffer,
    )
    observation_warning = max(
        sla.uptime_gap_warning_seconds,
        UPTIME_BASELINES.observation_gap_seconds + UPTIME_BASELINES.observation_warning_buffer,
    )
    observation_critical = max(
        sla.uptime_gap_critical_seconds,
        UPTIME_BASELINES.observation_gap_seconds + UPTIME_BASELINES.observation_critical_buffer,
    )
    epoch_warning = max(
        sla.uptime_gap_warning_seconds,
        UPTIME_BASELINES.epoch_age_seconds + UPTIME_BASELINES.epoch_warning_buffer,
    )
    epoch_critical = max(
        sla.uptime_gap_critical_seconds,
        UPTIME_BASELINES.epoch_age_seconds + UPTIME_BASELINES.epoch_critical_buffer,
    )
    timetoke_rate = max(
        sla.timetoke_minimum_rate,
        UPTIME_BASELINES.timetoke_rate_per_second - UPTIME_BASELINES.timetoke_rate_buffer,
    )
    return UptimeBaselineThresholds(
        participation_warning=participation_warning,
        participation_critical=participation_critical,
        observation_warning_seconds=observation_warning,
        observation_critical_seconds=observation_critical,
        epoch_warning_seconds=epoch_warning,
        epoch_critical_seconds=epoch_critical,
        timetoke_rate_per_second=timetoke_rate,
    )
