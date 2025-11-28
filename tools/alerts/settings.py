from dataclasses import dataclass


@dataclass(frozen=True)
class FinalityServiceLevel:
    lag_warning_slots: float
    lag_critical_slots: float
    gap_warning_blocks: float
    gap_critical_blocks: float
    stall_duration_seconds: float


FINALITY_SLA = FinalityServiceLevel(
    lag_warning_slots=12.0,
    lag_critical_slots=24.0,
    gap_warning_blocks=4.0,
    gap_critical_blocks=8.0,
    stall_duration_seconds=600.0,
)


@dataclass(frozen=True)
class UptimeServiceLevel:
    participation_warning_ratio: float
    participation_critical_ratio: float
    uptime_gap_warning_seconds: float
    uptime_gap_critical_seconds: float
    timetoke_minimum_rate: float
    timetoke_window_seconds: float


UPTIME_SLA = UptimeServiceLevel(
    participation_warning_ratio=0.97,
    participation_critical_ratio=0.94,
    uptime_gap_warning_seconds=900.0,
    uptime_gap_critical_seconds=1800.0,
    timetoke_minimum_rate=0.00025,
    timetoke_window_seconds=900.0,
)


@dataclass(frozen=True)
class BlockProductionServiceLevel:
    warning_ratio: float
    critical_ratio: float
    window_seconds: float
    duration_seconds: float


BLOCK_PRODUCTION_SLA = BlockProductionServiceLevel(
    warning_ratio=0.9,
    critical_ratio=0.75,
    window_seconds=300.0,
    duration_seconds=600.0,
)


@dataclass(frozen=True)
class PipelineLatencyServiceLevel:
    inclusion_warning_seconds: float
    inclusion_critical_seconds: float
    finality_warning_seconds: float
    finality_critical_seconds: float
    evaluation_duration_seconds: float


PIPELINE_LATENCY_SLA = PipelineLatencyServiceLevel(
    inclusion_warning_seconds=60.0,
    inclusion_critical_seconds=120.0,
    finality_warning_seconds=180.0,
    finality_critical_seconds=300.0,
    evaluation_duration_seconds=600.0,
)
