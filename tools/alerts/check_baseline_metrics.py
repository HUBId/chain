"""Compare uptime/timetoke metrics against the recorded baselines.

The script reads a Prometheus exposition log and checks the most recent samples
for the uptime/timetoke metrics we guard with alert buffers. It exits non-zero
when metrics fall outside the derived thresholds so CI and nightly jobs can
flag regressions early.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from prometheus_client.parser import text_string_to_metric_families

try:  # pragma: no cover - direct execution fallback
    from tools.alerts.baselines import UPTIME_BASELINES, compute_uptime_thresholds
    from tools.alerts.settings import UPTIME_SLA
except ModuleNotFoundError:  # pragma: no cover - allow execution via python path/to/script.py
    REPO_ROOT = Path(__file__).resolve().parents[2]
    sys.path.append(str(REPO_ROOT))
    from tools.alerts.baselines import UPTIME_BASELINES, compute_uptime_thresholds  # type: ignore
    from tools.alerts.settings import UPTIME_SLA  # type: ignore


MetricSample = Tuple[float, float]


@dataclass
class Evaluation:
    metric: str
    value: float
    threshold: float
    comparison: str
    ok: bool

    def render(self) -> str:
        status = "PASS" if self.ok else "FAIL"
        return f"[{status}] {self.metric}: {self.value:.6f} {self.comparison} {self.threshold:.6f}"


def _collect_samples(metrics_text: str, environment: str) -> Dict[str, List[MetricSample]]:
    series: Dict[str, List[MetricSample]] = {}
    for family in text_string_to_metric_families(metrics_text):
        for sample in family.samples:
            name = sample.name
            labels = getattr(sample, "labels", sample[1])
            if labels.get("environment") != environment:
                continue
            value = float(getattr(sample, "value", sample[2]))
            timestamp = getattr(sample, "timestamp", None)
            if timestamp is None:
                raise ValueError(f"sample for {name} missing timestamp; required for baseline checks")
            series.setdefault(name, []).append((float(timestamp), value))
    return series


def _latest(series: Iterable[MetricSample]) -> MetricSample:
    timestamped = sorted(series, key=lambda item: item[0])
    return timestamped[-1]


def _rate(series: Iterable[MetricSample]) -> float:
    timestamped = sorted(series, key=lambda item: item[0])
    if len(timestamped) < 2:
        raise ValueError("need at least two samples to compute a rate")
    start_ts, start_val = timestamped[-2]
    end_ts, end_val = timestamped[-1]
    delta = end_val - start_val
    elapsed = end_ts - start_ts
    if elapsed <= 0:
        raise ValueError("non-positive time delta in samples")
    return delta / elapsed


def evaluate_metrics(metrics: Dict[str, List[MetricSample]]) -> List[Evaluation]:
    thresholds = compute_uptime_thresholds(UPTIME_SLA)
    participation = _latest(metrics["uptime_participation_ratio"])  # type: ignore[index]
    observation_age = _latest(metrics["uptime_observation_age_seconds"])  # type: ignore[index]
    epoch_age = _latest(metrics["timetoke_epoch_age_seconds"])  # type: ignore[index]
    accrual_rate = _rate(metrics["timetoke_accrual_hours_total"])  # type: ignore[index]

    return [
        Evaluation(
            metric="uptime_participation_ratio",
            value=participation[1],
            threshold=thresholds.participation_warning,
            comparison=">=",
            ok=participation[1] >= thresholds.participation_warning,
        ),
        Evaluation(
            metric="uptime_observation_age_seconds",
            value=observation_age[1],
            threshold=thresholds.observation_warning_seconds,
            comparison="<=",
            ok=observation_age[1] <= thresholds.observation_warning_seconds,
        ),
        Evaluation(
            metric="timetoke_epoch_age_seconds",
            value=epoch_age[1],
            threshold=thresholds.epoch_warning_seconds,
            comparison="<=",
            ok=epoch_age[1] <= thresholds.epoch_warning_seconds,
        ),
        Evaluation(
            metric="timetoke_accrual_hours_total (per second)",
            value=accrual_rate,
            threshold=thresholds.timetoke_rate_per_second,
            comparison=">=",
            ok=accrual_rate >= thresholds.timetoke_rate_per_second,
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metrics-log",
        default="tools/alerts/fixtures/uptime_timetoke.prom",
        help="Path to a Prometheus text-format metrics dump",
    )
    parser.add_argument(
        "--environment",
        default="staging",
        help="Environment label to evaluate (default: staging)",
    )
    args = parser.parse_args()

    with open(args.metrics_log, "r", encoding="utf-8") as handle:
        metrics_text = handle.read()

    samples = _collect_samples(metrics_text, args.environment)
    required = {
        "uptime_participation_ratio",
        "uptime_observation_age_seconds",
        "timetoke_epoch_age_seconds",
        "timetoke_accrual_hours_total",
    }
    missing = required - set(samples)
    if missing:
        joined = ", ".join(sorted(missing))
        print(f"::error ::Missing metrics for environment '{args.environment}': {joined}", file=sys.stderr)
        return 1

    evaluations = evaluate_metrics(samples)
    failures = [evaluation for evaluation in evaluations if not evaluation.ok]
    for evaluation in evaluations:
        print(evaluation.render())

    if failures:
        failed_metrics = ", ".join(failure.metric for failure in failures)
        print(f"::error ::Baseline checks failed for: {failed_metrics}", file=sys.stderr)
        return 1

    print(
        "All uptime/timetoke metrics are within the buffered baselines "
        f"(participation baseline {UPTIME_BASELINES.participation_ratio}, "
        f"observation gap {UPTIME_BASELINES.observation_gap_seconds}s, "
        f"epoch age {UPTIME_BASELINES.epoch_age_seconds}s, accrual rate "
        f"{UPTIME_BASELINES.timetoke_rate_per_second:.5f}/s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
