from __future__ import annotations

import datetime as dt
from typing import Dict, List

import pytest

from tools.alerts import sla_report
from tools.alerts.sla_report import Breach, MetricSampler, MetricSummary, generate_report, render_markdown


class _FakeClient:
    def __init__(self, responses: Dict[str, List[float]]) -> None:
        self._responses = responses
        self.queries: list[str] = []

    def query_range(self, query: str, start: dt.datetime, end: dt.datetime, step_seconds: int):  # type: ignore[override]
        self.queries.append(query)
        values = self._responses.get(query, [])
        return [
            {
                "metric": {"environment": "test"},
                "values": [[start.timestamp(), str(value)] for value in values],
            }
        ]


def test_metric_summary_computes_statistics() -> None:
    summary = MetricSummary.from_samples([1.0, 2.0, 3.0, 4.0, 10.0])
    assert summary.minimum == 1.0
    assert summary.maximum == 10.0
    assert summary.samples == 5
    assert summary.average == pytest.approx(4.0)
    assert summary.p50 == pytest.approx(3.0)
    assert summary.p95 == pytest.approx(8.8)


def test_generate_report_detects_breaches() -> None:
    start = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    end = start + dt.timedelta(hours=1)
    client = _FakeClient(
        {
            "max_over_time(finality_lag_slots{environment=\"test\"}[5m])": [1.0, 13.0],
            "uptime_participation_ratio{environment=\"test\"}": [0.98, 0.91],
            "consensus:missed_slots:5m{environment=\"test\"}": [0, 5],
        }
    )
    sampler = MetricSampler(client, environment="test")

    report = generate_report(sampler, start, end, step_seconds=300)

    # Metric summaries propagate into the report
    finality_summary = report["metrics"]["finality_lag_slots"]
    assert finality_summary["maximum"] == 13.0

    # Breaches bubble up with severities
    breach_metrics = {(entry["metric"], entry["severity"]) for entry in report["breaches"]}
    assert ("finality_lag_slots", "warning") in breach_metrics
    assert ("consensus:missed_slots:5m", "critical") in breach_metrics
    assert ("uptime_participation_ratio", "critical") in breach_metrics


def test_render_markdown_handles_empty_series() -> None:
    report = {
        "window": {"start": "2024-01-01T00:00:00Z", "end": "2024-01-01T01:00:00Z", "step_seconds": 300},
        "metrics": {
            "finality_lag_slots": MetricSummary.from_samples([]).__dict__,
            "uptime_participation_ratio": MetricSummary.from_samples([1]).__dict__,
            "consensus:missed_slots:5m": MetricSummary.from_samples([0, 0, 0]).__dict__,
        },
        "breaches": [
            Breach(
                metric="uptime_participation_ratio",
                severity="critical",
                observed=0.5,
                threshold=0.94,
                message="drop",
            ).__dict__
        ],
    }

    markdown = render_markdown("qa", report)

    assert "SLA report for qa" in markdown
    assert "No SLA breaches" not in markdown
    assert "critical** uptime_participation_ratio observed 0.5" in markdown
