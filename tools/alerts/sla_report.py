#!/usr/bin/env python3
"""Generate SLA conformance reports from Prometheus metrics.

The report tracks uptime participation, finality lag, and missed slots over a
configurable window, exporting JSON/Markdown artifacts and optionally failing
when SLA breaches are detected. The script expects metrics to be labelled with
an ``environment`` label so reports can be scoped to staging, prod, or test
clusters.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, MutableSequence, Sequence
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from tools.alerts.settings import FINALITY_SLA, UPTIME_SLA

_PROM_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
_DEFAULT_STEP_SECONDS = 300

_FINALITY_QUERY = "max_over_time(finality_lag_slots{environment=\"$ENV\"}[5m])"
_UPTIME_QUERY = "uptime_participation_ratio{environment=\"$ENV\"}"
_MISSED_SLOTS_QUERY = "consensus:missed_slots:5m{environment=\"$ENV\"}"


@dataclass(frozen=True)
class MetricSummary:
    """Aggregated statistics for a single metric series."""

    minimum: float | None
    maximum: float | None
    average: float | None
    p50: float | None
    p95: float | None
    samples: int

    @classmethod
    def from_samples(cls, samples: Sequence[float]) -> "MetricSummary":
        if not samples:
            return cls(None, None, None, None, None, 0)

        sorted_samples = sorted(samples)
        count = len(sorted_samples)
        return cls(
            minimum=sorted_samples[0],
            maximum=sorted_samples[-1],
            average=sum(sorted_samples) / float(count),
            p50=_percentile(sorted_samples, 50.0),
            p95=_percentile(sorted_samples, 95.0),
            samples=count,
        )


@dataclass(frozen=True)
class Breach:
    metric: str
    severity: str
    observed: float
    threshold: float
    message: str


class PrometheusClient:
    def __init__(self, base_url: str, token: str | None, timeout_seconds: float) -> None:
        if base_url.endswith("/"):
            self._base_url = base_url[:-1]
        else:
            self._base_url = base_url
        self._token = token
        self._timeout_seconds = timeout_seconds

    def query_range(
        self, query: str, start: _dt.datetime, end: _dt.datetime, step_seconds: int
    ) -> List[Dict[str, object]]:
        start_str = start.strftime(_PROM_DATE_FMT)
        end_str = end.strftime(_PROM_DATE_FMT)
        params = urlencode({"query": query, "start": start_str, "end": end_str, "step": step_seconds})
        request = Request(f"{self._base_url}/api/v1/query_range?{params}")
        if self._token:
            request.add_header("Authorization", f"Bearer {self._token}")
        with urlopen(request, timeout=self._timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
        status = payload.get("status")
        if status != "success":  # pragma: no cover - passthrough for API errors
            raise RuntimeError(f"Prometheus query failed with status {status}: {payload}")
        result = payload.get("data", {}).get("result")
        if not isinstance(result, list):  # pragma: no cover - defensive
            raise ValueError("Prometheus response missing result array")
        return result


class MetricSampler:
    def __init__(self, client: PrometheusClient, environment: str) -> None:
        self._client = client
        self._environment = environment

    def summarize(self, query_template: str, start: _dt.datetime, end: _dt.datetime, step_seconds: int) -> MetricSummary:
        query = query_template.replace("$ENV", self._environment)
        series = self._client.query_range(query, start, end, step_seconds)
        samples: MutableSequence[float] = []
        for entry in series:
            for _, raw_value in entry.get("values", []):
                value = _coerce_float(raw_value)
                if value is None:
                    continue
                samples.append(value)
        return MetricSummary.from_samples(samples)


def _percentile(samples: Sequence[float], percentile: float) -> float:
    if not samples:
        raise ValueError("cannot compute percentile of empty sample set")
    if len(samples) == 1:
        return samples[0]
    if percentile <= 0:
        return samples[0]
    if percentile >= 100:
        return samples[-1]
    index = (percentile / 100.0) * (len(samples) - 1)
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return samples[int(index)]
    lower_value = samples[lower]
    upper_value = samples[upper]
    fraction = index - lower
    return lower_value + (upper_value - lower_value) * fraction


def _coerce_float(raw: object) -> float | None:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value):
        return None
    return value


def _evaluate_maximum(metric: str, summary: MetricSummary, warning: float, critical: float, message: str) -> list[Breach]:
    if summary.maximum is None:
        return []
    breaches: list[Breach] = []
    if summary.maximum > warning:
        breaches.append(
            Breach(
                metric=metric,
                severity="critical" if summary.maximum > critical else "warning",
                observed=summary.maximum,
                threshold=critical if summary.maximum > critical else warning,
                message=message,
            )
        )
    return breaches


def _evaluate_minimum(metric: str, summary: MetricSummary, warning: float, critical: float, message: str) -> list[Breach]:
    if summary.minimum is None:
        return []
    breaches: list[Breach] = []
    if summary.minimum < warning:
        breaches.append(
            Breach(
                metric=metric,
                severity="critical" if summary.minimum < critical else "warning",
                observed=summary.minimum,
                threshold=critical if summary.minimum < critical else warning,
                message=message,
            )
        )
    return breaches


def generate_report(
    sampler: MetricSampler,
    start: _dt.datetime,
    end: _dt.datetime,
    step_seconds: int,
) -> Dict[str, object]:
    finality_summary = sampler.summarize(_FINALITY_QUERY, start, end, step_seconds)
    uptime_summary = sampler.summarize(_UPTIME_QUERY, start, end, step_seconds)
    missed_slots_summary = sampler.summarize(_MISSED_SLOTS_QUERY, start, end, step_seconds)

    breaches: list[Breach] = []
    breaches.extend(
        _evaluate_maximum(
            metric="finality_lag_slots",
            summary=finality_summary,
            warning=FINALITY_SLA.lag_warning_slots,
            critical=FINALITY_SLA.lag_critical_slots,
            message="Finality lag exceeded the documented SLA budget.",
        )
    )
    breaches.extend(
        _evaluate_maximum(
            metric="consensus:missed_slots:5m",
            summary=missed_slots_summary,
            warning=2.0,
            critical=4.0,
            message="Scheduled slots outpaced produced blocks beyond the slot coverage SLA.",
        )
    )
    breaches.extend(
        _evaluate_minimum(
            metric="uptime_participation_ratio",
            summary=uptime_summary,
            warning=UPTIME_SLA.participation_warning_ratio,
            critical=UPTIME_SLA.participation_critical_ratio,
            message="Validator uptime participation dipped below the documented baseline.",
        )
    )

    return {
        "window": {
            "start": start.strftime(_PROM_DATE_FMT),
            "end": end.strftime(_PROM_DATE_FMT),
            "step_seconds": step_seconds,
        },
        "metrics": {
            "finality_lag_slots": finality_summary.__dict__,
            "uptime_participation_ratio": uptime_summary.__dict__,
            "consensus:missed_slots:5m": missed_slots_summary.__dict__,
        },
        "breaches": [breach.__dict__ for breach in breaches],
    }


def _markdown_table_row(metric: str, summary: MetricSummary) -> str:
    if summary.samples == 0:
        return f"| {metric} | n/a | n/a | n/a | n/a | n/a |"
    return "| {metric} | {minimum:.4f} | {p50:.4f} | {p95:.4f} | {maximum:.4f} | {average:.4f} |".format(
        metric=metric,
        minimum=summary.minimum or 0.0,
        p50=summary.p50 or 0.0,
        p95=summary.p95 or 0.0,
        maximum=summary.maximum or 0.0,
        average=summary.average or 0.0,
    )


def render_markdown(environment: str, report: Mapping[str, object]) -> str:
    metrics = report.get("metrics", {})
    finality_summary = MetricSummary(**metrics.get("finality_lag_slots", {}))  # type: ignore[arg-type]
    uptime_summary = MetricSummary(**metrics.get("uptime_participation_ratio", {}))  # type: ignore[arg-type]
    missed_slots_summary = MetricSummary(**metrics.get("consensus:missed_slots:5m", {}))  # type: ignore[arg-type]
    breaches = report.get("breaches", [])
    window = report.get("window", {})

    lines = [
        f"# SLA report for {environment}",
        "",
        f"Window: {window.get('start', '?')} to {window.get('end', '?')} (step {window.get('step_seconds', '?')}s)",
        "",
        "## Metric summaries",
        "| Metric | Min | P50 | P95 | Max | Average |",
        "| --- | --- | --- | --- | --- | --- |",
        _markdown_table_row("finality_lag_slots", finality_summary),
        _markdown_table_row("uptime_participation_ratio", uptime_summary),
        _markdown_table_row("consensus:missed_slots:5m", missed_slots_summary),
        "",
    ]

    if breaches:
        lines.append("## SLA breaches detected")
        for breach in breaches:
            lines.append(
                f"- **{breach['severity']}** {breach['metric']} observed {breach['observed']} (threshold {breach['threshold']}): {breach['message']}"
            )
    else:
        lines.append("## No SLA breaches detected")

    return "\n".join(lines)


def _write_artifacts(output_dir: Path, environment: str, report: Mapping[str, object]) -> tuple[Path, Path]:
    timestamp = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    environment_safe = environment.replace("/", "-")
    json_path = output_dir / f"sla-report-{environment_safe}-{timestamp}.json"
    markdown_path = output_dir / f"sla-report-{environment_safe}-{timestamp}.md"
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(environment, report), encoding="utf-8")
    return json_path, markdown_path


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate SLA reports from Prometheus metrics")
    parser.add_argument("--prom-url", required=True, help="Base URL for the Prometheus HTTP API")
    parser.add_argument("--environment", required=True, help="Environment label to scope metrics (e.g. staging or prod)")
    parser.add_argument(
        "--hours", type=int, default=24, help="Number of hours before now to include in the report window (default: 24)"
    )
    parser.add_argument(
        "--step-seconds",
        type=int,
        default=_DEFAULT_STEP_SECONDS,
        help="Query resolution step in seconds (default: 300)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("target/sla-reports"),
        help="Directory to write JSON and Markdown artifacts (default: target/sla-reports)",
    )
    parser.add_argument("--token", default=os.getenv("PROMETHEUS_BEARER_TOKEN"), help="Bearer token for Prometheus")
    parser.add_argument(
        "--timeout-seconds", type=float, default=30.0, help="HTTP timeout when querying Prometheus (default: 30)"
    )
    parser.add_argument(
        "--fail-on-breach",
        action="store_true",
        help="Exit with status 2 when any SLA breach is detected",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    end = _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc)
    start = end - _dt.timedelta(hours=args.hours)

    client = PrometheusClient(args.prom_url, args.token, args.timeout_seconds)
    sampler = MetricSampler(client, args.environment)
    report = generate_report(sampler, start, end, args.step_seconds)

    json_path, markdown_path = _write_artifacts(args.output_dir, args.environment, report)
    print(f"Wrote report JSON to {json_path}")
    print(f"Wrote report Markdown to {markdown_path}")

    if report.get("breaches") and args.fail_on_breach:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
