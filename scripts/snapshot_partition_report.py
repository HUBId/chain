#!/usr/bin/env python3
"""Aggregate snapshot partition simnet metrics and enforce recovery thresholds."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict


def load_summary(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"summary file {path} does not exist")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_report(summary: Dict[str, Any]) -> Dict[str, Any]:
    propagation = summary.get("propagation") or {}
    recovery = summary.get("recovery") or {}
    resume_latencies = recovery.get("resume_latencies_ms") or []

    report: Dict[str, Any] = {
        "total_publishes": summary.get("total_publishes", 0),
        "total_receives": summary.get("total_receives", 0),
        "duplicates": summary.get("duplicates", 0),
        "chunk_retries": summary.get("chunk_retries", 0),
        "propagation_ms": {
            "p50": propagation.get("p50_ms"),
            "p95": propagation.get("p95_ms"),
        },
        "recovery": {
            "resume_events": len(resume_latencies),
            "resume_latencies_ms": resume_latencies,
            "max_resume_latency_ms": recovery.get("max_resume_latency_ms"),
            "mean_resume_latency_ms": recovery.get("mean_resume_latency_ms"),
        },
    }
    return report


def _normalize(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _parse_headers(raw: str | None) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if raw is None:
        return headers
    for entry in raw.replace("\n", ",").split(","):
        part = entry.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"invalid header entry '{part}', expected key=value")
        key, value = part.split("=", 1)
        headers[key.strip()] = value.strip()
    return headers


class MetricsReporter:
    def __init__(
        self,
        prom_path: str | None,
        otlp_endpoint: str | None,
        auth_header: str | None,
        extra_headers: Dict[str, str],
        service_name: str,
        service_instance: str | None,
        scope_name: str,
        job_label: str | None,
        timeout: float,
    ) -> None:
        self._prom_path = prom_path
        self._otlp_endpoint = otlp_endpoint
        self._auth_header = auth_header
        self._extra_headers = extra_headers
        self._service_name = service_name
        self._service_instance = service_instance
        self._scope_name = scope_name
        self._job_label = job_label
        self._timeout = timeout
        self._start_time_ns = time.time_ns()

        self._snapshot_runs = 0
        self._snapshot_failures = 0
        self._dirty = False

    @classmethod
    def from_env(cls, scope: str, default_service: str) -> "MetricsReporter | None":
        prom_path = _normalize(os.getenv("OBSERVABILITY_METRICS_PROM_PATH"))
        otlp_endpoint = _normalize(os.getenv("OBSERVABILITY_METRICS_OTLP_ENDPOINT"))
        if prom_path is None and otlp_endpoint is None:
            return None

        auth_token = _normalize(os.getenv("OBSERVABILITY_METRICS_AUTH_TOKEN"))
        if auth_token is not None and not auth_token.lower().startswith("bearer "):
            auth_header = f"Bearer {auth_token}"
        else:
            auth_header = auth_token

        extra_headers = _parse_headers(os.getenv("OBSERVABILITY_METRICS_HEADERS"))
        service_name = _normalize(os.getenv("OBSERVABILITY_METRICS_SERVICE_NAME")) or default_service
        service_instance = _normalize(os.getenv("OBSERVABILITY_METRICS_SERVICE_INSTANCE"))
        scope_name = _normalize(os.getenv("OBSERVABILITY_METRICS_SCOPE")) or scope
        job_label = _normalize(os.getenv("OBSERVABILITY_METRICS_JOB"))
        timeout_raw = _normalize(os.getenv("OBSERVABILITY_METRICS_TIMEOUT_MS"))
        timeout = float(timeout_raw) / 1000.0 if timeout_raw else 10.0

        return cls(
            prom_path,
            otlp_endpoint,
            auth_header,
            extra_headers,
            service_name,
            service_instance,
            scope_name,
            job_label,
            timeout,
        )

    def record_snapshot_chaos(self, success: bool) -> None:
        self._snapshot_runs += 1
        if not success:
            self._snapshot_failures += 1
        self._dirty = True

    def flush(self) -> None:
        if not self._dirty:
            return
        if self._prom_path:
            try:
                self._write_prometheus()
            except Exception as exc:  # pragma: no cover - telemetry failures shouldn't abort tests
                print(
                    f"WARNING: failed to write Prometheus metrics to {self._prom_path}: {exc}",
                    file=sys.stderr,
                )
        if self._otlp_endpoint:
            try:
                self._send_otlp()
            except Exception as exc:  # pragma: no cover
                print(
                    f"WARNING: failed to export OTLP metrics to {self._otlp_endpoint}: {exc}",
                    file=sys.stderr,
                )
        self._snapshot_runs = 0
        self._snapshot_failures = 0
        self._dirty = False

    def _write_prometheus(self) -> None:
        directory = Path(self._prom_path).parent
        if directory and str(directory) != "":
            directory.mkdir(parents=True, exist_ok=True)
        lines = [
            "# TYPE worm_retention_checks_total counter",
            "worm_retention_checks_total 0",
            "# TYPE worm_retention_failures_total counter",
            "worm_retention_failures_total 0",
            "# TYPE snapshot_chaos_runs_total counter",
            f"snapshot_chaos_runs_total {self._snapshot_runs}",
            "# TYPE snapshot_chaos_failures_total counter",
            f"snapshot_chaos_failures_total {self._snapshot_failures}",
            "",
        ]
        Path(self._prom_path).write_text("\n".join(lines), encoding="utf-8")

    def _send_otlp(self) -> None:
        now_ns = time.time_ns()
        metrics = [
            {
                "name": "worm_retention_checks_total",
                "description": "Total number of worm-retention verification runs executed.",
                "sum": {
                    "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                    "isMonotonic": True,
                    "dataPoints": [
                        {
                            "startTimeUnixNano": str(self._start_time_ns),
                            "timeUnixNano": str(now_ns),
                            "asInt": "0",
                            "attributes": [],
                        }
                    ],
                },
            },
            {
                "name": "worm_retention_failures_total",
                "description": "Count of worm-retention verification runs that reported failures.",
                "sum": {
                    "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                    "isMonotonic": True,
                    "dataPoints": [
                        {
                            "startTimeUnixNano": str(self._start_time_ns),
                            "timeUnixNano": str(now_ns),
                            "asInt": "0",
                            "attributes": [],
                        }
                    ],
                },
            },
            {
                "name": "snapshot_chaos_runs_total",
                "description": "Total snapshot chaos drill executions.",
                "sum": {
                    "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                    "isMonotonic": True,
                    "dataPoints": [
                        {
                            "startTimeUnixNano": str(self._start_time_ns),
                            "timeUnixNano": str(now_ns),
                            "asInt": str(self._snapshot_runs),
                            "attributes": [],
                        }
                    ],
                },
            },
            {
                "name": "snapshot_chaos_failures_total",
                "description": "Snapshot chaos drill executions that breached configured thresholds.",
                "sum": {
                    "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                    "isMonotonic": True,
                    "dataPoints": [
                        {
                            "startTimeUnixNano": str(self._start_time_ns),
                            "timeUnixNano": str(now_ns),
                            "asInt": str(self._snapshot_failures),
                            "attributes": [],
                        }
                    ],
                },
            },
        ]

        resource_attributes = [
            {
                "key": "service.name",
                "value": {"stringValue": self._service_name},
            }
        ]
        if self._service_instance:
            resource_attributes.append(
                {
                    "key": "service.instance.id",
                    "value": {"stringValue": self._service_instance},
                }
            )
        if self._job_label:
            resource_attributes.append(
                {"key": "job", "value": {"stringValue": self._job_label}}
            )

        payload = {
            "resourceMetrics": [
                {
                    "resource": {"attributes": resource_attributes},
                    "scopeMetrics": [
                        {
                            "scope": {"name": self._scope_name},
                            "metrics": metrics,
                        }
                    ],
                }
            ]
        }

        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(self._otlp_endpoint, data=data)
        request.add_header("Content-Type", "application/json")
        if self._auth_header:
            request.add_header("Authorization", self._auth_header)
        for key, value in self._extra_headers.items():
            request.add_header(key, value)

        with urllib.request.urlopen(request, timeout=self._timeout) as response:
            if response.status >= 400:
                raise RuntimeError(
                    f"collector responded with HTTP {response.status}: {response.read().decode('utf-8', 'ignore')}"
                )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True, help="Path to the raw simnet summary JSON")
    parser.add_argument("--output", type=Path, required=True, help="Destination path for the aggregated report JSON")
    parser.add_argument(
        "--max-resume-minutes",
        type=float,
        default=2.0,
        help="Fail if max resume latency exceeds this many minutes",
    )
    parser.add_argument(
        "--max-chunk-retries",
        type=int,
        default=25,
        help="Fail if chunk retries exceed this value",
    )
    args = parser.parse_args(argv)

    reporter = MetricsReporter.from_env("nightly.snapshot_chaos", "compliance-nightly")

    try:
        summary = load_summary(args.summary)
    except FileNotFoundError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        if reporter:
            reporter.record_snapshot_chaos(False)
            reporter.flush()
        return 1

    issues: list[str] = []
    try:
        report = build_report(summary)

        max_resume_threshold_ms = args.max_resume_minutes * 60_000.0
        chunk_retry_threshold = args.max_chunk_retries

        max_resume = report["recovery"].get("max_resume_latency_ms")
        if max_resume is not None and max_resume > max_resume_threshold_ms:
            issues.append(
                f"max resume latency {max_resume:.2f}ms exceeds threshold {max_resume_threshold_ms:.2f}ms"
            )

        chunk_retries = report.get("chunk_retries", 0)
        if chunk_retries > chunk_retry_threshold:
            issues.append(
                f"chunk retries {chunk_retries} exceeds threshold {chunk_retry_threshold}"
            )

        report["thresholds"] = {
            "max_resume_latency_ms": max_resume_threshold_ms,
            "max_chunk_retries": chunk_retry_threshold,
        }
        report["source_summary"] = str(args.summary)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except Exception:
        if reporter:
            reporter.record_snapshot_chaos(False)
            reporter.flush()
        raise

    success = not issues
    if reporter:
        reporter.record_snapshot_chaos(success)
        reporter.flush()

    if issues:
        for issue in issues:
            print(f"ERROR: {issue}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
