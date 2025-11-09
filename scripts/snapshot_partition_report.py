#!/usr/bin/env python3
"""Aggregate snapshot partition simnet metrics and enforce recovery thresholds."""

from __future__ import annotations

import argparse
import json
import sys
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

    try:
        summary = load_summary(args.summary)
    except FileNotFoundError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    report = build_report(summary)

    max_resume_threshold_ms = args.max_resume_minutes * 60_000.0
    chunk_retry_threshold = args.max_chunk_retries
    issues = []

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

    if issues:
        for issue in issues:
            print(f"ERROR: {issue}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
