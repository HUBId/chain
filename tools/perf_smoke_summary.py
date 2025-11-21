#!/usr/bin/env python3
"""Generate performance smoke benchmark summaries.

This script consumes ``smoke-metrics.json`` produced by the benchmark and emits
three artifacts:

- A Markdown summary for humans reading CI output.
- A machine-readable JSON summary that downstream systems can ingest.
- A minimal HTML summary for dashboards or CI previews.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class BaselineEntry:
    key: str
    label: str
    actual: float
    lower: Optional[float]
    upper: Optional[float]
    within_range: bool

    def bounds_text(self) -> str:
        pieces: List[str] = []
        if self.lower is not None:
            pieces.append(f">= {self.lower:.2f}")
        if self.upper is not None:
            pieces.append(f"<= {self.upper:.2f}")
        return ", ".join(pieces) if pieces else "no bounds configured"

    def status_icon(self) -> str:
        return "✅" if self.within_range else "❌"


def load_metrics(path: Path) -> Dict[str, Any]:
    if not path.exists():
        print(f"::error ::{path} is missing", file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        print(f"::error ::Failed to parse {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def parse_baseline_entries(data: Dict[str, Any]) -> List[BaselineEntry]:
    baseline = data.get("baseline", {})
    entries: List[BaselineEntry] = []

    def record(key: str, label: str) -> None:
        entry = baseline.get(key)
        if not isinstance(entry, dict):
            print(
                f"::warning ::Baseline entry '{key}' missing from smoke-metrics.json",
                file=sys.stderr,
            )
            return
        actual = entry.get("actual")
        if actual is None:
            print(
                f"::warning ::Baseline entry '{key}' missing actual value",
                file=sys.stderr,
            )
            return
        entries.append(
            BaselineEntry(
                key=key,
                label=label,
                actual=float(actual),
                lower=entry.get("lower"),
                upper=entry.get("upper"),
                within_range=bool(entry.get("within_range")),
            )
        )

    record("throughput_ops_per_sec", "Throughput (ops/sec)")
    record("per_batch_p95_ms", "Batch P95 latency (ms)")
    record("total_duration_ms", "Total duration (ms)")
    return entries


def build_markdown(
    data: Dict[str, Any],
    baseline_entries: List[BaselineEntry],
    warn_missing_baseline: bool,
) -> str:
    throughput = float(data.get("throughput_ops_per_sec", 0.0))
    summary_lines = [
        "# Firewood smoke benchmark summary",
        "",
        f"* Total batches: {int(data.get('batches', 0))}",
        f"* Batch size: {int(data.get('batch_size', 0))}",
        f"* Throughput: {throughput:.2f} ops/sec",
        f"* Total duration: {float(data.get('total_duration_ms', 0.0)):.2f} ms",
    ]

    if baseline_entries:
        summary_lines.append("")
        summary_lines.append("## Baseline comparison")
        for entry in baseline_entries:
            summary_lines.append(
                f"* {entry.label}: {entry.actual:.2f} ({entry.bounds_text()}) {entry.status_icon()}"
            )
    elif warn_missing_baseline:
        summary_lines.append("")
        summary_lines.append(
            "⚠️ Baseline metrics were not evaluated. Review smoke-metrics.json for details."
        )

    return "\n".join(summary_lines) + "\n"


def build_summary_json(
    data: Dict[str, Any], baseline_entries: List[BaselineEntry], status: str
) -> Dict[str, Any]:
    return {
        "status": status,
        "run": {
            "batches": data.get("batches"),
            "batch_size": data.get("batch_size"),
            "total_operations": data.get("total_operations"),
            "total_duration_ms": data.get("total_duration_ms"),
            "throughput_ops_per_sec": data.get("throughput_ops_per_sec"),
            "per_batch_count": len(data.get("per_batch_ms", []) or []),
        },
        "baseline": [
            {
                "key": entry.key,
                "label": entry.label,
                "actual": entry.actual,
                "lower": entry.lower,
                "upper": entry.upper,
                "within_range": entry.within_range,
            }
            for entry in baseline_entries
        ],
        "baseline_source": data.get("baseline", {}).get("source"),
    }


def build_html(summary_json: Dict[str, Any]) -> str:
    header = """<style>
body { font-family: sans-serif; line-height: 1.5; }
table { border-collapse: collapse; margin-top: 1rem; }
th, td { border: 1px solid #ddd; padding: 0.5rem 0.75rem; }
th { background: #f2f2f2; text-align: left; }
</style>"""
    run = summary_json.get("run", {})
    baseline = summary_json.get("baseline", [])

    rows = "\n".join(
        f"<tr><td>{escape(entry.get('label', ''))}</td><td>{entry.get('actual'):.2f}</td>"
        f"<td>{escape(format_bounds(entry))}</td><td>{'✅' if entry.get('within_range') else '❌'}</td></tr>"
        for entry in baseline
    )

    return (
        "<html><head><meta charset='utf-8'>" + header + "</head><body>"
        f"<h1>Firewood smoke benchmark</h1>"
        f"<p>Status: <strong>{escape(str(summary_json.get('status', 'unknown')))}</strong></p>"
        "<ul>"
        f"<li>Total batches: {escape(str(run.get('batches')))}</li>"
        f"<li>Batch size: {escape(str(run.get('batch_size')))}</li>"
        f"<li>Throughput: {escape(str(run.get('throughput_ops_per_sec')))} ops/sec</li>"
        f"<li>Total duration: {escape(str(run.get('total_duration_ms')))} ms</li>"
        "</ul>"
        "<h2>Baseline comparison</h2>"
        "<table><thead><tr><th>Metric</th><th>Actual</th><th>Expected</th><th>Status</th></tr></thead><tbody>"
        + rows
        + "</tbody></table>"
        + "</body></html>"
    )


def format_bounds(entry: Dict[str, Any]) -> str:
    lower = entry.get("lower")
    upper = entry.get("upper")
    bounds: List[str] = []
    if lower is not None:
        bounds.append(f">= {float(lower):.2f}")
    if upper is not None:
        bounds.append(f"<= {float(upper):.2f}")
    return " and ".join(bounds) if bounds else "no bounds configured"


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize smoke benchmark metrics")
    parser.add_argument("--metrics", default="smoke-metrics.json", type=Path)
    parser.add_argument("--summary-md", default="smoke-summary.md", type=Path)
    parser.add_argument("--summary-json", default="smoke-summary.json", type=Path)
    parser.add_argument("--summary-html", default="smoke-summary.html", type=Path)
    args = parser.parse_args()

    metrics = load_metrics(args.metrics)
    baseline_entries = parse_baseline_entries(metrics)

    warn_missing_baseline = not baseline_entries
    failures = [entry for entry in baseline_entries if not entry.within_range]
    status = "pass" if not failures else "fail"

    markdown = build_markdown(metrics, baseline_entries, warn_missing_baseline)
    args.summary_md.write_text(markdown)

    summary_json = build_summary_json(metrics, baseline_entries, status)
    args.summary_json.write_text(json.dumps(summary_json, indent=2) + "\n")

    args.summary_html.write_text(build_html(summary_json))

    if failures:
        for entry in failures:
            expected = format_bounds(
                {
                    "lower": entry.lower,
                    "upper": entry.upper,
                }
            )
            print(
                f"::error ::{entry.label} {entry.actual:.2f} fell outside expected range ({expected})",
                file=sys.stderr,
            )
        return 1

    if warn_missing_baseline:
        print("::warning ::No baseline metrics were evaluated", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
