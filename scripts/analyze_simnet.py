#!/usr/bin/env python3
"""Aggregate metrics emitted by the simnet harness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


def load_summary(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def render_report(path: Path, summary: Dict[str, Any]) -> str:
    propagation = summary.get("propagation") or {}
    p50 = propagation.get("p50_ms")
    p95 = propagation.get("p95_ms")
    lines = [
        f"summary: {path}",
        f"  publishes: {summary.get('total_publishes', 0)}",
        f"  receives: {summary.get('total_receives', 0)}",
        f"  duplicates: {summary.get('duplicates', 0)}",
    ]
    if p50 is not None and p95 is not None:
        lines.append(f"  propagation_ms: p50={p50:.2f}, p95={p95:.2f}")
    else:
        lines.append("  propagation_ms: n/a")

    comparison = summary.get("comparison")
    if comparison:
        deltas = comparison.get("deltas", {})
        lines.append("  comparison:")
        lines.append(
            "    publishes_delta: "
            f"{deltas.get('total_publishes', 'n/a')}"
        )
        lines.append(
            "    receives_delta: "
            f"{deltas.get('total_receives', 'n/a')}"
        )
        lines.append(
            "    duplicates_delta: "
            f"{deltas.get('duplicates', 'n/a')}"
        )
        if deltas.get("propagation_p95_ms") is not None:
            lines.append(
                "    propagation_delta_ms: "
                f"p50={deltas.get('propagation_p50_ms'):.2f}, "
                f"p95={deltas.get('propagation_p95_ms'):.2f}"
            )
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "summaries",
        nargs="+",
        type=Path,
        help="One or more JSON summaries emitted by simnet",
    )
    parser.add_argument(
        "--max-propagation-p95",
        type=float,
        default=500.0,
        help="Fail if the propagation p95 exceeds this threshold (ms)",
    )
    args = parser.parse_args(argv)

    failures: List[str] = []
    for path in args.summaries:
        summary = load_summary(path)
        print(render_report(path, summary))
        print()

        propagation = summary.get("propagation") or {}
        p95 = propagation.get("p95_ms")
        if p95 is not None and p95 > args.max_propagation_p95:
            failures.append(
                f"{path} propagation p95 {p95:.2f}ms exceeds threshold {args.max_propagation_p95:.2f}ms"
            )

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
