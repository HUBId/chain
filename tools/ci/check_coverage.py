#!/usr/bin/env python3
"""Validate coverage thresholds emitted by cargo-llvm-cov."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Tuple


DEFAULT_THRESHOLDS: Dict[str, float] = {"line": 0.60, "branch": 0.50}
CRITICAL_THRESHOLDS: Dict[str, Dict[str, float]] = {
    "rpp-consensus": {"line": 0.78, "branch": 0.65},
    "rpp-p2p": {"line": 0.72, "branch": 0.60},
    "firewood": {"line": 0.70, "branch": 0.55},
    "storage-firewood": {"line": 0.72, "branch": 0.60},
}


def load_report(path: Path) -> Dict[str, Tuple[float, float]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    packages = payload.get("packages")
    if packages is None and "data" in payload:
        packages = payload["data"]

    if packages is None:
        raise SystemExit("coverage summary is missing package information")

    coverage: Dict[str, Tuple[float, float]] = {}
    for package in packages:
        name = package.get("name") or package.get("target")
        totals = package.get("totals") or package.get("coverage")
        if not name or not totals:
            continue
        line = _extract_percent(totals, "lines")
        branch = _extract_percent(totals, "branches")
        coverage[name] = (line, branch)

    if not coverage:
        raise SystemExit("coverage summary did not contain any package totals")

    return coverage


def _extract_percent(totals: Dict[str, object], key: str) -> float:
    entry = totals.get(key)
    if isinstance(entry, dict):
        percent = entry.get("percent")
        if percent is None and "coverage" in entry:
            percent = entry.get("coverage")
        if percent is None and "covered" in entry and "count" in entry:
            count = float(entry.get("count") or 0)
            covered = float(entry.get("covered") or 0)
            percent = 0.0 if count == 0 else covered / count * 100.0
    else:
        percent = entry

    if percent is None:
        raise SystemExit(f"coverage summary missing {key} information")

    return float(percent) / (100.0 if percent > 1 else 1.0)


def determine_threshold(crate: str) -> Dict[str, float]:
    return CRITICAL_THRESHOLDS.get(crate, DEFAULT_THRESHOLDS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "summary",
        type=Path,
        default=Path("coverage/summary.json"),
        help="Path to the JSON summary emitted by cargo-llvm-cov",
    )
    args = parser.parse_args()

    coverage = load_report(args.summary)
    failures = []

    for crate, (line_cov, branch_cov) in coverage.items():
        thresholds = determine_threshold(crate)
        if line_cov < thresholds["line"]:
            failures.append(
                f"{crate}: line coverage {line_cov:.3f} below threshold {thresholds['line']:.3f}"
            )
        if branch_cov < thresholds["branch"]:
            failures.append(
                f"{crate}: branch coverage {branch_cov:.3f} below threshold {thresholds['branch']:.3f}"
            )

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1

    for crate, (line_cov, branch_cov) in sorted(coverage.items()):
        print(f"{crate:>24s}  line={line_cov:.3f}  branch={branch_cov:.3f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
