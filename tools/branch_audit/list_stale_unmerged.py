#!/usr/bin/env python3
# Dieses Skript löscht oder merged nichts. Es listet nur Branches für die manuelle Prüfung auf.
"""List stale, unmerged branches from the audit report.

This script only reads the report and prints branch names for manual review.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import List


def load_report(report_path: Path) -> List[dict]:
    with report_path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)
    return data.get("branches", [])


def parse_timestamp(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return datetime.utcnow()


def main() -> None:
    parser = argparse.ArgumentParser(description="List stale, unmerged branches (oldest first).")
    parser.add_argument("--report", type=Path, default=Path("tools/branch_audit/report.json"), help="Path to audit report JSON.")
    args = parser.parse_args()

    branches = [
        b for b in load_report(args.report) if b.get("category") == "STALE_UNMERGED"
    ]
    branches.sort(key=lambda b: parse_timestamp(b.get("last_commit_iso", "")))

    print("# Review these branches manually; no deletion happens here.")
    for branch in branches:
        print(f"{branch['name']}  # last commit: {branch.get('last_commit_iso')}")


if __name__ == "__main__":
    main()
