#!/usr/bin/env python3
# Dieses Skript führt nichts automatisch aus. Es gibt nur manuelle Vorschläge zurück.
"""Generate merge/PR suggestions for TRIVIAL_MERGE_CANDIDATE branches.

This script only prints commands; it does not perform any merges.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import List


def load_report(report_path: Path) -> dict:
    with report_path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def resolve_canonical(report: dict, override: str | None) -> str:
    return override or os.getenv("CANONICAL_BRANCH") or report.get("canonical_branch") or "main"


def main() -> None:
    parser = argparse.ArgumentParser(description="Print merge suggestions for TRIVIAL_MERGE_CANDIDATE branches.")
    parser.add_argument("--report", type=Path, default=Path("tools/branch_audit/report.json"), help="Path to audit report JSON.")
    parser.add_argument("--canonical-branch", help="Override canonical branch.")
    args = parser.parse_args()

    report = load_report(args.report)
    canonical_branch = resolve_canonical(report, args.canonical_branch)

    candidates: List[dict] = [
        b for b in report.get("branches", []) if b.get("category") == "TRIVIAL_MERGE_CANDIDATE"
    ]

    print("# Dieses Skript führt keine Merges aus. Vorschläge für manuelle Ausführung:")
    for branch in candidates:
        name = branch["name"]
        local_name = name.split("/", 1)[1] if name.startswith("origin/") else name
        print("------------------------------")
        print(f"# Branch: {name}")
        print(f"git checkout {canonical_branch}")
        print("git pull")
        print(f"git merge --no-ff {local_name}  # zuerst lokal testen")
        print("# oder mit GitHub CLI:")
        print(f"gh pr create -B {canonical_branch} -H {local_name} --fill")


if __name__ == "__main__":
    main()
