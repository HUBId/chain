#!/usr/bin/env python3
# Dieses Skript löscht nichts automatisch. Es erzeugt nur Befehle für manuelle Ausführung.
"""Generate delete commands for SAFE_MERGED branches based on the audit report.

This script deletes nothing automatically; it only prints commands for a human
operator to review and run manually.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List


PROTECTED_PREFIXES = ("main", "master", "dev", "develop", "release/", "staging/")


def load_report(report_path: Path) -> List[dict]:
    with report_path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)
    return data.get("branches", [])


def is_protected(branch_name: str) -> bool:
    short = branch_name.split("/", 1)[1] if "/" in branch_name else branch_name
    return any(short == p.rstrip("/") or short.startswith(p) for p in PROTECTED_PREFIXES)


def main() -> None:
    parser = argparse.ArgumentParser(description="Print git delete commands for SAFE_MERGED branches.")
    parser.add_argument("--report", type=Path, default=Path("tools/branch_audit/report.json"), help="Path to audit report JSON.")
    args = parser.parse_args()

    branches = load_report(args.report)
    deletable = [b for b in branches if b.get("category") == "SAFE_MERGED" and not is_protected(b.get("name", ""))]

    print("# Dieses Skript löscht nichts automatisch. Die folgenden Befehle können manuell ausgeführt werden:")
    for branch in deletable:
        name = branch["name"]
        if name.startswith("origin/"):
            name = name.split("/", 1)[1]
        print(f"git push origin --delete {name}")


if __name__ == "__main__":
    main()
