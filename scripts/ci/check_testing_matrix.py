#!/usr/bin/env python3
"""
Validate that docs/development/testing_matrix.md stays aligned with CI jobs.

The script asserts that each documented combination maps to the expected set of
job IDs and that every referenced job exists in `.github/workflows/ci.yml`.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys
from typing import Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOC_PATH = REPO_ROOT / "docs" / "development" / "testing_matrix.md"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

EXPECTED_MATRIX: Dict[str, Set[str]] = {
    "Default storage / default backend": {
        "firewood-unit",
        "firewood-ffi-go",
        "firewood-giant-node",
        "unit-suites",
        "integration-workflows",
        "simnet-smoke",
    },
    "io-uring storage backend": {
        "firewood-unit",
        "firewood-ffi-go",
        "firewood-giant-node",
    },
    "Branch factor 256 hashing": {
        "firewood-unit",
    },
    "Ethereum-compatible hashing": {
        "firewood-unit",
        "firewood-ffi-go",
    },
    "Branch factor 256 + Ethereum hashing": {
        "firewood-unit",
        "firewood-ffi-go",
    },
    "RPP-STARK backend for Firewood": {
        "firewood-ffi-go",
        "firewood-giant-node",
    },
    "STWO production backend": {
        "unit-suites",
        "integration-workflows",
        "simnet-smoke",
    },
    "STWO backend with Plonky3 verifier": {
        "unit-suites",
        "integration-workflows",
        "simnet-smoke",
    },
}


def parse_table(path: Path) -> Dict[str, Set[str]]:
    rows: Dict[str, Set[str]] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        if not line.startswith("|"):
            continue
        if "---" in line:
            continue
        cells: List[str] = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells or cells[0].lower() == "combination":
            continue
        if len(cells) < 3:
            print(f"::error file={path}::Table row is missing columns: {line}")
            sys.exit(1)
        combination = cells[0]
        jobs = {job.strip() for job in cells[2].split(",") if job.strip()}
        rows[combination] = jobs
    return rows


def read_ci_job_ids(path: Path) -> Set[str]:
    job_pattern = re.compile(r"^  (?P<job>[A-Za-z0-9_-]+):\s*$")
    jobs: Set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = job_pattern.match(line)
        if match:
            jobs.add(match.group("job"))
    return jobs


def main() -> int:
    if not DOC_PATH.exists():
        print(f"::error file={DOC_PATH}::Testing matrix document is missing")
        return 1

    documented = parse_table(DOC_PATH)
    ci_jobs = read_ci_job_ids(CI_WORKFLOW)

    expected_keys = set(EXPECTED_MATRIX)
    documented_keys = set(documented)

    missing = expected_keys - documented_keys
    extra = documented_keys - expected_keys

    if missing:
        print(
            f"::error file={DOC_PATH}::Missing combinations: {', '.join(sorted(missing))}",
            file=sys.stderr,
        )
    if extra:
        print(
            f"::error file={DOC_PATH}::Unexpected combinations documented: {', '.join(sorted(extra))}",
            file=sys.stderr,
        )
    if missing or extra:
        return 1

    exit_code = 0

    for combination, expected_jobs in EXPECTED_MATRIX.items():
        documented_jobs = documented.get(combination, set())
        missing_jobs = expected_jobs - documented_jobs
        unexpected_jobs = documented_jobs - expected_jobs

        if missing_jobs:
            print(
                f"::error file={DOC_PATH}::Combination '{combination}' missing job IDs: {', '.join(sorted(missing_jobs))}",
                file=sys.stderr,
            )
            exit_code = 1
        if unexpected_jobs:
            print(
                f"::error file={DOC_PATH}::Combination '{combination}' lists extra job IDs: {', '.join(sorted(unexpected_jobs))}",
                file=sys.stderr,
            )
            exit_code = 1

        for job in documented_jobs:
            if job not in ci_jobs:
                print(
                    f"::error file={DOC_PATH}::Job ID '{job}' for '{combination}' not found in ci.yml",
                    file=sys.stderr,
                )
                exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
