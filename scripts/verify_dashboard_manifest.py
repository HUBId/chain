#!/usr/bin/env python3
"""Validate dashboard exports against the performance manifest.

The script enforces that every entry in docs/performance_dashboards.json
provides a version tag and checksum that match the committed dashboard export.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def validate_entry(entry: Dict[str, object], repo_root: Path) -> Tuple[bool, List[str]]:
    errors: List[str] = []

    uid = entry.get("uid")
    output = entry.get("output")
    expected_sha = entry.get("sha256")
    version_tag = entry.get("version_tag")
    manifest_version = entry.get("version")

    if not uid:
        errors.append("Manifest entry is missing a uid")
    if not output:
        errors.append("Manifest entry is missing an output path")
        return False, errors

    output_path = Path(output)
    if not output_path.is_absolute():
        output_path = repo_root / output_path

    if not output_path.exists():
        errors.append(f"Dashboard export {output_path} is missing")
        return False, errors

    if expected_sha is None:
        errors.append(f"Manifest entry for {uid} is missing sha256")
    if not version_tag:
        errors.append(f"Manifest entry for {uid} is missing version_tag")

    try:
        dashboard = json.loads(output_path.read_text())
    except json.JSONDecodeError as exc:  # pragma: no cover - validation utility
        errors.append(f"Failed to parse {output_path}: {exc}")
        return False, errors

    local_version = dashboard.get("version")
    if manifest_version is None:
        errors.append(f"Manifest entry for {uid} is missing version")
    elif local_version != manifest_version:
        errors.append(
            f"Dashboard version mismatch for {uid}: manifest={manifest_version}, file={local_version}"
        )

    if expected_sha is not None:
        actual_sha = compute_sha256(output_path)
        if str(expected_sha).lower() != actual_sha:
            errors.append(
                f"Checksum mismatch for {uid}: manifest={expected_sha}, actual={actual_sha}"
            )

    return not errors, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "manifest",
        type=Path,
        nargs="?",
        default=Path("docs/performance_dashboards.json"),
        help="Path to the dashboard manifest JSON",
    )
    args = parser.parse_args()

    manifest_path = args.manifest
    if not manifest_path.exists():
        print(f"::error file={manifest_path}::Manifest not found", file=sys.stderr)
        return 1

    try:
        manifest_data = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:  # pragma: no cover - validation utility
        print(f"::error file={manifest_path}::Failed to parse manifest: {exc}", file=sys.stderr)
        return 1

    dashboards = manifest_data.get("dashboards", [])
    if not isinstance(dashboards, list) or not dashboards:
        print(
            f"::error file={manifest_path}::Manifest must contain a non-empty 'dashboards' list",
            file=sys.stderr,
        )
        return 1

    repo_root = manifest_path.parent.parent.resolve()
    errors = False
    for entry in dashboards:
        ok, problems = validate_entry(entry, repo_root)
        if not ok:
            errors = True
            for problem in problems:
                print(f"::error file={manifest_path}::{problem}", file=sys.stderr)

    if errors:
        return 1

    print("Dashboard manifest verified; checksums and versions match.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
