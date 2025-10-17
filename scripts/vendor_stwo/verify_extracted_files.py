#!/usr/bin/env python3
"""Verify that extracted STWO sources match the recorded final file list."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Dict

DEFAULT_VERSION = "0.1.1"
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
DEFAULT_VENDOR_ROOT = REPO_ROOT / "vendor" / "stwo-dev" / DEFAULT_VERSION
DEFAULT_SOURCE_DIR = DEFAULT_VENDOR_ROOT / "staging"
DEFAULT_FINAL_LIST = DEFAULT_VENDOR_ROOT / "manifest" / "final_file_list.txt"


def compute_sha256(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            data = handle.read(chunk_size)
            if not data:
                break
            digest.update(data)
    return digest.hexdigest()


def load_expected(path: Path) -> Dict[str, str]:
    expected: Dict[str, str] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            sha, size_str, rel = line.split(" ", 2)
            expected[rel] = sha
    return expected


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR)
    parser.add_argument("--final-file-list", type=Path, default=DEFAULT_FINAL_LIST)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    expected = load_expected(args.final_file_list)
    missing = []
    mismatched = []

    for rel_path, sha in expected.items():
        file_path = args.source_dir / rel_path
        if not file_path.exists():
            missing.append(rel_path)
            continue
        actual = compute_sha256(file_path)
        if actual != sha:
            mismatched.append((rel_path, sha, actual))

    if missing or mismatched:
        if missing:
            print("Missing files:")
            for item in missing:
                print(f"  - {item}")
        if mismatched:
            print("Mismatched files:")
            for rel, exp, act in mismatched:
                print(f"  - {rel}: expected {exp}, got {act}")
        return 1

    print("All files match recorded hashes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
