from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
STWO_ARCHIVE = REPO_ROOT / "prover" / "prover_stwo_backend" / "stwo-dev.zip"
STWO_ARCHIVE_SHA256 = "7aeb7cf550e322f5570bccad4f0a51ec1d6828b3b2577b9c5a6350aed4f771c6"
STWO_VENDOR_ROOT = REPO_ROOT / "vendor" / "stwo-dev" / "0.1.1"
STWO_MANIFEST_DIR = STWO_VENDOR_ROOT / "manifest"
STWO_SUMMARY = STWO_MANIFEST_DIR / "integrity_summary.json"
STWO_FINAL_LIST = STWO_MANIFEST_DIR / "final_file_list.txt"
STWO_STAGING = STWO_VENDOR_ROOT / "staging"
PLONKY3_MANIFEST = REPO_ROOT / "third_party" / "plonky3" / "manifest" / "checksums.json"

def sha256(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def validate_archive(path: Path, expected_sha: str, errors: List[str]) -> None:
    if not path.exists():
        errors.append(f"missing archive: {path}")
        return
    actual = sha256(path)
    if actual != expected_sha:
        errors.append(
            f"archive hash mismatch for {path}: expected {expected_sha}, got {actual}"
        )

def validate_summary(summary_path: Path, errors: List[str]) -> Dict:
    if not summary_path.exists():
        errors.append(f"missing STWO integrity summary: {summary_path}")
        return {}
    try:
        summary = json.loads(summary_path.read_text())
    except json.JSONDecodeError as exc:
        errors.append(f"failed to parse {summary_path}: {exc}")
        return {}

    if summary.get("workspace") != "stwo-dev" or summary.get("version") != "0.1.1":
        errors.append(
            f"unexpected STWO manifest identity in {summary_path}: {summary.get('workspace')} {summary.get('version')}"
        )
    return summary


def validate_final_list(final_list: Path, staging_dir: Path, summary: Dict, errors: List[str]) -> None:
    if not final_list.exists():
        errors.append(f"missing STWO final file list: {final_list}")
        return
    entries: List[Tuple[str, int, str]] = []
    with final_list.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                sha, size_str, rel_path = line.split(" ", 2)
                size = int(size_str)
            except ValueError as exc:
                errors.append(f"malformed final_file_list entry '{line}': {exc}")
                continue
            entries.append((sha, size, rel_path))

    for sha_expected, size_expected, rel_path in entries:
        file_path = staging_dir / rel_path
        if not file_path.exists():
            errors.append(f"staging file missing: {rel_path}")
            continue
        actual_sha = sha256(file_path)
        if actual_sha != sha_expected:
            errors.append(
                f"staging hash mismatch for {rel_path}: expected {sha_expected}, got {actual_sha}"
            )
        actual_size = file_path.stat().st_size
        if actual_size != size_expected:
            errors.append(
                f"staging size mismatch for {rel_path}: expected {size_expected} bytes, got {actual_size}"
            )

    key_files = summary.get("staging", {}).get("key_files", {})
    for rel_path, meta in key_files.items():
        file_path = staging_dir / rel_path
        if not file_path.exists():
            errors.append(f"key file missing: {rel_path}")
            continue
        expected_sha = meta.get("sha256")
        if expected_sha:
            actual_sha = sha256(file_path)
            if actual_sha != expected_sha:
                errors.append(
                    f"key file hash mismatch for {rel_path}: expected {expected_sha}, got {actual_sha}"
                )
        expected_size = meta.get("size_bytes")
        if expected_size is not None:
            size = file_path.stat().st_size
            if size != expected_size:
                errors.append(
                    f"key file size mismatch for {rel_path}: expected {expected_size} bytes, got {size}"
                )


def validate_plonky3(manifest_path: Path, errors: List[str]) -> None:
    if not manifest_path.exists():
        errors.append(f"missing Plonky3 manifest: {manifest_path}")
        return
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        errors.append(f"failed to parse {manifest_path}: {exc}")
        return
    files: Dict[str, str] = manifest.get("files", {})
    base_dir = manifest_path.parent.parent

    critical_files = [
        "README.md",
        "config.toml",
        "p3-air/0.3.0/Cargo.toml",
        "p3-fri/0.3.0/src/lib.rs",
        "p3-commit/0.3.0/src/lib.rs",
        "p3-uni-stark/0.3.0/src/lib.rs",
    ]

    for rel_path in critical_files:
        file_path = base_dir / rel_path
        expected_sha = files.get(rel_path)
        if expected_sha is None:
            errors.append(f"Plonky3 manifest missing entry for {rel_path}")
            continue
        if not file_path.exists():
            errors.append(f"Plonky3 critical file missing: {rel_path}")
            continue
        actual_sha = sha256(file_path)
        if actual_sha != expected_sha:
            errors.append(
                f"Plonky3 hash mismatch for {rel_path}: expected {expected_sha}, got {actual_sha}"
            )

    for file_path in base_dir.rglob("*"):
        if not file_path.is_file():
            continue
        rel_path = file_path.relative_to(base_dir).as_posix()
        if rel_path == "manifest/checksums.json":
            continue
        expected_sha = files.get(rel_path)
        if expected_sha is None:
            errors.append(f"Plonky3 file missing from manifest: {rel_path}")
            continue
        actual_sha = sha256(file_path)
        if actual_sha != expected_sha:
            errors.append(
                f"Plonky3 hash mismatch for {rel_path}: expected {expected_sha}, got {actual_sha}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate prover dependency integrity baselines")
    parser.parse_args()

    errors: List[str] = []
    validate_archive(STWO_ARCHIVE, STWO_ARCHIVE_SHA256, errors)
    summary = validate_summary(STWO_SUMMARY, errors)
    if summary:
        validate_final_list(STWO_FINAL_LIST, STWO_STAGING, summary, errors)
    validate_plonky3(PLONKY3_MANIFEST, errors)

    if errors:
        for entry in errors:
            print(f"ERROR: {entry}")
        return 1

    print("Prover dependency integrity checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
