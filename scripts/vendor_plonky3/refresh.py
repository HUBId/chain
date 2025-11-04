#!/usr/bin/env python3
"""Refresh the Plonky3 third-party mirror via `cargo vendor`."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
DEFAULT_MANIFEST = Path(os.environ.get("PLONKY3_VENDOR_MANIFEST", SCRIPT_DIR / "Cargo.toml"))
DEFAULT_VENDOR_DIR = Path(os.environ.get("PLONKY3_VENDOR_DIR", REPO_ROOT / "third_party" / "plonky3"))
DEFAULT_CONFIG_PATH = Path(
    os.environ.get("PLONKY3_VENDOR_CONFIG", DEFAULT_VENDOR_DIR / "config.toml")
)
DEFAULT_CHECKSUMS = Path(
    os.environ.get("PLONKY3_VENDOR_CHECKSUMS", DEFAULT_VENDOR_DIR / "manifest" / "checksums.json")
)
KEEP_NAMES = {"README.md", "manifest"}


def utc_now() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_checksums(root: Path, *, ignore: set[Path]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path in ignore:
            continue
        rel = path.relative_to(root).as_posix()
        mapping[rel] = compute_sha256(path)
    return mapping


def ensure_clean_vendor_dir(vendor_dir: Path) -> None:
    vendor_dir.mkdir(parents=True, exist_ok=True)
    for entry in vendor_dir.iterdir():
        if entry.name in KEEP_NAMES:
            continue
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def write_config(config_path: Path, payload: str) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(payload, encoding="utf-8")


def load_expected_checksums(path: Path) -> Dict[str, str] | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    files = payload.get("files")
    if not isinstance(files, dict):
        raise ValueError(f"invalid checksum manifest at {path}")
    return {str(k): str(v) for k, v in files.items()}


def write_checksum_manifest(path: Path, mapping: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": utc_now(),
        "files": mapping,
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def _write_stderr(payload: str | None) -> None:
    if not payload:
        return
    sys.stderr.write(payload)
    if not payload.endswith("\n"):
        sys.stderr.write("\n")


def run_cargo_vendor(manifest: Path, vendor_dir: Path) -> str:
    cmd = [
        "cargo",
        "vendor",
        "--manifest-path",
        str(manifest),
        "--versioned-dirs",
        str(vendor_dir),
    ]
    try:
        proc = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        # Forward cargo's diagnostics directly so warnings/errors stay visible.
        _write_stderr(exc.stderr or exc.stdout)
        raise

    _write_stderr(proc.stderr)
    return proc.stdout


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--vendor-dir", type=Path, default=DEFAULT_VENDOR_DIR)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--checksums", type=Path, default=DEFAULT_CHECKSUMS)
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Skip cargo vendor and only validate checksums",
    )
    parser.add_argument(
        "--write-checksums",
        action="store_true",
        help="Overwrite the checksum manifest with the freshly computed hashes",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    manifest = args.manifest
    vendor_dir = args.vendor_dir
    config_path = args.config
    checksum_path = args.checksums

    if not manifest.exists():
        print(f"error: manifest not found at {manifest}", file=sys.stderr)
        return 1

    if not args.check_only:
        ensure_clean_vendor_dir(vendor_dir)
        try:
            config_payload = run_cargo_vendor(manifest, vendor_dir)
        except subprocess.CalledProcessError as exc:
            return exc.returncode
        write_config(config_path, config_payload)

    ignore = {checksum_path}
    checksums = collect_checksums(vendor_dir, ignore=ignore)

    expected = load_expected_checksums(checksum_path)
    if expected is not None and checksums != expected and not args.write_checksums:
        print("error: checksum verification failed", file=sys.stderr)
        added = sorted(set(checksums) - set(expected))
        removed = sorted(set(expected) - set(checksums))
        changed = sorted(k for k in set(checksums) & set(expected) if checksums[k] != expected[k])
        if added:
            print("  added:", *added, sep="\n    ", file=sys.stderr)
        if removed:
            print("  removed:", *removed, sep="\n    ", file=sys.stderr)
        if changed:
            print("  changed:", *changed, sep="\n    ", file=sys.stderr)
        print(
            "Re-run with --write-checksums to record the new hashes.",
            file=sys.stderr,
        )
        return 1

    if args.write_checksums or expected is None:
        write_checksum_manifest(checksum_path, checksums)

    print("Plonky3 vendor tree is up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
