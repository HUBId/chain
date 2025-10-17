#!/usr/bin/env python3
"""Generate the STWO vendor manifest files based on on-disk artifacts."""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable, List

DEFAULT_VERSION = "0.1.1"
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
DEFAULT_VENDOR_ROOT = REPO_ROOT / "vendor" / "stwo-dev" / DEFAULT_VERSION
DEFAULT_CHUNKS_DIR = DEFAULT_VENDOR_ROOT / "chunks"
DEFAULT_SOURCE_DIR = DEFAULT_VENDOR_ROOT / "staging"
DEFAULT_MANIFEST_FILE = DEFAULT_VENDOR_ROOT / "manifest" / "chunks.json"
DEFAULT_FINAL_LIST_FILE = DEFAULT_VENDOR_ROOT / "manifest" / "final_file_list.txt"
DEFAULT_LOG_FILE = DEFAULT_VENDOR_ROOT / "logs" / "update_manifest.log"


def utcnow() -> str:
    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


class Logger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _emit(self, level: str, message: str) -> None:
        line = f"[{utcnow()}] [{level}] {message}"
        print(line)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def info(self, message: str) -> None:
        self._emit("INFO", message)

    def warn(self, message: str) -> None:
        self._emit("WARN", message)


def compute_sha256(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            data = handle.read(chunk_size)
            if not data:
                break
            digest.update(data)
    return digest.hexdigest()


def iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def build_manifest_entries(chunk_dir: Path, logger: Logger) -> List[dict]:
    entries: List[dict] = []
    if not chunk_dir.exists():
        logger.warn(f"Chunk directory {chunk_dir} does not exist; manifest will be empty")
        return entries

    for index, file_path in enumerate(iter_files(chunk_dir)):
        rel_path = file_path.relative_to(chunk_dir)
        logger.info(f"Hashing chunk {rel_path}")
        entries.append(
            {
                "segment_name": str(rel_path).replace(os.sep, "/"),
                "index": index,
                "size_bytes": file_path.stat().st_size,
                "sha256": compute_sha256(file_path),
                "timestamp": utcnow(),
                "status": "available",
            }
        )
    return entries


def write_manifest(manifest_path: Path, entries: List[dict], version: str) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": version,
        "generated_at": utcnow(),
        "segments": entries,
    }
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def write_final_file_list(source_dir: Path, output_path: Path, logger: Logger) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not source_dir.exists():
        logger.warn(f"Source directory {source_dir} does not exist; writing empty file list")
        output_path.write_text("", encoding="utf-8")
        return

    lines: List[str] = []
    for file_path in iter_files(source_dir):
        rel_path = file_path.relative_to(source_dir)
        sha = compute_sha256(file_path)
        size = file_path.stat().st_size
        lines.append(f"{sha} {size} {str(rel_path).replace(os.sep, '/')}\n")

    with output_path.open("w", encoding="utf-8") as handle:
        for line in sorted(lines):
            handle.write(line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chunks-dir", type=Path, default=DEFAULT_CHUNKS_DIR)
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_FILE)
    parser.add_argument("--final-file-list", type=Path, default=DEFAULT_FINAL_LIST_FILE)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logger = Logger(args.log_file)

    logger.info("Starting manifest rebuild")
    entries = build_manifest_entries(args.chunks_dir, logger)
    write_manifest(args.manifest, entries, args.version)
    write_final_file_list(args.source_dir, args.final_file_list, logger)
    logger.info("Manifest rebuild complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
