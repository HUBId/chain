#!/usr/bin/env python3
"""Update the malachite vendor manifest with fresh segment hashes.

This script scans the downloaded chunk files, recalculates their SHA-256
hashes and persists the metadata into ``manifest/chunks.json``.  Existing
manifest entries are updated in-place so that auxiliary metadata such as the
original download timestamp is retained when possible.

In addition to writing the manifest the script re-verifies the stored hashes.
Whenever a mismatch is detected the affected chunk is deleted and the process
terminates with a dedicated exit code.  Callers can use this behaviour to
trigger a re-download of the missing segment.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Iterable, List


# --- Constants -----------------------------------------------------------------

DEFAULT_VERSION = "0.4.18"
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
DEFAULT_VENDOR_ROOT = REPO_ROOT / "vendor" / "malachite" / DEFAULT_VERSION
DEFAULT_PLAN_FILE = DEFAULT_VENDOR_ROOT / "manifest" / "chunk_plan.json"
DEFAULT_MANIFEST_FILE = DEFAULT_VENDOR_ROOT / "manifest" / "chunks.json"
DEFAULT_LOG_FILE = DEFAULT_VENDOR_ROOT / "logs" / "update_manifest.log"
DEFAULT_SEGMENT_TEMPLATE = f"malachite-{DEFAULT_VERSION}.part{{index:03d}}"

# Non-zero exit code that signals that at least one segment must be re-downloaded
EXIT_MISMATCH = 3


# --- Helper utilities ----------------------------------------------------------


def utcnow() -> str:
    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


class Logger:
    """Simple console/file logger."""

    def __init__(self, log_file: Path) -> None:
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def _emit(self, level: str, message: str) -> None:
        timestamp = utcnow()
        formatted = f"[{timestamp}] [{level}] {message}"
        print(formatted)
        with self.log_file.open("a", encoding="utf-8") as handle:
            handle.write(formatted + "\n")

    def info(self, message: str) -> None:
        self._emit("INFO", message)

    def warn(self, message: str) -> None:
        self._emit("WARN", message)

    def error(self, message: str) -> None:
        self._emit("ERROR", message)


def compute_sha256(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Dict:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError:
        return {}


def load_plan(path: Path) -> Dict:
    if not path.exists():
        raise FileNotFoundError(f"Chunk plan not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    chunks = plan.get("chunks")
    if not isinstance(chunks, list) or not chunks:
        raise ValueError("Chunk plan must contain a non-empty 'chunks' list")
    for idx, chunk in enumerate(chunks):
        if "offset" not in chunk or "length" not in chunk:
            raise ValueError(f"Chunk {idx} is missing 'offset' or 'length'")
    return plan


def resolve_segment_name(index: int, template: str) -> str:
    return template.format(index=index)


def update_manifest(
    *,
    plan_chunks: Iterable[Dict],
    manifest_path: Path,
    chunk_dir: Path,
    logger: Logger,
    segment_template: str,
) -> int:
    manifest = load_json(manifest_path)
    existing_segments: Dict[str, Dict] = {
        entry.get("segment_name"): entry
        for entry in manifest.get("segments", [])
        if isinstance(entry, dict) and entry.get("segment_name")
    }

    needs_redownload = False
    updated_segments: List[Dict] = []
    now = utcnow()

    chunk_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    for chunk in plan_chunks:
        index = int(chunk.get("index", 0))
        offset = int(chunk.get("offset"))
        length = int(chunk.get("length"))
        chunk_name = chunk.get("chunk_name") or f"chunk_{index:03d}"
        segment_name = resolve_segment_name(index, segment_template)
        segment_path = chunk_dir / segment_name

        logger.info(
            f"Processing segment {segment_name} (index={index}, offset={offset}, length={length})"
        )

        entry_timestamp = utcnow()
        existing_entry = existing_segments.get(segment_name, {})
        expected_hash = existing_entry.get("sha256")
        expected_size = existing_entry.get("size_bytes")

        if not segment_path.exists():
            logger.warn(f"Segment {segment_name} is missing on disk")
            missing_entry = {
                "segment_name": segment_name,
                "index": index,
                "chunk_name": chunk_name,
                "offset": offset,
                "length": length,
                "status": "missing",
                "timestamp": entry_timestamp,
            }
            updated_segments.append(missing_entry)
            needs_redownload = True
            continue

        size_bytes = segment_path.stat().st_size
        sha256 = compute_sha256(segment_path)

        if expected_hash and expected_hash != sha256:
            logger.error(
                f"Hash mismatch for {segment_name}: manifest {expected_hash} != actual {sha256}; removing file"
            )
        if expected_size and expected_size != size_bytes:
            logger.error(
                f"Size mismatch for {segment_name}: manifest {expected_size} != actual {size_bytes}; removing file"
            )

        if (
            (expected_hash and expected_hash != sha256)
            or (expected_size and expected_size != size_bytes)
        ):
            try:
                segment_path.unlink()
                logger.warn(f"Deleted corrupt segment {segment_name}")
            except OSError as exc:
                logger.error(f"Failed to delete {segment_name}: {exc}")
            removal_entry = {
                "segment_name": segment_name,
                "index": index,
                "chunk_name": chunk_name,
                "offset": offset,
                "length": length,
                "status": "deleted",
                "timestamp": entry_timestamp,
            }
            updated_segments.append(removal_entry)
            needs_redownload = True
            continue

        logger.info(
            f"Segment {segment_name} verified (size={size_bytes}, sha256={sha256})"
        )

        downloaded_at = existing_entry.get("downloaded_at")
        if not downloaded_at:
            downloaded_at = entry_timestamp

        segment_entry = {
            "segment_name": segment_name,
            "index": index,
            "chunk_name": chunk_name,
            "offset": offset,
            "length": length,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "downloaded_at": downloaded_at,
            "timestamp": entry_timestamp,
            "status": "verified",
        }
        updated_segments.append(segment_entry)

    updated_segments.sort(key=lambda item: (item.get("index"), item.get("segment_name")))

    manifest.update(
        {
            "version": manifest.get("version") or DEFAULT_VERSION,
            "generated_at": now,
            "segments": updated_segments,
        }
    )

    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")

    if needs_redownload:
        logger.warn(
            "One or more segments are missing or invalid. Trigger a re-download to restore them."
        )
        return EXIT_MISMATCH

    logger.info("Manifest updated successfully")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan",
        dest="plan_file",
        default=DEFAULT_PLAN_FILE,
        type=Path,
        help="Path to the chunk plan (default: %(default)s)",
    )
    parser.add_argument(
        "--manifest",
        dest="manifest_file",
        default=DEFAULT_MANIFEST_FILE,
        type=Path,
        help="Path to the manifest file (default: %(default)s)",
    )
    parser.add_argument(
        "--chunks-dir",
        dest="chunks_dir",
        default=DEFAULT_VENDOR_ROOT / "chunks",
        type=Path,
        help="Directory containing downloaded segments (default: %(default)s)",
    )
    parser.add_argument(
        "--log-file",
        dest="log_file",
        default=DEFAULT_LOG_FILE,
        type=Path,
        help="Log file to write diagnostic output (default: %(default)s)",
    )
    parser.add_argument(
        "--segment-template",
        dest="segment_template",
        default=DEFAULT_SEGMENT_TEMPLATE,
        help=(
            "Filename template for chunk segments. "
            "Must contain '{index:03d}' (default: %(default)s)"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logger = Logger(args.log_file)
    try:
        plan = load_plan(args.plan_file)
    except (FileNotFoundError, ValueError) as exc:
        logger.error(str(exc))
        return 1

    plan_chunks: List[Dict] = []
    for index, chunk in enumerate(plan.get("chunks", [])):
        plan_chunks.append(
            {
                "index": index,
                "chunk_name": chunk.get("chunk_name"),
                "offset": int(chunk.get("offset")),
                "length": int(chunk.get("length")),
            }
        )

    return update_manifest(
        plan_chunks=plan_chunks,
        manifest_path=args.manifest_file,
        chunk_dir=args.chunks_dir,
        logger=logger,
        segment_template=args.segment_template,
    )


if __name__ == "__main__":
    os._exit(main())
