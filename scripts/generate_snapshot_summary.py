#!/usr/bin/env python3
"""Generate snapshot manifest summaries for bundled release artefacts.

The script scans a bundle directory for pruning snapshot manifests, derives
chunk counts from the persisted state-sync plans, and writes a structured JSON
summary that operators can inspect alongside the release artefacts.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class SnapshotManifestRecord:
    path: Path
    data: dict

    @property
    def block_height(self) -> int:
        value = self.data.get("block_height")
        if not isinstance(value, int):
            raise ValueError(f"manifest {self.path} missing integer block_height")
        return value

    @property
    def state_root(self) -> str:
        value = self.data.get("state_root")
        if not isinstance(value, str):
            raise ValueError(f"manifest {self.path} missing state_root")
        return value

    @property
    def snapshot_id(self) -> str:
        return self.path.stem


class SnapshotSummaryError(RuntimeError):
    pass


def load_manifest(path: Path) -> Optional[SnapshotManifestRecord]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    required_fields = {"block_height", "state_root", "proof_file", "proof_checksum"}
    if not required_fields.issubset(data):
        return None
    try:
        return SnapshotManifestRecord(path=path, data=data)
    except ValueError:
        return None


def discover_manifests(root: Path) -> Iterable[SnapshotManifestRecord]:
    for candidate in root.rglob("*.json"):
        record = load_manifest(candidate)
        if record is not None:
            yield record


def find_plan(root: Path, height: int) -> Optional[Path]:
    patterns = [
        f"snapshot-{height}.json",
        f"state_sync_plan-{height}.json",
        f"state-sync-plan-{height}.json",
        f"plan-{height}.json",
    ]
    for pattern in patterns:
        matches = list(root.rglob(pattern))
        if matches:
            return matches[0]
    return None


def chunk_count_from_plan(path: Path) -> int:
    with path.open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    if not isinstance(plan, dict):
        raise SnapshotSummaryError(f"plan {path} does not encode a JSON object")
    chunks = plan.get("chunks")
    if not isinstance(chunks, list):
        raise SnapshotSummaryError(f"plan {path} missing 'chunks' array")
    return len(chunks)


def remove_output(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "bundle_root",
        type=Path,
        help="Directory containing snapshot manifests and plans",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to write the manifest summary JSON",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Optional target triple to annotate in the summary",
    )
    args = parser.parse_args(argv)

    root = args.bundle_root.resolve()
    if not root.exists():
        raise SnapshotSummaryError(f"bundle root {root} does not exist")

    manifests = sorted(discover_manifests(root), key=lambda record: record.block_height)
    if not manifests:
        # Ensure stale summaries from previous runs are removed.
        remove_output(args.output)
        print(f"No snapshot manifests discovered under {root}, skipping summary generation.")
        return 0

    entries = []
    for record in manifests:
        plan_path = find_plan(root, record.block_height)
        chunk_count = record.data.get("chunk_count")
        plan_relative: Optional[str] = None

        if chunk_count is None:
            if plan_path is None:
                raise SnapshotSummaryError(
                    f"no plan found for snapshot height {record.block_height} in {root}"
                )
            chunk_count = chunk_count_from_plan(plan_path)
            plan_relative = str(plan_path.relative_to(root))
        else:
            plan_relative = str(plan_path.relative_to(root)) if plan_path else None

        if not isinstance(chunk_count, int):
            raise SnapshotSummaryError(
                f"invalid chunk count for manifest {record.path}: {chunk_count!r}"
            )

        entries.append(
            {
                "id": record.snapshot_id,
                "block_height": record.block_height,
                "state_root": record.state_root,
                "chunk_count": chunk_count,
                "manifest": str(record.path.relative_to(root)),
                "plan": plan_relative,
            }
        )

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "bundle_root": str(root),
        "snapshots": entries,
    }
    if args.target:
        summary["target"] = args.target

    output_path = args.output.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")

    print(f"Wrote snapshot manifest summary to {output_path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except SnapshotSummaryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
