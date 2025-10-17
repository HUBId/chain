#!/usr/bin/env python3
"""Decode Base64-encoded vendor assets into their binary form."""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path


def decode_asset(encoded_path: Path, *, force: bool = False) -> Path:
    if encoded_path.suffix != ".b64":
        raise ValueError(f"expected a .b64 file, got {encoded_path}")

    target_path = encoded_path.with_suffix("")
    if target_path.exists() and not force:
        raise FileExistsError(
            f"Refusing to overwrite existing asset {target_path}. "
            "Use --force to rebuild it."
        )

    raw_bytes = base64.b64decode(encoded_path.read_bytes())
    target_path.write_bytes(raw_bytes)
    return target_path


def iter_encoded_files(root: Path):
    for path in root.rglob("*.b64"):
        if path.is_file():
            yield path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Decode base64-encoded vendor assets stored alongside the STWO staging files."
        )
    )
    parser.add_argument(
        "root",
        type=Path,
        help="Root directory containing encoded assets (e.g. vendor/stwo-dev/0.1.1/staging)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite already materialized assets if they exist",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root

    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 1

    encoded_files = list(iter_encoded_files(root))
    if not encoded_files:
        print(f"No encoded assets found under {root}")
        return 0

    for encoded in encoded_files:
        try:
            target = decode_asset(encoded, force=args.force)
        except FileExistsError as exc:
            print(f"skip {encoded}: {exc}")
            continue
        except ValueError as exc:
            print(f"skip {encoded}: {exc}")
            continue
        else:
            print(f"wrote {target}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
