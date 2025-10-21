#!/usr/bin/env python3
"""Generate deterministic Plonky3 setup artifacts.

This helper mimics the output structure expected by the Rust loader while
allowing developers to regenerate the fixtures in a reproducible way.
"""

from __future__ import annotations

import argparse
import json
import hashlib
from pathlib import Path
from typing import Tuple

CIRCUITS: Tuple[Tuple[str, int, int], ...] = (
    ("identity", 96, 192),
    ("transaction", 96, 256),
    ("state", 96, 224),
    ("pruning", 96, 160),
    ("recursive", 96, 288),
    ("uptime", 96, 128),
    ("consensus", 96, 320),
)


def derive_bytes(label: str, length: int) -> bytes:
    """Derive a deterministic byte sequence using BLAKE2b expansions."""

    counter = 0
    chunks: list[bytes] = []
    while sum(len(chunk) for chunk in chunks) < length:
        hasher = hashlib.blake2b(digest_size=64)
        hasher.update(label.encode("utf-8"))
        hasher.update(counter.to_bytes(4, "little"))
        chunks.append(hasher.digest())
        counter += 1
    data = b"".join(chunks)
    return data[:length]


def encode_blob(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def emit_artifact(output_dir: Path, circuit: str, vk_len: int, pk_len: int) -> None:
    verifying_key = encode_blob(derive_bytes(f"{circuit}:verifying", vk_len))
    proving_key = encode_blob(derive_bytes(f"{circuit}:proving", pk_len))
    artifact = {
        "circuit": circuit,
        "verifying_key": {
            "encoding": "base64",
            "value": verifying_key,
        },
        "proving_key": {
            "encoding": "base64",
            "value": proving_key,
        },
    }
    path = output_dir / f"{circuit}.json"
    path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output",
        type=Path,
        help="Directory where the artifacts should be materialised",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir: Path = args.output
    output_dir.mkdir(parents=True, exist_ok=True)
    for circuit, vk_len, pk_len in CIRCUITS:
        emit_artifact(output_dir, circuit, vk_len, pk_len)


if __name__ == "__main__":
    main()
