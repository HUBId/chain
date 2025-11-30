#!/usr/bin/env python3
"""Generate OpenAPI/JSON schema snapshots for node and wallet RPCs."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
RPC_DIR = ROOT / "docs" / "interfaces" / "rpc"
SNAPSHOT_DIR = ROOT / "docs" / "interfaces" / "snapshots"
VERSIONS_PATH = ROOT / "docs" / "interfaces" / "schema_versions.toml"
WALLET_SCHEMAS = {
    "error_response",
    "pipeline_wait_request",
    "pipeline_wait_response",
    "sign_tx_request",
    "sign_tx_response",
}


def load_versions() -> dict[str, str]:
    with VERSIONS_PATH.open("rb") as handle:
        return tomllib.load(handle)


def load_schema_files() -> tuple[dict[str, dict], dict[str, dict]]:
    node: dict[str, dict] = {}
    wallet: dict[str, dict] = {}

    for path in sorted(RPC_DIR.glob("*.jsonschema")):
        stem = path.stem
        with path.open("r", encoding="utf-8") as handle:
            schema = json.load(handle)

        if stem in WALLET_SCHEMAS:
            wallet[stem] = schema
        if stem == "error_response" or stem not in WALLET_SCHEMAS:
            node[stem] = schema

    if not node:
        raise SystemExit(f"no RPC schemas found in {RPC_DIR}")

    return node, wallet


def write_json(path: Path, payload: dict) -> None:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def git_status(paths: list[Path]) -> list[str]:
    cmd = ["git", "status", "--porcelain", "--", *[str(path) for path in paths]]
    result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=True)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if snapshots drift from the working tree")
    args = parser.parse_args()

    versions = load_versions()
    node_schemas, wallet_schemas = load_schema_files()

    node_openapi = {
        "components": {"schemas": node_schemas},
        "info": {
            "description": "Snapshot generated from docs/interfaces/rpc JSON Schemas.",
            "title": "RPP Node RPC",
            "version": versions.get("node", "0.0.0"),
        },
        "openapi": "3.1.0",
        "paths": {},
        "x-generated-by": {"command": "python scripts/generate_api_schemas.py", "source": "docs/interfaces/rpc"},
    }
    wallet_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "definitions": wallet_schemas,
        "description": "Snapshot of wallet JSON-RPC contracts derived from docs/interfaces/rpc JSON Schemas.",
        "title": "RPP Wallet RPC",
        "version": versions.get("wallet", "0.0.0"),
        "x-generated-by": {"command": "python scripts/generate_api_schemas.py", "source": "docs/interfaces/rpc"},
    }

    write_json(SNAPSHOT_DIR / "node_openapi.json", node_openapi)
    write_json(SNAPSHOT_DIR / "wallet_rpc.schema.json", wallet_schema)

    if args.check:
        snapshot_changes = git_status([SNAPSHOT_DIR])
        if not snapshot_changes:
            return 0

        version_changes = git_status([VERSIONS_PATH])
        if not version_changes:
            raise SystemExit(
                "API schemas changed without bumping docs/interfaces/schema_versions.toml; "
                "update the relevant version and re-run the generator."
            )
        raise SystemExit("API schema snapshots are out of date; commit the regenerated files.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
