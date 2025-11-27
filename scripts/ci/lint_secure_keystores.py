#!/usr/bin/env python3
"""Validate secure key storage defaults for production config templates."""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - stdlib in Python 3.11+
    raise SystemExit("tomllib is required to lint keystore settings") from exc

ALLOWED_BACKENDS = {"hsm", "vault"}
PRODUCTION_CONFIGS = [
    Path("config/examples/production/validator-plonky3-tls.toml"),
    Path("config/examples/production/validator-stwo-tls.toml"),
    Path("config/examples/high-throughput.toml"),
]

ALLOW_INSECURE = os.environ.get("ALLOW_INSECURE_KEY_STORAGE", "").lower() in {
    "1",
    "true",
    "yes",
}


def _non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _error(message: str, *, path: Path | None = None) -> str:
    if path:
        return f"::error file={path}::{message}"
    return f"::error ::{message}"


def _validate_hsm(path: Path, secrets: dict, errors: list[str]) -> None:
    hsm_cfg = secrets.get("hsm") or {}
    if not _non_empty_string(hsm_cfg.get("library_path")):
        errors.append(
            _error(
                "[secrets.hsm].library_path must point to the production PKCS#11 library",
                path=path,
            )
        )
    if not _non_empty_string(hsm_cfg.get("key_id")):
        errors.append(
            _error(
                "[secrets.hsm].key_id must be set so the runtime binds to the provisioned slot",
                path=path,
            )
        )


def _validate_config(path: Path) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        errors.append(_error("config file is missing", path=path))
        return errors

    try:
        config = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        errors.append(_error(f"failed to parse TOML: {exc}", path=path))
        return errors

    secrets = config.get("secrets")
    if not isinstance(secrets, dict):
        errors.append(_error("[secrets] block is required", path=path))
        return errors

    backend = secrets.get("backend")
    if backend not in ALLOWED_BACKENDS:
        errors.append(
            _error(
                f"secrets.backend must be one of {sorted(ALLOWED_BACKENDS)}, found {backend!r}",
                path=path,
            )
        )
        return errors

    if backend == "hsm":
        _validate_hsm(path, secrets, errors)

    return errors


def main() -> int:
    if ALLOW_INSECURE:
        print(
            "ALLOW_INSECURE_KEY_STORAGE is set; skipping secure keystore lint (intended for development)."
        )
        return 0

    all_errors: list[str] = []
    for config_path in PRODUCTION_CONFIGS:
        all_errors.extend(_validate_config(config_path))

    if all_errors:
        for message in all_errors:
            print(message, file=sys.stderr)
        print(
            "Secure keystore validation failed. Set ALLOW_INSECURE_KEY_STORAGE=1 to bypass during development.",
            file=sys.stderr,
        )
        return 1

    print("Secure keystore validation passed for production config templates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
