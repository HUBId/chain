#!/usr/bin/env python3
"""Verify the integrity of the vendored malachite source tree.

The script hashes all files under the extracted ``src`` directory and compares
those digests against reference values originating either from a saved hash
manifest or from the official crate archive.  A structured JSON report and a
human-readable summary are written to the vendor manifest/log directories.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, Mapping, Tuple


# --- Constants -----------------------------------------------------------------

PACKAGE_NAME = "malachite"
DEFAULT_VERSION = "0.4.18"
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_VENDOR_ROOT = REPO_ROOT / "vendor" / PACKAGE_NAME / DEFAULT_VERSION
DEFAULT_SRC_DIR = DEFAULT_VENDOR_ROOT / "src"
DEFAULT_MANIFEST_DIR = DEFAULT_VENDOR_ROOT / "manifest"
DEFAULT_LOG_DIR = DEFAULT_VENDOR_ROOT / "logs"
DEFAULT_REPORT_JSON = DEFAULT_MANIFEST_DIR / "integrity_report.json"
DEFAULT_REPORT_TEXT = DEFAULT_LOG_DIR / "integrity_report.txt"
DEFAULT_REFERENCE_MANIFEST = DEFAULT_MANIFEST_DIR / "reference_hashes.json"
DEFAULT_CRATE_URL_TEMPLATE = (
    "https://static.crates.io/crates/{name}/{name}-{version}.crate"
)


# --- Helper utilities ----------------------------------------------------------


def utcnow() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""

    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_sha256_for_path(path: Path, chunk_size: int = 1 << 20) -> str:
    """Compute the SHA-256 digest for the given file path."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def compute_sha256_for_bytes_stream(stream, chunk_size: int = 1 << 20) -> str:
    """Compute the SHA-256 digest for the given file-like byte stream."""

    digest = hashlib.sha256()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def normalise_rel_path(path: Path | str) -> str:
    """Normalise relative paths to POSIX form without leading './'."""

    if isinstance(path, Path):
        rel = path.as_posix()
    else:
        rel = Path(path).as_posix()
    if rel.startswith("./"):
        rel = rel[2:]
    return rel


def collect_hashes(root: Path) -> Dict[str, str]:
    """Collect SHA-256 hashes for all files under *root*."""

    if not root.exists():
        raise FileNotFoundError(f"Source directory does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Source path is not a directory: {root}")

    hashes: Dict[str, str] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = normalise_rel_path(path.relative_to(root))
        hashes[rel] = compute_sha256_for_path(path)
    return hashes


def load_reference_manifest(path: Path) -> Tuple[Dict[str, str], str]:
    """Load reference hashes from a JSON manifest.

    The manifest can either be a plain mapping of ``path -> sha256`` entries or a
    dictionary containing a ``files`` object with the same mapping.
    Returns a tuple of the mapping and a description of the source.
    """

    if not path.exists():
        raise FileNotFoundError(f"Reference manifest not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, Mapping) and isinstance(payload.get("files"), Mapping):
        files = payload["files"]
    elif isinstance(payload, Mapping):
        files = payload
    else:
        raise ValueError("Reference manifest must contain a mapping of file hashes")

    reference_hashes = {
        normalise_rel_path(key): str(value)
        for key, value in files.items()
        if isinstance(key, str)
    }
    source_description = f"hash manifest {path}"
    return reference_hashes, source_description


def collect_hashes_from_dir(path: Path) -> Tuple[Dict[str, str], str]:
    """Collect reference hashes from an extracted crate directory."""

    if not path.exists():
        raise FileNotFoundError(f"Reference directory does not exist: {path}")

    # Support pointing either to the crate root or directly to its ``src`` folder.
    candidate_root = path
    if (path / "src").is_dir():
        candidate_root = path
    elif any((path / sub).is_dir() for sub in ("src", "tests", "benches")):
        candidate_root = path
    elif path.name == "src" and path.parent.exists():
        candidate_root = path.parent

    hashes = collect_hashes(candidate_root)
    source_description = f"extracted crate at {candidate_root}"
    return hashes, source_description


def collect_hashes_from_crate_archive(
    path: Path, *, version: str, package: str
) -> Tuple[Dict[str, str], str]:
    """Collect hashes by inspecting a ``.crate`` tarball."""

    if not path.exists():
        raise FileNotFoundError(f"Crate archive not found: {path}")

    prefix = f"{package}-{version}/"
    hashes: Dict[str, str] = {}

    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            member_path = member.name
            if not member_path.startswith(prefix):
                continue
            relative_path = member_path[len(prefix) :]
            # Skip directories and empty names that might result from stripping the prefix.
            if not relative_path:
                continue
            fileobj = archive.extractfile(member)
            if fileobj is None:
                continue
            digest = compute_sha256_for_bytes_stream(fileobj)
            hashes[normalise_rel_path(relative_path)] = digest

    source_description = f"crate archive {path}"
    return hashes, source_description


def download_crate(
    *,
    url: str,
    package: str,
    version: str,
) -> Tuple[Path, tempfile.NamedTemporaryFile]:
    """Download the crate archive and return its path and the temporary handle."""

    tmp_handle = tempfile.NamedTemporaryFile(
        prefix=f"{package}-{version}-", suffix=".crate", delete=False
    )
    try:
        with urllib.request.urlopen(url) as response:
            tmp_handle.write(response.read())
    except Exception:
        tmp_handle.close()
        os.unlink(tmp_handle.name)
        raise

    tmp_handle.flush()
    tmp_handle.close()
    return Path(tmp_handle.name), tmp_handle


def determine_reference_hashes(
    *,
    reference_manifest: Path | None,
    reference_dir: Path | None,
    crate_path: Path | None,
    crate_url: str,
    allow_download: bool,
    version: str,
    package: str,
) -> Tuple[Dict[str, str], str, tempfile.NamedTemporaryFile | None]:
    """Resolve the reference hash mapping based on the available inputs."""

    if reference_manifest and reference_manifest.exists():
        hashes, source = load_reference_manifest(reference_manifest)
        return hashes, source, None

    if reference_dir:
        hashes, source = collect_hashes_from_dir(reference_dir)
        return hashes, source, None

    if crate_path:
        hashes, source = collect_hashes_from_crate_archive(
            crate_path, version=version, package=package
        )
        return hashes, source, None

    if not allow_download:
        raise RuntimeError("No reference hashes available and downloads are disabled")

    archive_path, tmp_handle = download_crate(
        url=crate_url, package=package, version=version
    )
    hashes, source = collect_hashes_from_crate_archive(
        archive_path, version=version, package=package
    )
    return hashes, f"downloaded {source}", tmp_handle


def compare_hashes(
    *, actual: Mapping[str, str], reference: Mapping[str, str]
) -> Tuple[str, Dict[str, Dict[str, str]]]:
    """Compare actual hashes with reference values.

    Returns a tuple containing the overall status (``"pass"``/``"fail"``) and a
    mapping with per-file comparison results.
    """

    results: Dict[str, Dict[str, str]] = {}
    all_paths = sorted(set(actual) | set(reference))
    mismatches = False

    for rel_path in all_paths:
        actual_hash = actual.get(rel_path)
        expected_hash = reference.get(rel_path)
        if actual_hash is None:
            status = "missing_in_vendor"
            mismatches = True
        elif expected_hash is None:
            status = "missing_in_reference"
            mismatches = True
        elif actual_hash == expected_hash:
            status = "match"
        else:
            status = "mismatch"
            mismatches = True

        results[rel_path] = {
            "status": status,
            "actual": actual_hash,
            "expected": expected_hash,
        }

    overall_status = "fail" if mismatches else "pass"
    return overall_status, results


def summarise_results(results: Mapping[str, Mapping[str, str]]) -> Dict[str, int]:
    """Compute summary statistics for the comparison results."""

    summary = {"total": 0, "match": 0, "mismatch": 0, "missing_in_vendor": 0, "missing_in_reference": 0}
    for entry in results.values():
        status = entry.get("status") or ""
        summary["total"] += 1
        if status in summary:
            summary[status] += 1
    return summary


def write_json_report(
    path: Path,
    *,
    version: str,
    generated_at: str,
    source_description: str,
    overall_status: str,
    summary: Mapping[str, int],
    results: Mapping[str, Mapping[str, str]],
    actual_hashes: Mapping[str, str],
    reference_hashes: Mapping[str, str],
) -> None:
    """Persist the structured integrity report as JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "package": PACKAGE_NAME,
        "version": version,
        "generated_at": generated_at,
        "reference_source": source_description,
        "status": overall_status,
        "summary": dict(summary),
        "results": results,
        "actual_hashes": dict(actual_hashes),
        "reference_hashes": dict(reference_hashes),
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def write_text_summary(
    path: Path,
    *,
    version: str,
    generated_at: str,
    source_description: str,
    overall_status: str,
    summary: Mapping[str, int],
    results: Mapping[str, Mapping[str, str]],
) -> None:
    """Write a human-readable summary of the verification process."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"Integrity Report for {PACKAGE_NAME} {version}",
        f"Generated at: {generated_at}",
        f"Reference source: {source_description}",
        f"Overall result: {overall_status.upper()}",
        "",
        "Checksum summary:",
        f"  Total files processed: {summary.get('total', 0)}",
        f"  Matching files: {summary.get('match', 0)}",
        f"  Mismatched files: {summary.get('mismatch', 0)}",
        f"  Missing in vendor: {summary.get('missing_in_vendor', 0)}",
        f"  Missing in reference: {summary.get('missing_in_reference', 0)}",
        "",
        "Per-file details:",
    ]

    for rel_path in sorted(results):
        entry = results[rel_path]
        status = entry.get("status", "unknown").upper()
        actual_hash = entry.get("actual") or "-"
        expected_hash = entry.get("expected") or "-"
        lines.append(
            f"  {rel_path}: {status} (actual={actual_hash}, expected={expected_hash})"
        )

    with path.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# --- CLI handling --------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        default=DEFAULT_VERSION,
        help="Malachite crate version to verify (default: %(default)s)",
    )
    parser.add_argument(
        "--src-dir",
        type=Path,
        default=DEFAULT_SRC_DIR,
        help="Directory containing the extracted crate files (default: %(default)s)",
    )
    parser.add_argument(
        "--report-json",
        type=Path,
        default=DEFAULT_REPORT_JSON,
        help="Path to write the JSON integrity report (default: %(default)s)",
    )
    parser.add_argument(
        "--report-text",
        type=Path,
        default=DEFAULT_REPORT_TEXT,
        help="Path to write the human-readable summary (default: %(default)s)",
    )
    parser.add_argument(
        "--reference-manifest",
        type=Path,
        default=DEFAULT_REFERENCE_MANIFEST,
        help="Optional JSON file containing reference hashes",
    )
    parser.add_argument(
        "--reference-dir",
        type=Path,
        help="Optional directory with an extracted crate to use as reference",
    )
    parser.add_argument(
        "--crate-path",
        type=Path,
        help="Optional path to a .crate archive to use as reference",
    )
    parser.add_argument(
        "--crate-url",
        default=None,
        help="Override the download URL for the crate archive",
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Disable automatic crate downloads when no reference data is available",
    )
    return parser.parse_args()


# --- Main entry point ----------------------------------------------------------


def main() -> int:
    args = parse_args()

    version = args.version
    package = PACKAGE_NAME

    crate_url = args.crate_url or DEFAULT_CRATE_URL_TEMPLATE.format(
        name=package, version=version
    )

    generated_at = utcnow()

    try:
        actual_hashes = collect_hashes(args.src_dir)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"ERROR: {exc}")
        return 2

    tmp_handle = None
    try:
        reference_hashes, source_description, tmp_handle = determine_reference_hashes(
            reference_manifest=args.reference_manifest,
            reference_dir=args.reference_dir,
            crate_path=args.crate_path,
            crate_url=crate_url,
            allow_download=not args.no_download,
            version=version,
            package=package,
        )
    except Exception as exc:
        print(f"ERROR: failed to obtain reference hashes: {exc}")
        return 3

    overall_status, results = compare_hashes(
        actual=actual_hashes, reference=reference_hashes
    )
    summary = summarise_results(results)

    write_json_report(
        args.report_json,
        version=version,
        generated_at=generated_at,
        source_description=source_description,
        overall_status=overall_status,
        summary=summary,
        results=results,
        actual_hashes=actual_hashes,
        reference_hashes=reference_hashes,
    )
    write_text_summary(
        args.report_text,
        version=version,
        generated_at=generated_at,
        source_description=source_description,
        overall_status=overall_status,
        summary=summary,
        results=results,
    )

    if tmp_handle is not None:
        try:
            os.unlink(tmp_handle.name)
        except OSError:
            pass

    return 0 if overall_status == "pass" else 1


if __name__ == "__main__":
    os._exit(main())
