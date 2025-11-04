#!/usr/bin/env python3
"""Materialise Plonky3 setup artifacts from official key outputs."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:  # Optional dependency; used only for metadata.
    from blake3 import blake3  # type: ignore
except Exception:  # pragma: no cover - metadata support is best effort.
    blake3 = None  # type: ignore

DEFAULT_CIRCUITS: Tuple[str, ...] = (
    "identity",
    "transaction",
    "state",
    "pruning",
    "recursive",
    "uptime",
    "consensus",
)


@dataclass
class Artifact:
    circuit: str
    verifying_key: bytes
    proving_key: bytes


@dataclass
class ArtifactEncoding:
    encoding: str
    byte_length: int
    value: str
    compression: Optional[str] = None
    hash_blake3: Optional[str] = None

    def to_json(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "encoding": self.encoding,
            "byte_length": self.byte_length,
            "value": self.value,
        }
        if self.compression:
            payload["compression"] = self.compression
        if self.hash_blake3:
            payload["hash_blake3"] = self.hash_blake3
        return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output",
        type=Path,
        help="Directory where JSON artifacts should be written",
    )
    parser.add_argument(
        "--circuits",
        nargs="*",
        default=list(DEFAULT_CIRCUITS),
        help="Subset of circuits to materialise (defaults to all known circuits)",
    )
    parser.add_argument(
        "--generator",
        help=(
            "Command template used to invoke the official key generator. "
            "Use placeholders {circuit}, {verifying_key} and {proving_key}."
        ),
    )
    parser.add_argument(
        "--generator-cwd",
        type=Path,
        help="Working directory to run the generator command from",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        help=(
            "Directory containing pre-built key artifacts. This option is "
            "required when --generator is omitted."
        ),
    )
    parser.add_argument(
        "--verifying-pattern",
        default="{artifact_dir}/{circuit}.vk",
        help="Path pattern for verifying keys when using --artifact-dir",
    )
    parser.add_argument(
        "--proving-pattern",
        default="{artifact_dir}/{circuit}.pk",
        help="Path pattern for proving keys when using --artifact-dir",
    )
    parser.add_argument(
        "--compression",
        choices=("none", "gzip"),
        default="gzip",
        help="Compression applied before base64 serialisation",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output with indentation",
    )
    parser.add_argument(
        "--toolchain-version",
        help="Annotate outputs with the Plonky3 toolchain version",
    )
    parser.add_argument(
        "--git-sha",
        action="append",
        default=[],
        metavar="NAME=SHA",
        help="Record git repository SHAs in metadata (repeatable)",
    )
    parser.add_argument(
        "--signature",
        help="Attach a signature blob to the metadata",
    )
    parser.add_argument(
        "--signature-file",
        type=Path,
        help="Read the signature blob to embed from the provided file",
    )
    parser.add_argument(
        "--signature-output",
        type=Path,
        help="Emit a deterministic manifest for signing to the given path",
    )
    return parser.parse_args()


def ensure_circuits(values: Iterable[str]) -> List[str]:
    circuits = []
    for circuit in values:
        name = circuit.strip()
        if not name:
            raise ValueError("Circuit names must not be empty")
        circuits.append(name)
    return circuits


def invoke_generator(
    command_template: str,
    circuit: str,
    workdir: Optional[Path],
) -> Tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory(prefix=f"plonky3-keygen-{circuit}-") as tmp:
        tmp_path = Path(tmp)
        vk_path = tmp_path / "verifying.key"
        pk_path = tmp_path / "proving.key"
        command = command_template.format(
            circuit=shlex.quote(circuit),
            verifying_key=shlex.quote(str(vk_path)),
            proving_key=shlex.quote(str(pk_path)),
        )
        subprocess.run(
            command,
            shell=True,
            check=True,
            cwd=str(workdir) if workdir else None,
            env=os.environ,
        )
        verifying_key = vk_path.read_bytes()
        proving_key = pk_path.read_bytes()
    return verifying_key, proving_key


def load_from_artifact_dir(
    circuit: str,
    artifact_dir: Path,
    verifying_pattern: str,
    proving_pattern: str,
) -> Tuple[bytes, bytes]:
    context = {
        "artifact_dir": str(artifact_dir),
        "circuit": circuit,
    }
    vk_path = Path(verifying_pattern.format(**context))
    pk_path = Path(proving_pattern.format(**context))
    if not vk_path.exists():
        raise FileNotFoundError(f"Missing verifying key for {circuit} at {vk_path}")
    if not pk_path.exists():
        raise FileNotFoundError(f"Missing proving key for {circuit} at {pk_path}")
    return vk_path.read_bytes(), pk_path.read_bytes()


def encode_bytes(data: bytes, compression: str) -> ArtifactEncoding:
    digest = blake3(data).hexdigest() if blake3 else None
    if compression == "gzip":
        payload = gzip.compress(data)
        value = base64.b64encode(payload).decode("ascii")
        return ArtifactEncoding(
            encoding="base64",
            byte_length=len(data),
            value=value,
            compression="gzip",
            hash_blake3=digest,
        )
    if compression == "none":
        value = base64.b64encode(data).decode("ascii")
        return ArtifactEncoding(
            encoding="base64",
            byte_length=len(data),
            value=value,
            hash_blake3=digest,
        )
    raise ValueError(f"Unsupported compression: {compression}")


def artifact_to_document(
    artifact: Artifact,
    compression: str,
    metadata: Optional[Dict[str, object]],
) -> Dict[str, object]:
    document: "OrderedDict[str, object]" = OrderedDict()
    document["circuit"] = artifact.circuit
    if metadata:
        document["metadata"] = metadata
    verifying_encoding = encode_bytes(artifact.verifying_key, compression)
    proving_encoding = encode_bytes(artifact.proving_key, compression)
    document["verifying_key"] = verifying_encoding.to_json()
    document["proving_key"] = proving_encoding.to_json()
    return document


def emit_artifact(
    output_dir: Path,
    artifact: Artifact,
    compression: str,
    pretty: bool,
    metadata: Optional[Dict[str, object]],
) -> Tuple[Path, str]:
    document = artifact_to_document(artifact, compression, metadata)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{artifact.circuit}.json"
    if pretty:
        serialized = json.dumps(document, indent=2, sort_keys=False)
        serialized += "\n"
    else:
        serialized = json.dumps(document, indent=None, sort_keys=False, separators=(",", ":"))
        serialized = f"{serialized}\n"
    output_path.write_text(serialized, encoding="utf-8")
    return output_path, serialized


def parse_git_shas(values: Iterable[str]) -> "OrderedDict[str, str]":
    mapping: Dict[str, str] = {}
    for entry in values:
        if "=" not in entry:
            raise ValueError(f"--git-sha expects NAME=SHA, received '{entry}'")
        name, sha = entry.split("=", 1)
        key = name.strip()
        value = sha.strip()
        if not key or not value:
            raise ValueError(f"--git-sha expects NAME=SHA, received '{entry}'")
        mapping[key] = value
    ordered = OrderedDict(sorted(mapping.items(), key=lambda item: item[0]))
    return ordered


def build_metadata(args: argparse.Namespace) -> Optional[Dict[str, object]]:
    metadata: "OrderedDict[str, object]" = OrderedDict()
    if args.toolchain_version:
        metadata["toolchain_version"] = args.toolchain_version
    if args.git_sha:
        metadata["git_shas"] = parse_git_shas(args.git_sha)
    signature_payload: Optional[str] = None
    if args.signature and args.signature_file:
        raise ValueError("--signature and --signature-file cannot be combined")
    if args.signature:
        signature_payload = args.signature
    if args.signature_file:
        signature_payload = args.signature_file.read_text(encoding="utf-8").strip()
    if signature_payload:
        metadata["signature"] = signature_payload
    return metadata or None


def write_signature_manifest(
    output_path: Path,
    artifacts: List[Tuple[Path, str]],
    metadata: Optional[Dict[str, object]],
) -> None:
    entries: List[Dict[str, object]] = []
    for path, payload in sorted(artifacts, key=lambda item: item[0].name):
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        entries.append(
            OrderedDict(
                (
                    ("circuit", path.stem),
                    ("file", path.name),
                    ("sha256", digest),
                )
            )
        )
    manifest: "OrderedDict[str, object]" = OrderedDict()
    if metadata:
        manifest["metadata"] = metadata
    manifest["artifacts"] = entries
    output_path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(manifest, indent=2, sort_keys=False)
    output_path.write_text(f"{serialized}\n", encoding="utf-8")


def gather_artifacts(args: argparse.Namespace) -> List[Artifact]:
    circuits = ensure_circuits(args.circuits)
    artifacts: List[Artifact] = []
    for circuit in circuits:
        if args.generator:
            verifying_key, proving_key = invoke_generator(
                args.generator,
                circuit,
                args.generator_cwd,
            )
        else:
            if not args.artifact_dir:
                raise ValueError(
                    "--artifact-dir must be provided when --generator is omitted"
                )
            verifying_key, proving_key = load_from_artifact_dir(
                circuit,
                args.artifact_dir,
                args.verifying_pattern,
                args.proving_pattern,
            )
        artifacts.append(
            Artifact(
                circuit=circuit,
                verifying_key=verifying_key,
                proving_key=proving_key,
            )
        )
    return artifacts


def main() -> None:
    args = parse_args()
    metadata = build_metadata(args)
    artifacts = gather_artifacts(args)
    emitted: List[Tuple[Path, str]] = []
    for artifact in artifacts:
        emitted.append(
            emit_artifact(args.output, artifact, args.compression, args.pretty, metadata)
        )
    if args.signature_output:
        write_signature_manifest(args.signature_output, emitted, metadata)


if __name__ == "__main__":
    main()
