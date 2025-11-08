#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <firewood-storage-dir> <backup-dir>" >&2
  exit 1
fi

storage_dir="$1"
backup_dir="$2"

snapshots_dir="$storage_dir/cf_pruning_snapshots"
proofs_dir="$storage_dir/cf_pruning_proofs"
meta_dir="$storage_dir/cf_meta"

mkdir -p "$backup_dir"

python3 - "$snapshots_dir" "$proofs_dir" "$meta_dir" "$backup_dir" <<'PY'
import hashlib
import json
import pathlib
import shutil
import sys

snapshots = pathlib.Path(sys.argv[1])
proofs = pathlib.Path(sys.argv[2])
meta = pathlib.Path(sys.argv[3])
dest = pathlib.Path(sys.argv[4])

if not snapshots.exists():
    raise SystemExit(f"missing snapshots directory: {snapshots}")
if not proofs.exists():
    raise SystemExit(f"missing proofs directory: {proofs}")

manifests_dest = dest / "manifests"
proofs_dest = dest / "proofs"
meta_dest = dest / "meta"

manifests_dest.mkdir(parents=True, exist_ok=True)
proofs_dest.mkdir(parents=True, exist_ok=True)
meta_dest.mkdir(parents=True, exist_ok=True)

for manifest_path in sorted(snapshots.glob("*.json")):
    data = json.loads(manifest_path.read_text())
    proof_file = data.get("proof_file")
    if not proof_file:
        raise SystemExit(f"manifest {manifest_path.name} missing proof_file")
    proof_path = proofs / proof_file
    if not proof_path.exists():
        raise SystemExit(f"proof missing for manifest {manifest_path.name}")
    checksum = hashlib.sha256(proof_path.read_bytes()).hexdigest()
    if checksum != data.get("proof_checksum"):
        raise SystemExit(f"checksum mismatch for {proof_path.name}")
    shutil.copy2(manifest_path, manifests_dest / manifest_path.name)
    sig_path = manifest_path.parent / f"{manifest_path.name}.sig"
    if sig_path.exists():
        shutil.copy2(sig_path, manifests_dest / sig_path.name)
    shutil.copy2(proof_path, proofs_dest / proof_path.name)

for meta_file in ("layout_version.json", "pruner_state.json"):
    src = meta / meta_file
    if src.exists():
        shutil.copy2(src, meta_dest / meta_file)
PY
