#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <backup-dir> <firewood-storage-dir>" >&2
  exit 1
fi

backup_dir="$1"
storage_dir="$2"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

python3 - "$backup_dir" "$tmp_dir" <<'PY'
import hashlib
import json
import pathlib
import shutil
import sys

backup = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])

manifests_src = backup / "manifests"
proofs_src = backup / "proofs"
meta_src = backup / "meta"

if not manifests_src.exists():
    raise SystemExit(f"missing manifests directory: {manifests_src}")
if not proofs_src.exists():
    raise SystemExit(f"missing proofs directory: {proofs_src}")

snapshots_dst = target / "cf_pruning_snapshots"
proofs_dst = target / "cf_pruning_proofs"
meta_dst = target / "cf_meta"

snapshots_dst.mkdir(parents=True, exist_ok=True)
proofs_dst.mkdir(parents=True, exist_ok=True)
meta_dst.mkdir(parents=True, exist_ok=True)

for manifest_path in sorted(manifests_src.glob("*.json")):
    data = json.loads(manifest_path.read_text())
    proof_file = data.get("proof_file")
    if not proof_file:
        raise SystemExit(f"manifest {manifest_path.name} missing proof_file")
    proof_path = proofs_src / proof_file
    if not proof_path.exists():
        raise SystemExit(f"missing proof {proof_file}")
    checksum = hashlib.sha256(proof_path.read_bytes()).hexdigest()
    if checksum != data.get("proof_checksum"):
        raise SystemExit(f"checksum mismatch for {proof_file}")
    shutil.copy2(manifest_path, snapshots_dst / manifest_path.name)
    sig_path = manifest_path.parent / f"{manifest_path.name}.sig"
    if sig_path.exists():
        shutil.copy2(sig_path, snapshots_dst / sig_path.name)
    shutil.copy2(proof_path, proofs_dst / proof_path.name)

for meta_file in ("layout_version.json", "pruner_state.json"):
    src = meta_src / meta_file
    if src.exists():
        shutil.copy2(src, meta_dst / meta_file)
PY

mkdir -p "$storage_dir"
rm -rf "$storage_dir/cf_pruning_snapshots" "$storage_dir/cf_pruning_proofs"
rm -rf "$storage_dir/cf_meta"

mv "$tmp_dir/cf_pruning_snapshots" "$storage_dir/"
mv "$tmp_dir/cf_pruning_proofs" "$storage_dir/"
mv "$tmp_dir/cf_meta" "$storage_dir/"
