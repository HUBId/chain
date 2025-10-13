#!/usr/bin/env bash
set -euo pipefail

crate="malachite-base"
version="0.4.18"
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/.." && pwd)
vendor_dir="${repo_root}/vendor/malachite-msrv/${crate}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required to download ${crate}" >&2
  exit 1
fi

if ! cargo download --version >/dev/null 2>&1; then
  echo "error: cargo-download is required (install via 'cargo install cargo-download')" >&2
  exit 1
fi

workdir=$(mktemp -d)
trap 'rm -rf "${workdir}"' EXIT

archive="${workdir}/${crate}-${version}.tar.gz"
extract_dir="${workdir}/extracted"
mkdir -p "${extract_dir}"

cargo download "${crate}" --version "${version}" --output "${archive}"

tar -xzf "${archive}" -C "${extract_dir}"

src_dir="${extract_dir}/${crate}-${version}"
if [ ! -d "${src_dir}" ]; then
  echo "error: expected extracted directory ${src_dir} to exist" >&2
  exit 1
fi

mkdir -p "${vendor_dir}"
rm -f "${vendor_dir}/.gitkeep"

rsync -a --delete \
  --exclude '/target/' \
  --exclude '/.fingerprint/' \
  --exclude '/.cargo-ok' \
  --exclude '/.git/' \
  --exclude '/.github/' \
  "${src_dir}/" "${vendor_dir}/"
