#!/usr/bin/env bash
set -euo pipefail

if ! command -v mdbook >/dev/null; then
  echo "mdbook is required; install it with 'cargo install mdbook --locked --version 0.4.40'" >&2
  exit 127
fi

if ! command -v lychee >/dev/null; then
  echo "lychee is required; install it with 'cargo install lychee --locked --version 0.15.1'" >&2
  exit 127
fi

workdir=$(mktemp -d)
cleanup() {
  rm -rf "${workdir}"
}
trap cleanup EXIT

book_root="${workdir}/book"
src_root="${book_root}/src"
mkdir -p "${src_root}/docs"

rsync -a docs/ "${src_root}/docs/"

for file in README.md CONTRIBUTING.md MIGRATION.md; do
  if [[ -f "${file}" ]]; then
    mkdir -p "${src_root}/$(dirname "${file}")"
    cp "${file}" "${src_root}/${file}"
  fi
done

summary_path="${src_root}/SUMMARY.md"
{
  echo "# Summary"
  find "${src_root}" -type f -name '*.md' -not -path "${summary_path}" | sort |
    while read -r path; do
      rel_path=${path#"${src_root}/"}
      title=$(basename "${rel_path}" .md)
      echo "* [${title}](${rel_path})"
    done
} > "${summary_path}"

cat > "${book_root}/book.toml" <<'TOML'
[book]
authors = []
language = "en"
multilingual = false
title = "Documentation checks"
src = "src"

[output.html]

TOML

mdbook build "${book_root}"

mapfile -t targets < <(find docs -type f -name '*.md' | sort)
for top in README.md CONTRIBUTING.md MIGRATION.md; do
  if [[ -f "${top}" ]]; then
    targets+=("${top}")
  fi
done

if ! grep -qi "Proving/verification parameters (no hot reload)" docs/rpp_node_operator_guide.md; then
  echo "rpp_node_operator_guide.md must document that proving/verifying parameters do not support hot reload" >&2
  exit 1
fi

if ! grep -qi "Hot reload status and parameter rotation" docs/runbooks/plonky3.md; then
  echo "plonky3 runbook must describe the absence of hot reload and the rotation workflow" >&2
  exit 1
fi

lychee --include-fragments --scheme file --base . "${targets[@]}"
