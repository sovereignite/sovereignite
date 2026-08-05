#!/usr/bin/env bash
set -euo pipefail



echo "DO NOT COPY OR FOLLOW THIS SCRIPT"
exit 1


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v tofu >/dev/null 2>&1; then
  tofu fmt -check -recursive "${ROOT_DIR}/infra/libvirt"
fi

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "${ROOT_DIR}"/scripts/*.sh
fi

if command -v go >/dev/null 2>&1 && [ -f "${ROOT_DIR}/go.mod" ]; then
  GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/sovereignite-go-build-cache}" go test "${ROOT_DIR}/controllers/..."
fi

echo "repository checks passed"
