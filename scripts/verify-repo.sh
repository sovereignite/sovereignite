#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OVERLAY="${ROOT_DIR}/k8s/overlays/local"
RENDERED="${TMPDIR:-/tmp}/sovereignite-local.yaml"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require kustomize

if command -v tofu >/dev/null 2>&1; then
  tofu fmt -check -recursive "${ROOT_DIR}/infra/libvirt"
fi

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "${ROOT_DIR}"/scripts/*.sh
fi

if command -v go >/dev/null 2>&1 && [ -f "${ROOT_DIR}/go.mod" ]; then
  GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/sovereignite-go-build-cache}" go test "${ROOT_DIR}/controllers/..."
fi

if command -v rg >/dev/null 2>&1; then
  mapfile -t local_kustomization_files < <(
    find "${OVERLAY}" -name kustomization.yaml -print
    find "${ROOT_DIR}/k8s/components" -path '*/base/kustomization.yaml' -print
    find "${ROOT_DIR}/k8s/components" -path '*/base/upstream/kustomization.yaml' -print
  )
  if rg -n 'https?://|helmCharts:|repo:' "${local_kustomization_files[@]}"; then
    echo "local overlays/bases must not reference remotes or Helm repos" >&2
    exit 1
  fi
fi

kustomize build "${OVERLAY}" > "${RENDERED}"

if [ "${VERIFY_KUBECTL:-0}" = "1" ] && command -v kubectl >/dev/null 2>&1; then
  kubectl apply --dry-run=client --validate=false -f "${RENDERED}" >/dev/null
fi

echo "repo validation passed: ${RENDERED}"
