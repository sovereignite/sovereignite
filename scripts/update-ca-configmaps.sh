#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKI_ROOT="${PKI_ROOT:-${ROOT_DIR}/build/pki}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require kubectl

apply_configmap() {
  local name="$1"
  local file="$2"

  if [ ! -f "${file}" ]; then
    echo "missing CA certificate for ${name}: ${file}" >&2
    exit 66
  fi

  kubectl -n sovereignite-system create configmap "${name}" \
    --from-file=ca.crt="${file}" \
    --dry-run=client \
    -o yaml | kubectl apply -f -
}

apply_configmap kubernetes-ca "${PKI_ROOT}/kubernetes/ca.crt"
apply_configmap cert-manager-local-ca "${PKI_ROOT}/cert-manager/ca.crt"
apply_configmap spire-upstream-ca "${PKI_ROOT}/spire/upstream-ca.crt"

if [ ! -f "${PKI_ROOT}/spire/tpm-devid-ca.crt" ]; then
  echo "missing CA certificate for spire-tpm-attestor-ca: ${PKI_ROOT}/spire/tpm-devid-ca.crt" >&2
  exit 66
fi
if [ ! -f "${PKI_ROOT}/spire/tpm-endorsement-ca.crt" ]; then
  echo "missing CA certificate for spire-tpm-attestor-ca: ${PKI_ROOT}/spire/tpm-endorsement-ca.crt" >&2
  exit 66
fi

kubectl -n spire create configmap spire-tpm-attestor-ca \
  --from-file=tpm-devid-ca.pem="${PKI_ROOT}/spire/tpm-devid-ca.crt" \
  --from-file=tpm-endorsement-ca.pem="${PKI_ROOT}/spire/tpm-endorsement-ca.crt" \
  --dry-run=client \
  -o yaml | kubectl apply -f -
