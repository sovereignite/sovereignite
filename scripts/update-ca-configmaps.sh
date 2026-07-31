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

apply_pin_secret() {
  local namespace="$1"

  kubectl -n "${namespace}" create secret generic tpm2-pkcs11-pin \
    --from-literal=so-pin="${TPM2_PKCS11_SO_PIN}" \
    --from-literal=user-pin="${TPM2_PKCS11_USER_PIN}" \
    --dry-run=client \
    -o yaml | kubectl apply -f -
}

pin_file="${PKI_ROOT}/secrets/tpm2-pkcs11-pin.env"
if [ ! -f "${pin_file}" ]; then
  echo "missing TPM PKCS#11 PIN file: ${pin_file}" >&2
  echo "run scripts/generate-kubeadm-external-pki.sh before updating CA ConfigMaps" >&2
  exit 66
fi
# shellcheck disable=SC1090
. "${pin_file}"
if [ -z "${TPM2_PKCS11_SO_PIN:-}" ] || [ -z "${TPM2_PKCS11_USER_PIN:-}" ]; then
  echo "TPM PIN file must define TPM2_PKCS11_SO_PIN and TPM2_PKCS11_USER_PIN" >&2
  exit 66
fi

apply_configmap sovereignite-root "${PKI_ROOT}/root-ca.crt"
apply_configmap kubernetes-ca "${PKI_ROOT}/kubernetes/ca.crt"
apply_configmap kubernetes-front-proxy-ca "${PKI_ROOT}/kubernetes/front-proxy-ca.crt"
apply_configmap etcd-ca "${PKI_ROOT}/kubernetes/etcd/ca.crt"
apply_configmap cert-manager-local-ca "${PKI_ROOT}/cert-manager/ca.crt"
apply_configmap spire-upstream-ca "${PKI_ROOT}/spire/upstream-ca.crt"
apply_configmap spire-tpm-devid-ca "${PKI_ROOT}/spire/tpm-devid-ca.crt"
apply_configmap spire-tpm-endorsement-ca "${PKI_ROOT}/spire/tpm-endorsement-ca.crt"
apply_pin_secret sovereignite-system
apply_pin_secret spire

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
