#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEARCH_ROOTS=(
  "${ROOT_DIR}/build/pki"
  "${ROOT_DIR}/infra/libvirt/build/ignition"
)

found=0
for root in "${SEARCH_ROOTS[@]}"; do
  if [ ! -e "${root}" ]; then
    continue
  fi
  while IFS= read -r key; do
    echo "forbidden CA private key found: ${key}" >&2
    found=1
  done < <(find "${root}" -type f \( -name 'ca.key' -o -name '*-ca.key' \))
done

exit "${found}"
