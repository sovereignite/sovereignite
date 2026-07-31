#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
SSH_USER="${SSH_USER:-core}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require yq
require ssh

mapfile -t nodes < <(yq -r '.spec.nodes[].name' "${INVENTORY}")

for node in "${nodes[@]}"; do
  ip="$(NODE_NAME="${node}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .ip' "${INVENTORY}")"
  echo "checking ${node} (${ip})"
  ssh "${SSH_USER}@${ip}" 'set -euo pipefail
    test -e /dev/tpmrm0 -o -e /dev/tpm0
    secure_boot_var="$(find /sys/firmware/efi/efivars -name "SecureBoot-*" -print -quit)"
    test -n "${secure_boot_var}"
    secure_boot_state="$(od -An -t u1 "${secure_boot_var}" | awk "{print \$5}")"
    test "${secure_boot_state}" = "1"
    systemctl is-active --quiet containerd
    systemctl is-active --quiet kubelet
    systemctl is-active --quiet locksmithd
  '
done
