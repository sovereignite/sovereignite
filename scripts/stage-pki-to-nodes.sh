#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
PKI_ROOT="${PKI_ROOT:-${ROOT_DIR}/build/pki/nodes}"
TPM_DEVID_ROOT="${TPM_DEVID_ROOT:-${ROOT_DIR}/build/pki/tpm-devid}"
SSH_USER="${SSH_USER:-core}"
SSH_KEY="${SSH_KEY:-}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require yq
require ssh
require tar

ssh_cmd=(ssh -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
if [ -n "${SSH_KEY}" ]; then
  ssh_cmd+=(-i "${SSH_KEY}" -o IdentitiesOnly=yes)
fi

mapfile -t nodes < <(yq -r '.spec.nodes[].name' "${INVENTORY}")

for node in "${nodes[@]}"; do
  ip="$(NODE_NAME="${node}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .ip' "${INVENTORY}")"
  node_dir="${PKI_ROOT}/${node}"

  if [ ! -d "${node_dir}" ]; then
    echo "missing node PKI directory: ${node_dir}" >&2
    exit 66
  fi

  devid_dir="${TPM_DEVID_ROOT}/${node}"
  for required in devid.crt devid.priv.blob devid.pub.blob; do
    if [ ! -f "${devid_dir}/${required}" ]; then
      echo "missing TPM DevID material for ${node}: ${devid_dir}/${required}" >&2
      exit 66
    fi
  done

  if find "${node_dir}" -type f \( -name 'ca.key' -o -name '*-ca.key' \) | grep -q .; then
    echo "refusing to stage CA private key from ${node_dir}" >&2
    exit 65
  fi

  echo "staging PKI for ${node}"
  tar -C "${node_dir}" -cf - . | "${ssh_cmd[@]}" "${SSH_USER}@${ip}" 'sudo mkdir -p /opt/sovereignite/pki/kubernetes && sudo tar -C /opt/sovereignite/pki/kubernetes -xf - && sudo find /opt/sovereignite/pki/kubernetes -type f \( -name "ca.key" -o -name "*-ca.key" \) -delete'
  tar -C "${devid_dir}" -cf - devid.crt devid.priv.blob devid.pub.blob | "${ssh_cmd[@]}" "${SSH_USER}@${ip}" 'sudo mkdir -p /var/lib/sovereignite/tpm && sudo tar -C /var/lib/sovereignite/tpm -xf - && sudo chmod 0600 /var/lib/sovereignite/tpm/devid.priv.blob && sudo chmod 0644 /var/lib/sovereignite/tpm/devid.crt /var/lib/sovereignite/tpm/devid.pub.blob'
done
