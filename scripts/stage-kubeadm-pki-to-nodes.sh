#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
PKI_ROOT="${PKI_ROOT:-${ROOT_DIR}/build/pki/nodes}"
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
  pki_dir="${node_dir}/pki"
  etc_dir="${node_dir}/etc-kubernetes"

  if [ ! -d "${pki_dir}" ]; then
    echo "missing node PKI directory: ${pki_dir}" >&2
    exit 66
  fi
  if [ ! -d "${etc_dir}" ]; then
    echo "missing node kubeconfig directory: ${etc_dir}" >&2
    exit 66
  fi
  if find "${node_dir}" -type f \( -name 'ca.key' -o -name '*-ca.key' \) | grep -q .; then
    echo "refusing to stage CA private key from ${node_dir}" >&2
    exit 65
  fi

  mapfile -d '' -t kubeconfigs < <(find "${etc_dir}" -maxdepth 1 -type f -name '*.conf' -printf '%f\0' | sort -z)
  if [ "${#kubeconfigs[@]}" -eq 0 ]; then
    echo "missing kubeconfig files in ${etc_dir}" >&2
    exit 66
  fi

  echo "staging kubeadm PKI for ${node}"
  tar -C "${pki_dir}" --exclude='*.csr' -cf - . | "${ssh_cmd[@]}" "${SSH_USER}@${ip}" \
    'sudo mkdir -p /etc/kubernetes/pki /opt/sovereignite/pki/kubernetes && sudo tar -C /etc/kubernetes/pki -xf - && sudo cp -a /etc/kubernetes/pki/. /opt/sovereignite/pki/kubernetes/ && sudo find /etc/kubernetes/pki /opt/sovereignite/pki/kubernetes -type f \( -name "ca.key" -o -name "*-ca.key" \) -delete && sudo chown -R root:root /etc/kubernetes/pki /opt/sovereignite/pki/kubernetes && sudo find /etc/kubernetes/pki /opt/sovereignite/pki/kubernetes -type f -name "*.key" -exec chmod 0600 {} + && sudo find /etc/kubernetes/pki /opt/sovereignite/pki/kubernetes -type f ! -name "*.key" -exec chmod 0644 {} +'

  tar -C "${etc_dir}" -cf - "${kubeconfigs[@]}" | "${ssh_cmd[@]}" "${SSH_USER}@${ip}" \
    'sudo mkdir -p /etc/kubernetes && sudo tar -C /etc/kubernetes -xf - && sudo chown root:root /etc/kubernetes/*.conf && sudo find /etc/kubernetes -maxdepth 1 -type f -name "*.conf" -exec chmod 0600 {} +'
done
