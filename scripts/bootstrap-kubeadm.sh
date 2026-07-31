#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
KUBECONFIG_OUT="${KUBECONFIG_OUT:-${ROOT_DIR}/build/kubeconfig/admin.conf}"
SSH_USER="${SSH_USER:-core}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require yq
require ssh
require kubectl

first_cp="$(yq -r '.spec.nodes[] | select(.role == "control-plane") | .name' "${INVENTORY}" | head -n1)"
first_cp_ip="$(NODE_NAME="${first_cp}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .ip' "${INVENTORY}")"

mkdir -p "$(dirname "${KUBECONFIG_OUT}")"

echo "initializing ${first_cp}"
ssh "${SSH_USER}@${first_cp_ip}" 'sudo /opt/sovereignite/bin/bootstrap-node.sh init'
ssh "${SSH_USER}@${first_cp_ip}" 'sudo cat /etc/kubernetes/admin.conf' > "${KUBECONFIG_OUT}"
chmod 0600 "${KUBECONFIG_OUT}"

export KUBECONFIG="${KUBECONFIG_OUT}"
kubectl apply -k "${ROOT_DIR}/k8s/overlays/local"

join_command="$(ssh "${SSH_USER}@${first_cp_ip}" 'sudo /opt/bin/kubeadm token create --print-join-command')"

mapfile -t control_planes < <(yq -r '.spec.nodes[] | select(.role == "control-plane") | .name' "${INVENTORY}" | tail -n +2)
for node in "${control_planes[@]}"; do
  ip="$(NODE_NAME="${node}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .ip' "${INVENTORY}")"
  echo "joining control-plane ${node}"
  ssh "${SSH_USER}@${ip}" "sudo ${join_command} --control-plane"
done

mapfile -t workers < <(yq -r '.spec.nodes[] | select(.role == "worker") | .name' "${INVENTORY}")
for node in "${workers[@]}"; do
  ip="$(NODE_NAME="${node}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .ip' "${INVENTORY}")"
  echo "joining worker ${node}"
  ssh "${SSH_USER}@${ip}" "sudo ${join_command}"
done

kubectl get nodes -o wide
