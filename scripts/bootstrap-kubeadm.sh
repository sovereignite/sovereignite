#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
KUBECONFIG_OUT="${KUBECONFIG_OUT:-${ROOT_DIR}/build/kubeconfig/admin.conf}"
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
require scp
require kubectl
require openssl

ssh_cmd=(ssh -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
scp_cmd=(scp -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
if [ -n "${SSH_KEY}" ]; then
  ssh_cmd+=(-i "${SSH_KEY}" -o IdentitiesOnly=yes)
  scp_cmd+=(-i "${SSH_KEY}" -o IdentitiesOnly=yes)
fi

first_cp="$(yq -r '.spec.nodes[] | select(.role == "control-plane") | .name' "${INVENTORY}" | head -n1)"
first_cp_ip="$(NODE_NAME="${first_cp}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .ip' "${INVENTORY}")"
api_endpoint="$(yq -r '.spec.cluster.apiEndpoint' "${INVENTORY}")"
api_vip="$(yq -r '.spec.cluster.apiVip' "${INVENTORY}")"
api_port="$(yq -r '.spec.cluster.apiServerPort' "${INVENTORY}")"
cri_socket="$(yq -r '.spec.kubeadm.criSocket' "${INVENTORY}")"

mkdir -p "$(dirname "${KUBECONFIG_OUT}")"

ensure_kubelet_unit() {
  local ip="$1"
  local unit_file

  unit_file="$(mktemp)"
  cat > "${unit_file}" <<'EOF_KUBELET_UNIT'
[Unit]
Description=kubelet
Documentation=https://kubernetes.io/docs/
After=containerd.service install-kubernetes-tools.service
Requires=containerd.service

[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
EnvironmentFile=-/etc/sysconfig/kubelet
ExecStart=/opt/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
Restart=always
StartLimitInterval=0
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF_KUBELET_UNIT

  "${scp_cmd[@]}" "${unit_file}" "${SSH_USER}@${ip}:/tmp/sovereignite-kubelet.service"
  "${ssh_cmd[@]}" "${SSH_USER}@${ip}" 'sudo install -m 0644 /tmp/sovereignite-kubelet.service /etc/systemd/system/kubelet.service && sudo systemctl daemon-reload'
  rm -f "${unit_file}"
}

write_join_config() {
  local node="$1"
  local role="$2"
  local ip="$3"
  local token="$4"
  local ca_hash="$5"
  local join_config

  join_config="$(mktemp)"
  {
    cat <<EOF_JOIN
apiVersion: kubeadm.k8s.io/v1beta4
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: ${api_endpoint}:${api_port}
    token: ${token}
    caCertHashes:
      - sha256:${ca_hash}
nodeRegistration:
  name: ${node}
  criSocket: ${cri_socket}
  kubeletExtraArgs:
    - name: node-ip
      value: ${ip}
EOF_JOIN
    if [ "${role}" = "control-plane" ]; then
      cat <<EOF_CONTROL_PLANE
controlPlane:
  localAPIEndpoint:
    advertiseAddress: ${ip}
    bindPort: ${api_port}
EOF_CONTROL_PLANE
    fi
  } > "${join_config}"

  "${scp_cmd[@]}" "${join_config}" "${SSH_USER}@${ip}:/tmp/sovereignite-join.yaml"
  "${ssh_cmd[@]}" "${SSH_USER}@${ip}" 'sudo install -m 0600 /tmp/sovereignite-join.yaml /etc/kubernetes/join.yaml'
  rm -f "${join_config}"
}

echo "initializing ${first_cp}"
ensure_kubelet_unit "${first_cp_ip}"
if "${ssh_cmd[@]}" "${SSH_USER}@${first_cp_ip}" 'sudo test -f /etc/kubernetes/manifests/kube-apiserver.yaml'; then
  echo "${first_cp} already has kube-apiserver manifest"
else
  "${ssh_cmd[@]}" "${SSH_USER}@${first_cp_ip}" 'sudo systemctl stop kubelet || true; sudo env PATH=/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /opt/sovereignite/bin/bootstrap-node.sh init'
fi
"${ssh_cmd[@]}" "${SSH_USER}@${first_cp_ip}" 'sudo cat /etc/kubernetes/admin.conf' > "${KUBECONFIG_OUT}"
SERVER_URL="https://${api_vip}:${api_port}" yq -i '.clusters[0].cluster.server = strenv(SERVER_URL)' "${KUBECONFIG_OUT}"
chmod 0600 "${KUBECONFIG_OUT}"

export KUBECONFIG="${KUBECONFIG_OUT}"

join_token="$("${ssh_cmd[@]}" "${SSH_USER}@${first_cp_ip}" 'sudo /opt/bin/kubeadm token create --ttl 2h')"
ca_hash="$(openssl x509 -pubkey -in "${ROOT_DIR}/build/pki/kubernetes/ca.crt" -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print $2}')"

mapfile -t control_planes < <(yq -r '.spec.nodes[] | select(.role == "control-plane") | .name' "${INVENTORY}" | tail -n +2)
for node in "${control_planes[@]}"; do
  ip="$(NODE_NAME="${node}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .ip' "${INVENTORY}")"
  echo "joining control-plane ${node}"
  if kubectl get node "${node}" >/dev/null 2>&1; then
    echo "${node} already joined"
    continue
  fi
  ensure_kubelet_unit "${ip}"
  write_join_config "${node}" "control-plane" "${ip}" "${join_token}" "${ca_hash}"
  "${ssh_cmd[@]}" "${SSH_USER}@${ip}" 'sudo systemctl stop kubelet || true; sudo env PATH=/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /opt/bin/kubeadm join --config /etc/kubernetes/join.yaml --ignore-preflight-errors=FileAvailable--etc-kubernetes-kubelet.conf,FileAvailable--etc-kubernetes-pki-ca.crt'
done

mapfile -t workers < <(yq -r '.spec.nodes[] | select(.role == "worker") | .name' "${INVENTORY}")
for node in "${workers[@]}"; do
  ip="$(NODE_NAME="${node}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .ip' "${INVENTORY}")"
  echo "joining worker ${node}"
  if kubectl get node "${node}" >/dev/null 2>&1; then
    echo "${node} already joined"
    continue
  fi
  ensure_kubelet_unit "${ip}"
  write_join_config "${node}" "worker" "${ip}" "${join_token}" "${ca_hash}"
  "${ssh_cmd[@]}" "${SSH_USER}@${ip}" 'sudo systemctl stop kubelet || true; sudo env PATH=/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /opt/bin/kubeadm join --config /etc/kubernetes/join.yaml --ignore-preflight-errors=FileAvailable--etc-kubernetes-kubelet.conf,FileAvailable--etc-kubernetes-pki-ca.crt'
done

kubectl apply -k "${ROOT_DIR}/k8s/overlays/local"
"${ROOT_DIR}/scripts/update-ca-configmaps.sh"
kubectl wait --for=condition=Ready nodes --all --timeout=15m
kubectl get nodes -o wide
