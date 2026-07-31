#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
TEMPLATE="${ROOT_DIR}/infra/libvirt/butane/node.bu.tmpl"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/infra/libvirt/build/ignition}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require yq
require envsubst
require base64
require butane

if [ ! -f "${INVENTORY}" ]; then
  echo "inventory not found: ${INVENTORY}" >&2
  exit 66
fi

SSH_AUTHORIZED_KEY="${SSH_AUTHORIZED_KEY:-}"
if [ -z "${SSH_AUTHORIZED_KEY}" ] && [ -f "${HOME}/.ssh/id_ed25519.pub" ]; then
  SSH_AUTHORIZED_KEY="$(cat "${HOME}/.ssh/id_ed25519.pub")"
fi
if [ -z "${SSH_AUTHORIZED_KEY}" ]; then
  echo "set SSH_AUTHORIZED_KEY or create ~/.ssh/id_ed25519.pub" >&2
  exit 64
fi

mkdir -p "${OUT_DIR}"

cluster_name="$(yq -r '.metadata.name' "${INVENTORY}")"
kubernetes_version="$(yq -r '.spec.versions.kubernetes' "${INVENTORY}")"
api_endpoint="$(yq -r '.spec.cluster.apiEndpoint' "${INVENTORY}")"
api_vip="$(yq -r '.spec.cluster.apiVip' "${INVENTORY}")"
api_port="$(yq -r '.spec.cluster.apiServerPort' "${INVENTORY}")"
dns_domain="$(yq -r '.spec.cluster.dnsDomain' "${INVENTORY}")"
private_dns_suffix="$(yq -r '.spec.cluster.privateDnsSuffix' "${INVENTORY}")"
pod_cidr="$(yq -r '.spec.cluster.podCidr' "${INVENTORY}")"
service_cidr="$(yq -r '.spec.cluster.serviceCidr' "${INVENTORY}")"
cri_socket="$(yq -r '.spec.kubeadm.criSocket' "${INVENTORY}")"
gateway="$(yq -r '.spec.libvirt.network.gateway' "${INVENTORY}")"
dns_servers="$(yq -r '.spec.libvirt.network.dns[]' "${INVENTORY}" | paste -sd ' ' -)"

hosts_file="$(mktemp)"
trap 'rm -f "${hosts_file}" "${networkd_file:-}" "${node_env_file:-}" "${containerd_file:-}" "${kubeadm_file:-}" "${butane_file:-}" "${sans_file:-}"' EXIT

{
  echo "127.0.0.1 localhost"
  echo "::1 localhost"
  echo "${api_vip} ${api_endpoint}"
  PRIVATE_DNS_SUFFIX="${private_dns_suffix}" yq -r '.spec.nodes[] | .ip + " " + .name + "." + strenv(PRIVATE_DNS_SUFFIX) + " " + .name' "${INVENTORY}"
} > "${hosts_file}"

HOSTS_B64="$(base64 -w0 "${hosts_file}")"
export SSH_AUTHORIZED_KEY HOSTS_B64
export KUBERNETES_VERSION="${kubernetes_version}"

mapfile -t node_names < <(yq -r '.spec.nodes[].name' "${INVENTORY}")

for node_name in "${node_names[@]}"; do
  NODE_NAME="${node_name}"
  NODE_IP="$(NODE_NAME="${node_name}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .ip' "${INVENTORY}")"
  ROLE="$(NODE_NAME="${node_name}" yq -r '.spec.nodes[] | select(.name == strenv(NODE_NAME)) | .role' "${INVENTORY}")"

  networkd_file="$(mktemp)"
  node_env_file="$(mktemp)"
  containerd_file="$(mktemp)"
  kubeadm_file="$(mktemp)"
  butane_file="$(mktemp)"
  sans_file="$(mktemp)"

  cat > "${networkd_file}" <<EOF_NETWORKD
[Match]
Name=en*

[Network]
Address=${NODE_IP}/24
Gateway=${gateway}
DNS=${dns_servers}
Domains=${private_dns_suffix}
EOF_NETWORKD

  cat > "${node_env_file}" <<EOF_NODE_ENV
NODE_NAME=${NODE_NAME}
NODE_IP=${NODE_IP}
ROLE=${ROLE}
CLUSTER_NAME=${cluster_name}
API_ENDPOINT=${api_endpoint}
API_VIP=${api_vip}
API_SERVER_PORT=${api_port}
EOF_NODE_ENV

  cat > "${containerd_file}" <<EOF_CONTAINERD
version = 2

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry.k8s.io/pause:3.10"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
EOF_CONTAINERD

  {
    echo "    - ${api_endpoint}"
    echo "    - ${api_vip}"
    PRIVATE_DNS_SUFFIX="${private_dns_suffix}" yq -r '.spec.nodes[] | select(.role == "control-plane") | "    - " + .name + "\n    - " + .name + "." + strenv(PRIVATE_DNS_SUFFIX) + "\n    - " + .ip' "${INVENTORY}"
  } > "${sans_file}"

  if [ "${ROLE}" = "control-plane" ]; then
    cat > "${kubeadm_file}" <<EOF_KUBEADM
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: ${NODE_IP}
  bindPort: ${api_port}
nodeRegistration:
  name: ${NODE_NAME}
  criSocket: ${cri_socket}
  kubeletExtraArgs:
    - name: node-ip
      value: ${NODE_IP}
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
clusterName: ${cluster_name}
kubernetesVersion: ${kubernetes_version}
controlPlaneEndpoint: ${api_endpoint}:${api_port}
certificatesDir: /etc/kubernetes/pki
imageRepository: registry.k8s.io
networking:
  dnsDomain: ${dns_domain}
  podSubnet: ${pod_cidr}
  serviceSubnet: ${service_cidr}
apiServer:
  certSANs:
$(cat "${sans_file}")
controllerManager:
  extraArgs:
    - name: controllers
      value: "*,bootstrapsigner,tokencleaner,-csrsigning"
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
rotateCertificates: true
serverTLSBootstrap: true
EOF_KUBEADM
  else
    cat > "${kubeadm_file}" <<EOF_KUBEADM
apiVersion: kubeadm.k8s.io/v1beta4
kind: JoinConfiguration
discovery:
  file:
    kubeConfigPath: /etc/kubernetes/bootstrap-kubeconfig
nodeRegistration:
  name: ${NODE_NAME}
  criSocket: ${cri_socket}
  kubeletExtraArgs:
    - name: node-ip
      value: ${NODE_IP}
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
rotateCertificates: true
serverTLSBootstrap: true
EOF_KUBEADM
  fi

  NETWORKD_B64="$(base64 -w0 "${networkd_file}")"
  NODE_ENV_B64="$(base64 -w0 "${node_env_file}")"
  CONTAINERD_CONFIG_B64="$(base64 -w0 "${containerd_file}")"
  KUBEADM_CONFIG_B64="$(base64 -w0 "${kubeadm_file}")"
  export NODE_NAME ROLE NODE_IP NETWORKD_B64 NODE_ENV_B64 CONTAINERD_CONFIG_B64 KUBEADM_CONFIG_B64

  envsubst '${SSH_AUTHORIZED_KEY} ${HOSTS_B64} ${KUBERNETES_VERSION} ${NODE_NAME} ${ROLE} ${NODE_IP} ${NETWORKD_B64} ${NODE_ENV_B64} ${CONTAINERD_CONFIG_B64} ${KUBEADM_CONFIG_B64}' \
    < "${TEMPLATE}" > "${butane_file}"

  butane --strict --pretty "${butane_file}" > "${OUT_DIR}/${NODE_NAME}.ign"
  echo "rendered ${OUT_DIR}/${NODE_NAME}.ign"
done
