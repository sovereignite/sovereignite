#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
TEMPLATE="${ROOT_DIR}/infra/libvirt/butane/node.bu.tmpl"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/infra/libvirt/build/ignition}"
SHARE_DIR="${SHARE_DIR:-${ROOT_DIR}/infra/libvirt/build/shares}"

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
require jq
require gzip

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
SSH_AUTHORIZED_KEYS_B64="$(printf '%s\n' "${SSH_AUTHORIZED_KEY}" | base64 -w0)"

mkdir -p "${OUT_DIR}" "${SHARE_DIR}"

cluster_name="$(yq -r '.metadata.name' "${INVENTORY}")"
kubernetes_version="$(yq -r '.spec.versions.kubernetes' "${INVENTORY}")"
butane_variant="$(yq -r '.spec.nodeOs.butane.variant // "flatcar"' "${INVENTORY}")"
butane_version="$(yq -r '.spec.nodeOs.butane.version // "1.0.0"' "${INVENTORY}")"
networkd_enabled="false"
if [ "${butane_variant}" = "flatcar" ]; then
  networkd_enabled="true"
fi
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
export SSH_AUTHORIZED_KEY SSH_AUTHORIZED_KEYS_B64 HOSTS_B64
export KUBERNETES_VERSION="${kubernetes_version}"
export BUTANE_VARIANT="${butane_variant}"
export BUTANE_VERSION="${butane_version}"
export NETWORKD_ENABLED="${networkd_enabled}"

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
version = 3

[plugins."io.containerd.cri.v1.images".pinned_images]
  sandbox = "registry.k8s.io/pause:3.10"

[plugins."io.containerd.cri.v1.runtime".containerd]
  default_runtime_name = "runc"

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
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
    - name: volume-plugin-dir
      value: /var/lib/kubelet/volumeplugins/
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
    - name: flex-volume-plugin-dir
      value: /var/lib/kubelet/volumeplugins/
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
    - name: volume-plugin-dir
      value: /var/lib/kubelet/volumeplugins/
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

  envsubst '${BUTANE_VARIANT} ${BUTANE_VERSION} ${NETWORKD_ENABLED} ${SSH_AUTHORIZED_KEY} ${SSH_AUTHORIZED_KEYS_B64} ${HOSTS_B64} ${KUBERNETES_VERSION} ${NODE_NAME} ${ROLE} ${NODE_IP} ${NETWORKD_B64} ${NODE_ENV_B64} ${CONTAINERD_CONFIG_B64} ${KUBEADM_CONFIG_B64}' \
    < "${TEMPLATE}" > "${butane_file}"

  ignition_file="${OUT_DIR}/${NODE_NAME}.ign"
  butane --strict --pretty "${butane_file}" > "${ignition_file}"
  node_share_dir="${SHARE_DIR}/${NODE_NAME}"
  mkdir -p \
    "${node_share_dir}/ignition" \
    "${node_share_dir}/home/core/.ssh" \
    "${node_share_dir}/etc" \
    "${node_share_dir}/etc/systemd/network" \
    "${node_share_dir}/etc/modules-load.d" \
    "${node_share_dir}/etc/sysctl.d" \
    "${node_share_dir}/etc/ssh/sshd_config.d" \
    "${node_share_dir}/etc/sovereignite" \
    "${node_share_dir}/etc/containerd" \
    "${node_share_dir}/etc/kubernetes" \
    "${node_share_dir}/etc/systemd/system" \
    "${node_share_dir}/opt/sovereignite/bin"
  cp "${ignition_file}" "${node_share_dir}/ignition/config.ign"
  printf '%s\n' "${SSH_AUTHORIZED_KEY}" > "${node_share_dir}/home/core/.ssh/authorized_keys"
  printf '%s' "${NODE_NAME}" > "${node_share_dir}/etc/hostname"
  cp "${hosts_file}" "${node_share_dir}/etc/hosts"
  cp "${networkd_file}" "${node_share_dir}/etc/systemd/network/10-sovereignite.network"
  printf 'br_netfilter\noverlay\n' > "${node_share_dir}/etc/modules-load.d/99-kubernetes.conf"
  cat > "${node_share_dir}/etc/sysctl.d/99-kubernetes.conf" <<'EOF_SYSCTL'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF_SYSCTL
  cat > "${node_share_dir}/etc/ssh/sshd_config.d/40-sovereignite-lockdown.conf" <<'EOF_SSHD'
PasswordAuthentication no
PermitRootLogin no
KbdInteractiveAuthentication no
EOF_SSHD
  cp "${node_env_file}" "${node_share_dir}/etc/sovereignite/node.env"
  cp "${containerd_file}" "${node_share_dir}/etc/containerd/config.toml"
  cp "${kubeadm_file}" "${node_share_dir}/etc/kubernetes/kubeadm.yaml"
  jq -r '.storage.files[] | select(.path == "/opt/sovereignite/bin/bootstrap-node.sh") | .contents.source' "${ignition_file}" \
    | sed 's|^data:;base64,||' \
    | base64 -d \
    | gzip -dc > "${node_share_dir}/opt/sovereignite/bin/bootstrap-node.sh"
  chmod 0755 "${node_share_dir}/opt/sovereignite/bin/bootstrap-node.sh"
  jq -r '.systemd.units[] | select(.contents != null) | @base64' "${ignition_file}" | while read -r unit_b64; do
    unit_name="$(printf '%s' "${unit_b64}" | base64 -d | jq -r '.name')"
    printf '%s' "${unit_b64}" | base64 -d | jq -r '.contents' > "${node_share_dir}/etc/systemd/system/${unit_name}"
  done
  echo "rendered ${ignition_file}"
done
