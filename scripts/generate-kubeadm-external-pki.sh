#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
SHARE_DIR="${SHARE_DIR:-${ROOT_DIR}/infra/libvirt/build/shares}"
OUT_ROOT="${OUT_ROOT:-${ROOT_DIR}/build/pki}"
KUBECONFIG_OUT="${KUBECONFIG_OUT:-${ROOT_DIR}/build/kubeconfig/admin.conf}"
SSH_USER="${SSH_USER:-core}"
SSH_KEY="${SSH_KEY:-}"
CA_NODE="${CA_NODE:-}"
REMOTE_ROOT="${REMOTE_ROOT:-/var/lib/sovereignite/kubeadm-pki}"
STORE_DIR="${STORE_DIR:-/var/lib/sovereignite/tpm2-pkcs11}"
TOKEN_LABEL="${TOKEN_LABEL:-sovereignite-ca}"
PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib64/pkcs11/libtpm2_pkcs11.so}"
TPM2_PKCS11_KEY_ALGORITHM="${TPM2_PKCS11_KEY_ALGORITHM:-rsa3072}"
INSTALL_PKI_TOOLS="${INSTALL_PKI_TOOLS:-1}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require yq
require ssh
require scp
require tar
require base64
require openssl

ssh_cmd=(ssh -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
scp_cmd=(scp -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
if [ -n "${SSH_KEY}" ]; then
  ssh_cmd+=(-i "${SSH_KEY}" -o IdentitiesOnly=yes)
  scp_cmd+=(-i "${SSH_KEY}" -o IdentitiesOnly=yes)
fi

first_cp="$(yq -r '.spec.nodes[] | select(.role == "control-plane") | .name' "${INVENTORY}" | head -n1)"
if [ -z "${CA_NODE}" ]; then
  CA_NODE="${first_cp}"
fi

ca_node_ip="$(CA_NODE="${CA_NODE}" yq -r '.spec.nodes[] | select(.name == strenv(CA_NODE)) | .ip' "${INVENTORY}")"
api_endpoint="$(yq -r '.spec.cluster.apiEndpoint' "${INVENTORY}")"
api_vip="$(yq -r '.spec.cluster.apiVip' "${INVENTORY}")"
api_port="$(yq -r '.spec.cluster.apiServerPort' "${INVENTORY}")"
cluster_name="$(yq -r '.metadata.name' "${INVENTORY}")"

mkdir -p "${OUT_ROOT}" "$(dirname "${KUBECONFIG_OUT}")"
input_dir="$(mktemp -d "${OUT_ROOT}/input.XXXXXX")"
input_tar="${OUT_ROOT}/kubeadm-pki-input.tar"

yq -r '.spec.nodes[] | [.name, .role, .ip] | @tsv' "${INVENTORY}" > "${input_dir}/nodes.tsv"
mkdir -p "${input_dir}/kubeadm"

while IFS=$'\t' read -r node _role _ip; do
  kubeadm_config="${SHARE_DIR}/${node}/etc/kubernetes/kubeadm.yaml"
  if [ ! -f "${kubeadm_config}" ]; then
    echo "missing rendered kubeadm config: ${kubeadm_config}" >&2
    exit 66
  fi
  cp "${kubeadm_config}" "${input_dir}/kubeadm/${node}.yaml"
done < "${input_dir}/nodes.tsv"

tar -C "${input_dir}" -cf "${input_tar}" .
"${scp_cmd[@]}" "${input_tar}" "${SSH_USER}@${ca_node_ip}:/tmp/sovereignite-kubeadm-pki-input.tar"

"${ssh_cmd[@]}" "${SSH_USER}@${ca_node_ip}" \
  "sudo env REMOTE_ROOT='${REMOTE_ROOT}' STORE_DIR='${STORE_DIR}' TOKEN_LABEL='${TOKEN_LABEL}' PKCS11_MODULE='${PKCS11_MODULE}' TPM2_PKCS11_KEY_ALGORITHM='${TPM2_PKCS11_KEY_ALGORITHM}' INSTALL_PKI_TOOLS='${INSTALL_PKI_TOOLS}' bash -s" <<'REMOTE_SCRIPT'
set -euo pipefail

need_tool() {
  command -v "$1" >/dev/null 2>&1
}

missing_pki_tool=0
for tool in openssl pkcs11-tool tpm2_ptool /opt/bin/kubeadm; do
  if ! need_tool "${tool}"; then
    missing_pki_tool=1
  fi
done

if [ "${missing_pki_tool}" = "1" ]; then
  if [ "${INSTALL_PKI_TOOLS}" != "1" ]; then
    echo "missing PKI tooling on CA node and INSTALL_PKI_TOOLS is not enabled" >&2
    exit 67
  fi
  rpm-ostree install --apply-live --idempotent -y \
    tpm2-pkcs11 \
    tpm2-pkcs11-tools \
    opensc \
    pkcs11-provider \
    openssl-pkcs11 \
    openssl-pkcs11-sign-provider
  hash -r
fi

for tool in openssl pkcs11-tool tpm2_ptool /opt/bin/kubeadm; do
  if ! need_tool "${tool}"; then
    echo "missing required CA-node command after install attempt: ${tool}" >&2
    exit 127
  fi
done

input_dir="${REMOTE_ROOT}/input"
output_dir="${REMOTE_ROOT}/output.next"
stable_output="${REMOTE_ROOT}/output"
pin_file="${STORE_DIR}/pins.env"

rm -rf "${input_dir}" "${output_dir}"
mkdir -p "${input_dir}" "${output_dir}" "${STORE_DIR}"
chmod 0700 "${STORE_DIR}" "${output_dir}"
tar -C "${input_dir}" -xf /tmp/sovereignite-kubeadm-pki-input.tar

if [ ! -f "${pin_file}" ]; then
  umask 077
  {
    printf 'TPM2_PKCS11_SO_PIN=%s\n' "$(openssl rand -hex 16)"
    printf 'TPM2_PKCS11_USER_PIN=%s\n' "$(openssl rand -hex 16)"
  } > "${pin_file}"
fi
# shellcheck disable=SC1090
. "${pin_file}"

export TPM2_PKCS11_STORE="${STORE_DIR}"
export PKCS11_PROVIDER_MODULE="${PKCS11_MODULE}"

if [ ! -f "${STORE_DIR}/tpm2_pkcs11.sqlite3" ]; then
  tpm2_ptool init --path "${STORE_DIR}"
fi

if ! tpm2_ptool listtokens --path "${STORE_DIR}" --pid 1 | grep -q "label: ${TOKEN_LABEL}$"; then
  tpm2_ptool addtoken \
    --path "${STORE_DIR}" \
    --pid 1 \
    --label "${TOKEN_LABEL}" \
    --sopin "${TPM2_PKCS11_SO_PIN}" \
    --userpin "${TPM2_PKCS11_USER_PIN}"
fi

ensure_key() {
  local label="$1"
  if tpm2_ptool listobjects --path "${STORE_DIR}" --label "${TOKEN_LABEL}" | grep -q "CKA_LABEL: ${label}$"; then
    return 0
  fi
  tpm2_ptool addkey \
    --path "${STORE_DIR}" \
    --label "${TOKEN_LABEL}" \
    --key-label "${label}" \
    --algorithm "${TPM2_PKCS11_KEY_ALGORITHM}" \
    --userpin "${TPM2_PKCS11_USER_PIN}"
}

key_uri() {
  printf 'pkcs11:token=%s;object=%s;type=private;pin-value=%s' "${TOKEN_LABEL}" "$1" "${TPM2_PKCS11_USER_PIN}"
}

openssl_with_tpm() {
  openssl "$@" -provider default -provider pkcs11
}

random_serial() {
  printf '0x%s' "$(openssl rand -hex 16)"
}

ensure_key sovereignite-root-ca
ensure_key sovereignite-kubernetes-ca
ensure_key sovereignite-front-proxy-ca
ensure_key sovereignite-etcd-ca
ensure_key sovereignite-cert-manager-ca
ensure_key sovereignite-spire-upstream-ca
ensure_key sovereignite-spire-tpm-devid-ca
ensure_key sovereignite-spire-tpm-endorsement-ca

mkdir -p \
  "${output_dir}/kubernetes/etcd" \
  "${output_dir}/cert-manager" \
  "${output_dir}/spire" \
  "${output_dir}/profiles" \
  "${output_dir}/shared"

cat > "${output_dir}/profiles/root-ca.cnf" <<'EOF_ROOT_CNF'
[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[ dn ]
CN = Sovereignite TPM Root CA

[ v3_ca ]
basicConstraints = critical, CA:true, pathlen:2
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF_ROOT_CNF

cat > "${output_dir}/profiles/intermediate-ca.ext" <<'EOF_INTERMEDIATE_EXT'
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF_INTERMEDIATE_EXT

cat > "${output_dir}/profiles/server.ext" <<'EOF_SERVER_EXT'
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF_SERVER_EXT

cat > "${output_dir}/profiles/client.ext" <<'EOF_CLIENT_EXT'
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF_CLIENT_EXT

cat > "${output_dir}/profiles/peer.ext" <<'EOF_PEER_EXT'
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF_PEER_EXT

root_cert="${output_dir}/root-ca.crt"
kube_ca="${output_dir}/kubernetes/ca.crt"
front_proxy_ca="${output_dir}/kubernetes/front-proxy-ca.crt"
etcd_ca="${output_dir}/kubernetes/etcd/ca.crt"
cert_manager_ca="${output_dir}/cert-manager/ca.crt"
spire_upstream_ca="${output_dir}/spire/upstream-ca.crt"
spire_tpm_devid_ca="${output_dir}/spire/tpm-devid-ca.crt"
spire_tpm_endorsement_ca="${output_dir}/spire/tpm-endorsement-ca.crt"

openssl_with_tpm req \
  -new \
  -x509 \
  -sha256 \
  -days 3650 \
  -config "${output_dir}/profiles/root-ca.cnf" \
  -key "$(key_uri sovereignite-root-ca)" \
  -out "${root_cert}"

make_intermediate() {
  local common_name="$1"
  local key_label="$2"
  local cert_out="$3"
  local csr="${cert_out}.csr"

  openssl_with_tpm req \
    -new \
    -sha256 \
    -subj "/CN=${common_name}" \
    -key "$(key_uri "${key_label}")" \
    -out "${csr}"

  openssl_with_tpm x509 \
    -req \
    -sha256 \
    -days 1825 \
    -in "${csr}" \
    -CA "${root_cert}" \
    -CAkey "$(key_uri sovereignite-root-ca)" \
    -set_serial "$(random_serial)" \
    -extfile "${output_dir}/profiles/intermediate-ca.ext" \
    -out "${cert_out}"
}

make_intermediate "Sovereignite Kubernetes CA" sovereignite-kubernetes-ca "${kube_ca}"
make_intermediate "Sovereignite Kubernetes Front Proxy CA" sovereignite-front-proxy-ca "${front_proxy_ca}"
make_intermediate "Sovereignite etcd CA" sovereignite-etcd-ca "${etcd_ca}"
make_intermediate "Sovereignite cert-manager Local CA" sovereignite-cert-manager-ca "${cert_manager_ca}"
make_intermediate "Sovereignite SPIRE Upstream CA" sovereignite-spire-upstream-ca "${spire_upstream_ca}"
make_intermediate "Sovereignite SPIRE TPM DevID CA" sovereignite-spire-tpm-devid-ca "${spire_tpm_devid_ca}"
make_intermediate "Sovereignite SPIRE TPM Endorsement CA" sovereignite-spire-tpm-endorsement-ca "${spire_tpm_endorsement_ca}"

sign_leaf() {
  local csr="$1"
  local ca_cert="$2"
  local ca_key_label="$3"
  local profile="$4"
  local cert_out="$5"

  openssl_with_tpm x509 \
    -req \
    -sha256 \
    -days 365 \
    -in "${csr}" \
    -CA "${ca_cert}" \
    -CAkey "$(key_uri "${ca_key_label}")" \
    -set_serial "$(random_serial)" \
    -copy_extensions copy \
    -extfile "${output_dir}/profiles/${profile}.ext" \
    -out "${cert_out}"
}

openssl genrsa -out "${output_dir}/shared/sa.key" 2048
openssl rsa -in "${output_dir}/shared/sa.key" -pubout -out "${output_dir}/shared/sa.pub"
chmod 0600 "${output_dir}/shared/sa.key"
chmod 0644 "${output_dir}/shared/sa.pub"

while IFS=$'\t' read -r node role _ip; do
  node_out="${output_dir}/nodes/${node}"
  mkdir -p "${node_out}/pki/etcd" "${node_out}/etc-kubernetes"
  install -m 0644 "${kube_ca}" "${node_out}/pki/ca.crt"

  if [ "${role}" = "control-plane" ]; then
    /opt/bin/kubeadm certs generate-csr \
      --config "${input_dir}/kubeadm/${node}.yaml" \
      --cert-dir "${node_out}/pki" \
      --kubeconfig-dir "${node_out}/etc-kubernetes"

    install -m 0644 "${front_proxy_ca}" "${node_out}/pki/front-proxy-ca.crt"
    install -m 0644 "${etcd_ca}" "${node_out}/pki/etcd/ca.crt"
    install -m 0600 "${output_dir}/shared/sa.key" "${node_out}/pki/sa.key"
    install -m 0644 "${output_dir}/shared/sa.pub" "${node_out}/pki/sa.pub"

    sign_leaf "${node_out}/pki/apiserver.csr" "${kube_ca}" sovereignite-kubernetes-ca server "${node_out}/pki/apiserver.crt"
    sign_leaf "${node_out}/pki/apiserver-kubelet-client.csr" "${kube_ca}" sovereignite-kubernetes-ca client "${node_out}/pki/apiserver-kubelet-client.crt"
    sign_leaf "${node_out}/pki/front-proxy-client.csr" "${front_proxy_ca}" sovereignite-front-proxy-ca client "${node_out}/pki/front-proxy-client.crt"
    sign_leaf "${node_out}/pki/apiserver-etcd-client.csr" "${etcd_ca}" sovereignite-etcd-ca client "${node_out}/pki/apiserver-etcd-client.crt"
    sign_leaf "${node_out}/pki/etcd/server.csr" "${etcd_ca}" sovereignite-etcd-ca server "${node_out}/pki/etcd/server.crt"
    sign_leaf "${node_out}/pki/etcd/peer.csr" "${etcd_ca}" sovereignite-etcd-ca peer "${node_out}/pki/etcd/peer.crt"
    sign_leaf "${node_out}/pki/etcd/healthcheck-client.csr" "${etcd_ca}" sovereignite-etcd-ca client "${node_out}/pki/etcd/healthcheck-client.crt"

    sign_leaf "${node_out}/etc-kubernetes/admin.conf.csr" "${kube_ca}" sovereignite-kubernetes-ca client "${node_out}/etc-kubernetes/admin.conf.crt"
    sign_leaf "${node_out}/etc-kubernetes/controller-manager.conf.csr" "${kube_ca}" sovereignite-kubernetes-ca client "${node_out}/etc-kubernetes/controller-manager.conf.crt"
    sign_leaf "${node_out}/etc-kubernetes/scheduler.conf.csr" "${kube_ca}" sovereignite-kubernetes-ca client "${node_out}/etc-kubernetes/scheduler.conf.crt"
    sign_leaf "${node_out}/etc-kubernetes/super-admin.conf.csr" "${kube_ca}" sovereignite-kubernetes-ca client "${node_out}/etc-kubernetes/super-admin.conf.crt"
    sign_leaf "${node_out}/etc-kubernetes/kubelet.conf.csr" "${kube_ca}" sovereignite-kubernetes-ca client "${node_out}/etc-kubernetes/kubelet.conf.crt"
  else
    openssl genrsa -out "${node_out}/etc-kubernetes/kubelet.key" 2048
    chmod 0600 "${node_out}/etc-kubernetes/kubelet.key"
    openssl req \
      -new \
      -sha256 \
      -key "${node_out}/etc-kubernetes/kubelet.key" \
      -subj "/O=system:nodes/CN=system:node:${node}" \
      -out "${node_out}/etc-kubernetes/kubelet.conf.csr"
    sign_leaf "${node_out}/etc-kubernetes/kubelet.conf.csr" "${kube_ca}" sovereignite-kubernetes-ca client "${node_out}/etc-kubernetes/kubelet.conf.crt"
  fi
done < "${input_dir}/nodes.tsv"

rm -rf "${stable_output}"
mv "${output_dir}" "${stable_output}"
chmod -R go-rwx "${stable_output}"
find "${stable_output}" -type f -name '*.crt' -exec chmod 0644 {} +
find "${stable_output}" -type f -name '*.pub' -exec chmod 0644 {} +
REMOTE_SCRIPT

tmp_output_tar="${OUT_ROOT}/kubeadm-pki-output.tar"
"${ssh_cmd[@]}" "${SSH_USER}@${ca_node_ip}" "sudo tar -C '${REMOTE_ROOT}/output' -cf - ." > "${tmp_output_tar}"
rm -rf "${OUT_ROOT}/nodes" "${OUT_ROOT}/kubernetes" "${OUT_ROOT}/cert-manager" "${OUT_ROOT}/spire" "${OUT_ROOT}/profiles" "${OUT_ROOT}/shared" "${OUT_ROOT}/root-ca.crt"
tar -C "${OUT_ROOT}" -xf "${tmp_output_tar}"

b64_file() {
  base64 -w0 "$1"
}

patch_kubeconfig() {
  local kubeconfig="$1"
  local cert="$2"
  local ca_b64 cert_b64
  ca_b64="$(b64_file "${OUT_ROOT}/kubernetes/ca.crt")"
  cert_b64="$(b64_file "${cert}")"
  CA_B64="${ca_b64}" CERT_B64="${cert_b64}" yq -i \
    '.clusters[0].cluster."certificate-authority-data" = strenv(CA_B64) |
     .users[0].user."client-certificate-data" = strenv(CERT_B64)' \
    "${kubeconfig}"
}

write_worker_kubeconfig() {
  local node="$1"
  local node_dir="${OUT_ROOT}/nodes/${node}/etc-kubernetes"
  local ca_b64 cert_b64 key_b64 server_url
  ca_b64="$(b64_file "${OUT_ROOT}/kubernetes/ca.crt")"
  cert_b64="$(b64_file "${node_dir}/kubelet.conf.crt")"
  key_b64="$(b64_file "${node_dir}/kubelet.key")"
  server_url="https://${api_endpoint}:${api_port}"
  cat > "${node_dir}/kubelet.conf" <<EOF_WORKER_KUBECONFIG
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: ${ca_b64}
    server: ${server_url}
  name: ${cluster_name}
contexts:
- context:
    cluster: ${cluster_name}
    user: system:node:${node}
  name: system:node:${node}@${cluster_name}
current-context: system:node:${node}@${cluster_name}
kind: Config
preferences: {}
users:
- name: system:node:${node}
  user:
    client-certificate-data: ${cert_b64}
    client-key-data: ${key_b64}
EOF_WORKER_KUBECONFIG
  chmod 0600 "${node_dir}/kubelet.conf"
}

while IFS=$'\t' read -r node role _ip; do
  node_etc="${OUT_ROOT}/nodes/${node}/etc-kubernetes"
  if [ "${role}" = "control-plane" ]; then
    for conf in admin.conf controller-manager.conf scheduler.conf super-admin.conf kubelet.conf; do
      patch_kubeconfig "${node_etc}/${conf}" "${node_etc}/${conf}.crt"
      chmod 0600 "${node_etc}/${conf}"
    done
  else
    write_worker_kubeconfig "${node}"
  fi
done < "${input_dir}/nodes.tsv"

cp "${OUT_ROOT}/nodes/${first_cp}/etc-kubernetes/admin.conf" "${KUBECONFIG_OUT}"
SERVER_URL="https://${api_vip}:${api_port}" yq -i '.clusters[0].cluster.server = strenv(SERVER_URL)' "${KUBECONFIG_OUT}"
chmod 0600 "${KUBECONFIG_OUT}"

"${ROOT_DIR}/scripts/assert-no-ca-private-keys.sh"

echo "generated kubeadm external CA PKI under ${OUT_ROOT}"
echo "wrote local kubeconfig ${KUBECONFIG_OUT}"
