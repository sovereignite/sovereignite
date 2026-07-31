#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
OUT_ROOT="${OUT_ROOT:-${ROOT_DIR}/build/pki/tpm-devid}"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build/bin}"
BIN="${BIN:-${BUILD_DIR}/tpm-devid-provisioner}"
SSH_USER="${SSH_USER:-core}"
SSH_KEY="${SSH_KEY:-}"
CA_NODE="${CA_NODE:-}"
REMOTE_ROOT="${REMOTE_ROOT:-/var/lib/sovereignite/kubeadm-pki}"
STORE_DIR="${STORE_DIR:-/var/lib/sovereignite/tpm2-pkcs11}"
TOKEN_LABEL="${TOKEN_LABEL:-sovereignite-ca}"
PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib64/pkcs11/libtpm2_pkcs11.so}"
DEV_ID_KEY_TYPE="${DEV_ID_KEY_TYPE:-rsa}"
DEV_ID_DAYS="${DEV_ID_DAYS:-825}"
FORCE="${FORCE:-0}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require go
require yq
require ssh
require scp
require tar
require openssl

ssh_cmd=(ssh -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
scp_cmd=(scp -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
if [ -n "${SSH_KEY}" ]; then
  ssh_cmd+=(-i "${SSH_KEY}" -o IdentitiesOnly=yes)
  scp_cmd+=(-i "${SSH_KEY}" -o IdentitiesOnly=yes)
fi

mkdir -p "${BUILD_DIR}" "${OUT_ROOT}"
GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/sovereignite-go-build-cache}" \
  CGO_ENABLED=0 go build -trimpath -o "${BIN}" "${ROOT_DIR}/cmd/tpm-devid-provisioner"

first_cp="$(yq -r '.spec.nodes[] | select(.role == "control-plane") | .name' "${INVENTORY}" | head -n1)"
if [ -z "${CA_NODE}" ]; then
  CA_NODE="${first_cp}"
fi
ca_node_ip="$(CA_NODE="${CA_NODE}" yq -r '.spec.nodes[] | select(.name == strenv(CA_NODE)) | .ip' "${INVENTORY}")"

nodes_tsv="${OUT_ROOT}/nodes.tsv"
yq -r '.spec.nodes[] | [.name, .ip] | @tsv' "${INVENTORY}" > "${nodes_tsv}"

force_arg=()
if [ "${FORCE}" = "1" ]; then
  force_arg=(-force)
fi

while IFS=$'\t' read -r node ip; do
  node_dir="${OUT_ROOT}/${node}"
  remote_bin=".cache/sovereignite/tpm-devid-provisioner"
  mkdir -p "${node_dir}"

  echo "provisioning TPM DevID key on ${node}"
  "${ssh_cmd[@]}" -n "${SSH_USER}@${ip}" "mkdir -p .cache/sovereignite"
  "${scp_cmd[@]}" "${BIN}" "${SSH_USER}@${ip}:${remote_bin}"
  "${ssh_cmd[@]}" -n "${SSH_USER}@${ip}" \
    "sudo ${remote_bin} -key-type '${DEV_ID_KEY_TYPE}' -out-dir /var/lib/sovereignite/tpm ${force_arg[*]}"

  "${ssh_cmd[@]}" -n "${SSH_USER}@${ip}" \
    "sudo tar -C /var/lib/sovereignite/tpm -cf - devid.priv.blob devid.pub.blob devid.pub.pem" \
    > "${node_dir}/devid-material.tar"
  tar -C "${node_dir}" -xf "${node_dir}/devid-material.tar"
  rm "${node_dir}/devid-material.tar"
done < "${nodes_tsv}"

sign_input="$(mktemp -d "${OUT_ROOT}/sign-input.XXXXXX")"
mkdir -p "${sign_input}/public"
cp "${nodes_tsv}" "${sign_input}/nodes.tsv"
while IFS=$'\t' read -r node _ip; do
  cp "${OUT_ROOT}/${node}/devid.pub.pem" "${sign_input}/public/${node}.pem"
done < "${nodes_tsv}"

sign_input_tar="${OUT_ROOT}/spire-devid-sign-input.tar"
tar -C "${sign_input}" -cf "${sign_input_tar}" .
"${scp_cmd[@]}" "${sign_input_tar}" "${SSH_USER}@${ca_node_ip}:/tmp/sovereignite-spire-devid-input.tar"

"${ssh_cmd[@]}" "${SSH_USER}@${ca_node_ip}" \
  "sudo env REMOTE_ROOT='${REMOTE_ROOT}' STORE_DIR='${STORE_DIR}' TOKEN_LABEL='${TOKEN_LABEL}' PKCS11_MODULE='${PKCS11_MODULE}' DEV_ID_DAYS='${DEV_ID_DAYS}' bash -s" <<'REMOTE_SCRIPT'
set -euo pipefail

input_dir="${REMOTE_ROOT}/spire-devid-input"
output_dir="${REMOTE_ROOT}/spire-devid-output.next"
stable_output="${REMOTE_ROOT}/spire-devid-output"
pin_file="${STORE_DIR}/pins.env"
ca_cert="${REMOTE_ROOT}/output/spire/tpm-devid-ca.crt"

if [ ! -f "${pin_file}" ]; then
  echo "missing TPM PKCS#11 pin file: ${pin_file}" >&2
  exit 66
fi
if [ ! -f "${ca_cert}" ]; then
  echo "missing SPIRE TPM DevID CA certificate: ${ca_cert}" >&2
  exit 66
fi

rm -rf "${input_dir}" "${output_dir}"
mkdir -p "${input_dir}" "${output_dir}"
tar -C "${input_dir}" -xf /tmp/sovereignite-spire-devid-input.tar

# shellcheck disable=SC1090
. "${pin_file}"

export TPM2_PKCS11_STORE="${STORE_DIR}"
export PKCS11_PROVIDER_MODULE="${PKCS11_MODULE}"

key_uri() {
  printf 'pkcs11:token=%s;object=%s;type=private;pin-value=%s' "${TOKEN_LABEL}" "$1" "${TPM2_PKCS11_USER_PIN}"
}

random_serial() {
  printf '0x%s' "$(openssl rand -hex 16)"
}

profile="${output_dir}/devid.ext"
cat > "${profile}" <<'EOF_PROFILE'
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF_PROFILE

while IFS=$'\t' read -r node _ip; do
  node_out="${output_dir}/${node}"
  mkdir -p "${node_out}"
  openssl x509 \
    -new \
    -sha256 \
    -force_pubkey "${input_dir}/public/${node}.pem" \
    -subj "/CN=sovereignite-spire-tpm-devid-${node}" \
    -days "${DEV_ID_DAYS}" \
    -CA "${ca_cert}" \
    -CAkey "$(key_uri sovereignite-spire-tpm-devid-ca)" \
    -set_serial "$(random_serial)" \
    -extfile "${profile}" \
    -out "${node_out}/devid.crt" \
    -provider default \
    -provider pkcs11
done < "${input_dir}/nodes.tsv"

rm -rf "${stable_output}"
mv "${output_dir}" "${stable_output}"
chmod -R go-rwx "${stable_output}"
find "${stable_output}" -type f -name '*.crt' -exec chmod 0644 {} +
REMOTE_SCRIPT

certs_tar="${OUT_ROOT}/spire-devid-certs.tar"
"${ssh_cmd[@]}" "${SSH_USER}@${ca_node_ip}" "sudo tar -C '${REMOTE_ROOT}/spire-devid-output' -cf - ." > "${certs_tar}"
tar -C "${OUT_ROOT}" -xf "${certs_tar}"
rm "${certs_tar}" "${sign_input_tar}"
rm -rf "${sign_input}"

while IFS=$'\t' read -r node ip; do
  if [ ! -f "${OUT_ROOT}/${node}/devid.crt" ]; then
    echo "missing signed DevID certificate for ${node}" >&2
    exit 66
  fi
  echo "staging signed TPM DevID certificate on ${node}"
  tar -C "${OUT_ROOT}/${node}" -cf - devid.crt | "${ssh_cmd[@]}" "${SSH_USER}@${ip}" \
    "sudo mkdir -p /var/lib/sovereignite/tpm && sudo tar -C /var/lib/sovereignite/tpm -xf - && sudo chmod 0600 /var/lib/sovereignite/tpm/devid.priv.blob && sudo chmod 0644 /var/lib/sovereignite/tpm/devid.pub.blob /var/lib/sovereignite/tpm/devid.crt"
done < "${nodes_tsv}"
