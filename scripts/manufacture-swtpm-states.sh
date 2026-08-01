#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
LIBVIRT_DIR="${ROOT_DIR}/infra/libvirt"
BUILD_ROOT="${BUILD_ROOT:-${LIBVIRT_DIR}/build/swtpm}"
CA_DIR="${SWTPM_CA_DIR:-${BUILD_ROOT}/ca}"
CONFIG_DIR="${BUILD_ROOT}/config"
CERT_ROOT="${BUILD_ROOT}/ek-certs"
FORCE="${FORCE:-0}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

absolute_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "${LIBVIRT_DIR}/$1" ;;
  esac
}

require yq
require swtpm_setup
require swtpm_localca
require openssl
require setfacl

if [ ! -f "${INVENTORY}" ]; then
  echo "inventory not found: ${INVENTORY}" >&2
  exit 66
fi

tpm_state_dir="$(absolute_path "$(yq -r '.spec.libvirt.tpm.stateDir' "${INVENTORY}")")"
swtpm_localca="$(command -v swtpm_localca)"

mkdir -p "${CA_DIR}" "${CONFIG_DIR}" "${CERT_ROOT}" "${tpm_state_dir}"
chmod 0700 "${CA_DIR}"

cat > "${CONFIG_DIR}/swtpm-localca.conf" <<EOF_CONF
statedir = ${CA_DIR}
signingkey = ${CA_DIR}/signkey.pem
issuercert = ${CA_DIR}/issuercert.pem
certserial = ${CA_DIR}/certserial
EOF_CONF

cat > "${CONFIG_DIR}/swtpm-localca.options" <<'EOF_OPTIONS'
--platform-manufacturer Sovereignite
--platform-model Libvirt
--platform-version 2026-07-31
EOF_OPTIONS

cat > "${CONFIG_DIR}/swtpm_setup.conf" <<EOF_SETUP
create_certs_tool = ${swtpm_localca}
create_certs_tool_config = ${CONFIG_DIR}/swtpm-localca.conf
create_certs_tool_options = ${CONFIG_DIR}/swtpm-localca.options
active_pcr_banks = sha256
profile = {"Name":"default-v1"}
EOF_SETUP

nodes_tsv="${BUILD_ROOT}/nodes.tsv"
yq -r '.spec.nodes[] | [.name, .ip] | @tsv' "${INVENTORY}" > "${nodes_tsv}"

while IFS=$'\t' read -r node _ip; do
  state_dir="${tpm_state_dir}/${node}"
  cert_dir="${CERT_ROOT}/${node}"

  if [ "${FORCE}" != "1" ] && [ -f "${state_dir}/tpm2-00.permall" ]; then
    echo "swtpm state already exists for ${node}: ${state_dir}"
  else
    mkdir -p "${state_dir}" "${cert_dir}"
    swtpm_setup \
      --tpm2 \
      --tpm-state "dir://${state_dir}" \
      --create-ek-cert \
      --create-platform-cert \
      --vmid "${node}" \
      --config "${CONFIG_DIR}/swtpm_setup.conf" \
      --write-ek-cert-files "${cert_dir}" \
      --overwrite
  fi

  setfacl -m u:tss:rwx "${tpm_state_dir}" "${state_dir}"
  setfacl -R -m u:tss:rwX "${state_dir}"
done < "${nodes_tsv}"

if [ ! -f "${CA_DIR}/issuercert.pem" ] || [ ! -f "${CA_DIR}/swtpm-localca-rootca-cert.pem" ]; then
  echo "swtpm CA manufacture did not produce the expected CA chain under ${CA_DIR}" >&2
  exit 66
fi

cat "${CA_DIR}/issuercert.pem" "${CA_DIR}/swtpm-localca-rootca-cert.pem" > "${BUILD_ROOT}/ca-bundle.pem"
openssl verify \
  -CAfile "${CA_DIR}/swtpm-localca-rootca-cert.pem" \
  -untrusted "${CA_DIR}/issuercert.pem" \
  "${CERT_ROOT}/$(head -n1 "${nodes_tsv}" | cut -f1)/ek-rsa2048.crt"

echo "${tpm_state_dir}"
