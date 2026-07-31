#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build/images}"
ARCHIVE="${ARCHIVE:-${BUILD_DIR}/sovereignite-controller-images.tar}"
CONTAINER_TOOL="${CONTAINER_TOOL:-podman}"
SSH_USER="${SSH_USER:-core}"
SSH_KEY="${SSH_KEY:-}"
REFRESH_ARCHIVE="${REFRESH_ARCHIVE:-0}"

images=(
  ghcr.io/sovereignite/tpm-cluster-issuer:v0.1.0
  ghcr.io/sovereignite/k8s-tpm-csr-signer:v0.1.0
  ghcr.io/sovereignite/spire-tpm-keymanager-controller:v0.1.0
  ghcr.io/sovereignite/spire-tpm-keymanager:v0.1.0
  ghcr.io/sovereignite/spire-server-tpm:1.15.2-sovereignite.0
)

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require "${CONTAINER_TOOL}"
require yq
require ssh
require scp

ssh_cmd=(ssh -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
scp_cmd=(scp -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
if [ -n "${SSH_KEY}" ]; then
  ssh_cmd+=(-i "${SSH_KEY}" -o IdentitiesOnly=yes)
  scp_cmd+=(-i "${SSH_KEY}" -o IdentitiesOnly=yes)
fi

mkdir -p "${BUILD_DIR}"

for image in "${images[@]}"; do
  "${CONTAINER_TOOL}" image exists "${image}" || {
    echo "missing local image: ${image}" >&2
    echo "run scripts/build-controller-images.sh first" >&2
    exit 66
  }
done

save_images() {
  local output="$1"
  shift

  if "${CONTAINER_TOOL}" --version 2>/dev/null | grep -qi podman; then
    "${CONTAINER_TOOL}" save --multi-image-archive -o "${output}" "$@"
  else
    "${CONTAINER_TOOL}" save -o "${output}" "$@"
  fi
}

if [ "${REFRESH_ARCHIVE}" = "1" ] || [ ! -f "${ARCHIVE}" ]; then
  if [ -f "${ARCHIVE}" ]; then
    archive_next="${ARCHIVE}.next"
    save_images "${archive_next}" "${images[@]}"
    mv "${archive_next}" "${ARCHIVE}"
  else
    save_images "${ARCHIVE}" "${images[@]}"
  fi
fi

remote_archive=".cache/sovereignite/$(basename "${ARCHIVE}")"
mapfile -t nodes < <(yq -r '.spec.nodes[] | [.name, .ip] | @tsv' "${INVENTORY}")
for node_entry in "${nodes[@]}"; do
  IFS=$'\t' read -r node ip <<< "${node_entry}"
  "${ssh_cmd[@]}" "${SSH_USER}@${ip}" "mkdir -p .cache/sovereignite"
  "${scp_cmd[@]}" "${ARCHIVE}" "${SSH_USER}@${ip}:${remote_archive}"
  "${ssh_cmd[@]}" "${SSH_USER}@${ip}" "sudo ctr -n k8s.io images import /home/${SSH_USER}/${remote_archive}"
  echo "imported controller images on ${node}"
done
