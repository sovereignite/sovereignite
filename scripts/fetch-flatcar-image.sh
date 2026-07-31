#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/infra/libvirt/build/images}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require yq
require curl
require bunzip2

url="$(yq -r '.spec.libvirt.flatcarImage.url' "${INVENTORY}")"
name="$(yq -r '.spec.libvirt.flatcarImage.decompressedName' "${INVENTORY}")"
archive="${OUT_DIR}/${name}.bz2"
image="${OUT_DIR}/${name}"

mkdir -p "${OUT_DIR}"

if [ ! -f "${archive}" ]; then
  curl -fL --retry 5 --retry-delay 5 -o "${archive}" "${url}"
fi

if [ ! -f "${image}" ]; then
  bunzip2 -kc "${archive}" > "${image}"
fi

echo "${image}"
