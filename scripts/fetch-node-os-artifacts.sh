#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
OUT_ROOT="${OUT_ROOT:-${ROOT_DIR}/infra/libvirt/build/images}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require yq
require curl
require sha256sum

if [ ! -f "${INVENTORY}" ]; then
  echo "inventory not found: ${INVENTORY}" >&2
  exit 66
fi

os_id="$(yq -r '.spec.nodeOs.id // "flatcar"' "${INVENTORY}")"
iso_url="$(yq -r '.spec.nodeOs.artifacts.installerIso.url // .spec.libvirt.flatcarInstallerIso.url' "${INVENTORY}")"
iso_name="$(yq -r '.spec.nodeOs.artifacts.installerIso.name // .spec.libvirt.flatcarInstallerIso.name' "${INVENTORY}")"
iso_sha="$(yq -r '.spec.nodeOs.artifacts.installerIso.sha256 // ""' "${INVENTORY}")"

out_dir="${OUT_ROOT}/${os_id}"
iso_path="${out_dir}/${iso_name}"

mkdir -p "${out_dir}"

if [ ! -f "${iso_path}" ]; then
  curl -fL --retry 5 --retry-delay 5 -o "${iso_path}" "${iso_url}"
fi

if [ -n "${iso_sha}" ]; then
  printf '%s  %s\n' "${iso_sha}" "${iso_path}" | sha256sum -c -
fi

echo "${iso_path}"

