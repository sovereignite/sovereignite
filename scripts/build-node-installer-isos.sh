#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${INVENTORY:-${ROOT_DIR}/infra/libvirt/cluster.inventory.yaml}"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/infra/libvirt/build}"
COREOS_INSTALLER_IMAGE="${COREOS_INSTALLER_IMAGE:-quay.io/coreos/coreos-installer:release}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require yq
require podman

if [ ! -f "${INVENTORY}" ]; then
  echo "inventory not found: ${INVENTORY}" >&2
  exit 66
fi

os_id="$(yq -r '.spec.nodeOs.id // "flatcar"' "${INVENTORY}")"
customize="$(yq -r '.spec.nodeOs.installer.customize // "false"' "${INVENTORY}")"

if [ "${customize}" != "true" ]; then
  echo "installer customization disabled for ${os_id}"
  exit 0
fi

if [ "${os_id}" != "fedora-coreos" ]; then
  echo "unsupported installer customization for ${os_id}" >&2
  exit 65
fi

iso_name="$(yq -r '.spec.nodeOs.artifacts.installerIso.name' "${INVENTORY}")"
dest_device="$(yq -r '.spec.nodeOs.installer.destDevice // "/dev/vda"' "${INVENTORY}")"
image_dir="${BUILD_DIR}/images/${os_id}"
input_iso="${image_dir}/${iso_name}"

if [ ! -f "${input_iso}" ]; then
  echo "missing pristine installer ISO: ${input_iso}" >&2
  exit 66
fi

mapfile -t node_names < <(yq -r '.spec.nodes[].name' "${INVENTORY}")

for node in "${node_names[@]}"; do
  ignition_file="${BUILD_DIR}/ignition/${node}.ign"
  output_iso="${image_dir}/${node}-${iso_name}"

  if [ ! -f "${ignition_file}" ]; then
    echo "missing ignition config: ${ignition_file}" >&2
    exit 66
  fi

  if [ -f "${output_iso}" ] && [ "${output_iso}" -nt "${input_iso}" ] && [ "${output_iso}" -nt "${ignition_file}" ]; then
    echo "up to date ${output_iso}"
    continue
  fi

  echo "customizing ${output_iso}"
  podman run \
    --security-opt label=disable \
    --rm \
    -v "${BUILD_DIR}:/build" \
    -w "/build/images/${os_id}" \
    "${COREOS_INSTALLER_IMAGE}" \
    iso customize \
    --force \
    --dest-device "${dest_device}" \
    --dest-ignition "/build/ignition/${node}.ign" \
    --dest-karg-append ignition.platform.id=qemu \
    -o "${node}-${iso_name}" \
    "${iso_name}"
done

