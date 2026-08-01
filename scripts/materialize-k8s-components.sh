#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REFRESH_VENDOR="${REFRESH_VENDOR:-0}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require kustomize
require yq

components=(
  calico
  gateway-api
  istio
  cert-manager
  knative-serving
  knative-eventing
  knative-net-gateway-api
)

if [ "$#" -gt 0 ]; then
  components=("$@")
fi

has_helm_charts() {
  local package_dir="$1"
  yq eval '.helmCharts != null' "${package_dir}/kustomization.yaml" | grep -qx true
}

resource_identities() {
  local package_dir="$1"
  kustomize build "${package_dir}" --enable-helm |
    yq eval '
      select(.kind != null) |
      (.apiVersion // "") + "\t" +
      (.kind // "") + "\t" +
      (.metadata.namespace // "") + "\t" +
      (.metadata.name // "")
    ' - |
    sort
}

materialize_component() {
  local component="$1"
  local source_dir="${ROOT_DIR}/k8s/components/${component}/source"
  local vendor_dir="${ROOT_DIR}/k8s/components/${component}/vendor"
  local upstream_dir="${ROOT_DIR}/k8s/components/${component}/base/upstream"
  local work_dir artifact_dir resources_dir input_dir old_ids new_ids

  if [ ! -f "${source_dir}/kustomization.yaml" ]; then
    echo "missing source kustomization for ${component}" >&2
    exit 66
  fi

  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sovereignite-${component}.XXXXXX")"
  artifact_dir="${work_dir}/upstream"
  resources_dir="${artifact_dir}/resources"
  old_ids="${work_dir}/old.ids"
  new_ids="${work_dir}/new.ids"
  input_dir="${vendor_dir}"

  if [ -f "${upstream_dir}/kustomization.yaml" ]; then
    resource_identities "${upstream_dir}" > "${old_ids}"
  fi

  if [ "${REFRESH_VENDOR}" = "1" ] || [ ! -f "${vendor_dir}/kustomization.yaml" ]; then
    if has_helm_charts "${source_dir}"; then
      echo "cannot localize Helm-backed component: ${component}" >&2
      exit 67
    fi

    input_dir="${work_dir}/vendor"
    kustomize localize "${source_dir}" "${input_dir}" --no-verify
  fi

  mkdir -p "${resources_dir}"
  kustomize build "${input_dir}" --enable-helm -o "${resources_dir}"
  (
    cd "${artifact_dir}"
    rm -f kustomization.yaml
    kustomize init --autodetect --recursive
  )

  resource_identities "${artifact_dir}" > "${new_ids}"

  if [ -s "${old_ids}" ] && ! diff -u "${old_ids}" "${new_ids}"; then
    echo "resource identity changed while materializing ${component}" >&2
    exit 68
  fi

  if [ "${input_dir}" != "${vendor_dir}" ]; then
    rm -rf "${vendor_dir}"
    mv "${input_dir}" "${vendor_dir}"
  fi

  rm -rf "${upstream_dir}"
  mkdir -p "$(dirname "${upstream_dir}")"
  mv "${artifact_dir}" "${upstream_dir}"
  rm -rf "${work_dir}"

  echo "materialized ${component} into ${upstream_dir}"
}

for component in "${components[@]}"; do
  materialize_component "${component}"
done
