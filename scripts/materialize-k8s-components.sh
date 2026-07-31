#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build/k8s/rendered}"

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

sanitize() {
  tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_.-]+/-/g; s/^-+//; s/-+$//'
}

write_upstream_kustomization() {
  local upstream_dir="$1"
  {
    echo "apiVersion: kustomize.config.k8s.io/v1beta1"
    echo "kind: Kustomization"
    echo "resources:"
    find "${upstream_dir}/resources" -type f -name '*.yaml' -printf '%f\n' | sort | while read -r file; do
      echo "  - resources/${file}"
    done
  } > "${upstream_dir}/kustomization.yaml"
}

split_rendered_yaml() {
  local rendered_file="$1"
  local upstream_dir="$2"

  rm -rf "${upstream_dir}/resources"
  mkdir -p "${upstream_dir}/resources"

  mapfile -t indices < <(yq eval-all 'documentIndex' "${rendered_file}" | sort -n | uniq)

  local written=0
  for idx in "${indices[@]}"; do
    local kind
    kind="$(yq eval-all "select(documentIndex == ${idx}) | .kind // \"\"" "${rendered_file}")"
    if [ -z "${kind}" ] || [ "${kind}" = "null" ]; then
      continue
    fi

    local api_version name namespace safe_kind safe_name safe_namespace file
    api_version="$(yq eval-all "select(documentIndex == ${idx}) | .apiVersion // \"unknown\"" "${rendered_file}")"
    name="$(yq eval-all "select(documentIndex == ${idx}) | .metadata.name // \"noname\"" "${rendered_file}")"
    namespace="$(yq eval-all "select(documentIndex == ${idx}) | .metadata.namespace // \"cluster\"" "${rendered_file}")"

    safe_kind="$(printf '%s' "${kind}" | sanitize)"
    safe_name="$(printf '%s' "${name}" | sanitize)"
    safe_namespace="$(printf '%s' "${namespace}" | sanitize)"
    file="$(printf '%03d-%s-%s-%s.yaml' "${idx}" "${safe_kind}" "${safe_namespace}" "${safe_name}")"

    {
      echo "# Source apiVersion: ${api_version}"
      yq eval-all "select(documentIndex == ${idx})" "${rendered_file}"
    } > "${upstream_dir}/resources/${file}"
    written=$((written + 1))
  done

  if [ "${written}" -eq 0 ]; then
    echo "component rendered no Kubernetes resources: ${rendered_file}" >&2
    exit 65
  fi

  write_upstream_kustomization "${upstream_dir}"
}

mkdir -p "${BUILD_DIR}"

for component in "${components[@]}"; do
  source_dir="${ROOT_DIR}/k8s/components/${component}/source"
  vendor_dir="${ROOT_DIR}/k8s/components/${component}/vendor"
  upstream_dir="${ROOT_DIR}/k8s/components/${component}/base/upstream"
  rendered_file="${BUILD_DIR}/${component}.yaml"

  if [ ! -f "${source_dir}/kustomization.yaml" ]; then
    echo "missing source kustomization for ${component}" >&2
    exit 66
  fi

  rm -rf "${vendor_dir}"
  kustomize localize "${source_dir}" "${vendor_dir}" --no-verify
  kustomize build "${vendor_dir}" --enable-helm > "${rendered_file}"
  split_rendered_yaml "${rendered_file}" "${upstream_dir}"

  echo "materialized ${component} into ${upstream_dir}"
done
