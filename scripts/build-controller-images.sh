#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="${REGISTRY:-ghcr.io/sovereignite}"
TAG="${TAG:-v0.1.0}"
SPIRE_SERVER_TAG="${SPIRE_SERVER_TAG:-1.15.2-sovereignite.0}"
CONTAINER_TOOL="${CONTAINER_TOOL:-}"
PUSH="${PUSH:-0}"

if [ -z "${CONTAINER_TOOL}" ]; then
  if command -v docker >/dev/null 2>&1; then
    CONTAINER_TOOL=docker
  elif command -v podman >/dev/null 2>&1; then
    CONTAINER_TOOL=podman
  else
    echo "set CONTAINER_TOOL or install docker/podman" >&2
    exit 127
  fi
fi

build_image() {
  local dockerfile="$1"
  local image="$2"

  "${CONTAINER_TOOL}" build \
    -f "${ROOT_DIR}/${dockerfile}" \
    -t "${image}" \
    "${ROOT_DIR}"

  if [ "${PUSH}" = "1" ]; then
    "${CONTAINER_TOOL}" push "${image}"
  fi
}

build_image controllers/tpm-cluster-issuer/Dockerfile "${REGISTRY}/tpm-cluster-issuer:${TAG}"
build_image controllers/k8s-tpm-csr-signer/Dockerfile "${REGISTRY}/k8s-tpm-csr-signer:${TAG}"
build_image controllers/spire-tpm-keymanager-controller/Dockerfile "${REGISTRY}/spire-tpm-keymanager-controller:${TAG}"
build_image controllers/spire-tpm-keymanager/Dockerfile "${REGISTRY}/spire-tpm-keymanager:${TAG}"
build_image controllers/spire-tpm-keymanager/Dockerfile.spire-server "${REGISTRY}/spire-server-tpm:${SPIRE_SERVER_TAG}"
