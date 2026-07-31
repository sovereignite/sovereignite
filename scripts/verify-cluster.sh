#!/usr/bin/env bash
set -euo pipefail

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require kubectl

kubectl wait --for=condition=Ready nodes --all --timeout=20m
kubectl -n tigera-operator wait --for=condition=Available deployment/tigera-operator --timeout=20m
kubectl -n calico-system wait --for=condition=Available deployment --all --timeout=20m
kubectl -n cert-manager wait --for=condition=Available deployment --all --timeout=20m
kubectl -n spire rollout status statefulset/spire-server --timeout=20m
kubectl -n spire rollout status daemonset/spire-agent --timeout=20m
kubectl -n istio-system wait --for=condition=Available deployment --all --timeout=20m
kubectl -n knative-serving wait --for=condition=Available deployment --all --timeout=20m
kubectl -n knative-eventing wait --for=condition=Available deployment --all --timeout=20m

kubectl get peerauthentication -A
kubectl get gatewayclass,gateway -A
kubectl get nodes -o wide
