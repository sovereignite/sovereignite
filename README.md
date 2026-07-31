# Sovereignite

Secure Flatcar Kubernetes deployment scaffolding for Libvirt/KVM.

This repository uses the Nix flake only as a local development shell. Cluster
provisioning and Kubernetes deployment are implemented with OpenTofu, Butane,
plain scripts, and Kustomize overlays.

## What Is Defined

- 8 Flatcar Stable VMs on Libvirt/KVM: 3 control-plane nodes and 5 workers.
- OVMF Secure Boot and TPM2/vTPM domain XML for every VM.
- kubeadm HA configuration in external CA mode.
- Calico, Gateway API, cert-manager, SPIRE, Istio sidecar mode, Knative Serving,
  Knative Eventing, Knative net-gateway-api, private Gateway resources, and
  STRICT mesh mTLS policy.
- Repo-owned custom APIs, Go controller/plugin source, and Dockerfiles for
  TPM-backed certificate issuance, Kubernetes CSR signing, and SPIRE TPM key
  management.

## Quick Start

```bash
nix develop
scripts/materialize-k8s-components.sh
scripts/verify-repo.sh
scripts/build-controller-images.sh
scripts/fetch-flatcar-image.sh
SSH_AUTHORIZED_KEY="$(cat ~/.ssh/id_ed25519.pub)" scripts/render-ignition.sh
cd infra/libvirt
tofu init
tofu apply
```

After the VMs are running, initialize and stage TPM-backed PKI material as
described in [docs/pki.md](docs/pki.md), then:

```bash
scripts/stage-pki-to-nodes.sh
scripts/bootstrap-kubeadm.sh
scripts/update-ca-configmaps.sh
scripts/verify-cluster.sh
```

The final Kubernetes deployment entrypoint is:

```bash
kubectl apply -k k8s/overlays/local
```

Do not deploy from `k8s/components/*/source`; those directories are only inputs
for localizing and rendering pinned upstream resources into local bases.
