# Deployment Runbook

## Inputs

- Inventory: `infra/libvirt/cluster.inventory.yaml`
- PKI hierarchy: `pki/ca-hierarchy.yaml`
- Final Kubernetes overlay: `k8s/overlays/local`

Default cluster settings:

- Kubernetes `v1.36.3`
- Flatcar Stable `4593.2.4`
- Pod CIDR `192.168.0.0/16`
- Service CIDR `10.96.0.0/12`
- Kubernetes DNS domain `cluster.local`
- SPIFFE trust domain `sovereignite.local`
- Private DNS suffix `sovereignite.local`

## 1. Enter The Dev Shell

```bash
nix develop
```

The flake provides local tools only. It does not define VM, cluster, or
Kubernetes resources.

## 2. Vendor Kubernetes Components

```bash
scripts/materialize-k8s-components.sh
scripts/verify-repo.sh
```

The materializer reads each component `source/kustomization.yaml`, localizes
remote references under `vendor/`, renders with Kustomize, splits the output
into deterministic YAML files, and writes those files under
`base/upstream/resources`.

The final overlay only references local bases.

## 3. Build Controller Images

The custom components are ordinary Go programs under `controllers/*/cmd` with
Dockerfiles beside their CRD/RBAC manifests.

```bash
scripts/build-controller-images.sh
```

Override `REGISTRY`, `TAG`, `SPIRE_SERVER_TAG`, or `CONTAINER_TOOL` when using a
private registry or Podman. Set `PUSH=1` to push the same tags after building.
The manifest image names default to `ghcr.io/sovereignite/*`.

## 4. Prepare Flatcar VM Inputs

```bash
scripts/fetch-flatcar-image.sh
SSH_AUTHORIZED_KEY="$(cat ~/.ssh/id_ed25519.pub)" scripts/render-ignition.sh
```

Ignition output is written to `infra/libvirt/build/ignition/<node>.ign`.

## 5. Apply Libvirt Infrastructure

```bash
cd infra/libvirt
tofu init
tofu plan
tofu apply
```

By default the VMs attach to bridge `br0`. Set
`-var=create_managed_network=true` to create a managed NAT network for local
testing.

## 6. Stage PKI And Bootstrap Kubernetes

Generate or import TPM-backed PKI material using `pki/ca-hierarchy.yaml`, then
place per-node kubeadm leaf material under:

```text
build/pki/nodes/<node>/
```

Each node directory must contain only public CA certificates and leaf
certificate/private-key pairs required by kubeadm. CA private keys are rejected
by `scripts/stage-pki-to-nodes.sh`.

```bash
scripts/assert-no-ca-private-keys.sh
scripts/stage-pki-to-nodes.sh
scripts/bootstrap-kubeadm.sh
scripts/update-ca-configmaps.sh
```

## 7. Verify

```bash
scripts/check-node-security.sh
scripts/verify-cluster.sh
kubectl apply -k k8s/samples/knative
```

Confirm the Knative sample route resolves only on the internal/private network.
