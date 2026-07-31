# Deployment Runbook

## Inputs

- Inventory: `infra/libvirt/cluster.inventory.yaml`
- PKI hierarchy: `pki/ca-hierarchy.yaml`
- Final Kubernetes overlay: `k8s/overlays/local`

Default cluster settings:

- Kubernetes `v1.36.3`
- Fedora CoreOS `44.20260707.3.1`
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

### Fedora CoreOS Volume Plugin Path

Fedora CoreOS keeps `/usr` read-only. Kubernetes' default flexvolume path is
under `/usr/libexec`, so the kubeadm render path sets both kubelet
`volume-plugin-dir` and kube-controller-manager `flex-volume-plugin-dir` to
`/var/lib/kubelet/volumeplugins/`. Calico's `Installation` resource must use
the same `flexVolumePath`; otherwise `calico-node` fails to mount the host path
and all nodes remain `NotReady`.

## 3. Build Controller Images

The custom components are ordinary Go programs under `controllers/*/cmd` with
Dockerfiles beside their CRD/RBAC manifests.

```bash
scripts/build-controller-images.sh
```

Override `REGISTRY`, `TAG`, `SPIRE_SERVER_TAG`, or `CONTAINER_TOOL` when using a
private registry or Podman. Set `PUSH=1` to push the same tags after building.
The manifest image names default to `ghcr.io/sovereignite/*`.

## 4. Prepare VM Inputs

```bash
scripts/fetch-node-os-artifacts.sh
SSH_AUTHORIZED_KEY="$(cat ~/.ssh/id_ed25519.pub)" scripts/render-ignition.sh
scripts/build-node-installer-isos.sh
```

Ignition output is written to `infra/libvirt/build/ignition/<node>.ign`.
Downloaded pristine ISO artifacts and generated per-node installer ISOs are
written under `infra/libvirt/build/images/<nodeOs.id>/`.

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

Fresh domains can be started normally after apply. If the configured OVMF vars
template changes for existing domains, start them once with libvirt's documented
NVRAM reset so the new vars template is copied into each VM:

```bash
virsh --connect qemu:///system start <node> --reset-nvram
```

## 6. Stage PKI And Bootstrap Kubernetes

Generate or import TPM-backed PKI material using `pki/ca-hierarchy.yaml`, then
place per-node kubeadm leaf material under:

```text
build/pki/nodes/<node>/
  pki/
  etc-kubernetes/
```

Each node directory must contain only public CA certificates, signed kubeadm
kubeconfigs, and leaf certificate/private-key pairs required by kubeadm. CA
private keys are rejected by the staging scripts.

```bash
scripts/generate-kubeadm-external-pki.sh
scripts/assert-no-ca-private-keys.sh
scripts/stage-kubeadm-pki-to-nodes.sh
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
