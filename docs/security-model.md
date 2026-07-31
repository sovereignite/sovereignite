# Security Model

## VM Boundary

Every Flatcar VM is provisioned with:

- OVMF Secure Boot through libvirt domain XML.
- TPM2/vTPM through libvirt swtpm.
- Locked-down SSH with key-only login.
- Static network configuration from inventory.
- A boot-time check for TPM and Secure Boot before kubelet startup.

## Kubernetes PKI

kubeadm is configured for external CA mode. Public CA certificates and
pre-signed leaf certificates are staged to nodes, but CA private keys are never
copied to nodes or Kubernetes Secrets.

The kube-controller-manager CSR signing controller is disabled. Kubelet CSR
rotation is delegated to `k8s-tpm-csr-signer`.

## Workload Identity

SPIRE is the workload identity authority for the trust domain
`sovereignite.local`. Istio is installed in sidecar mode and configured to use
SPIRE SDS identities. Ambient mode is intentionally not used because the SPIRE
requirement is treated as stricter than the ambient dataplane goal.

## Ingress

Gateway API and Knative routing are private-only. The Gateway is annotated for
ClusterIP service generation and no MetalLB, cloud LoadBalancer, or public
ingress VIP is defined in this repo.

## Mesh

`k8s/components/mesh-security/base` installs mesh-wide STRICT mTLS using Istio
`PeerAuthentication`.
