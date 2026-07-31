 # Secure TPM-backed Flatcar Kubernetes Deployment Plan

  ## Summary

  - Target Libvirt/KVM with 8 Flatcar Stable VMs: 3 control-plane nodes with 4 GB RAM/256 GB disk, 5 workers with 16 GB RAM/256 GB disk, all using OVMF Secure Boot and TPM2/vTPM.
  - Use kubeadm HA with external CA mode, Calico CNI, Gateway API, cert-manager, SPIRE, Istio sidecar mode with SPIRE SDS, and YAML-based Knative Serving/Eventing.
  - Replace Istio Ambient with Istio sidecar mode because current Istio docs list SPIRE as a hard blocker for ambient. This preserves the stricter SPIRE-issued workload identity requirement.
  - Keep ingress private-only: Gateway and Knative routes are cluster/internal-network reachable, with no MetalLB, cloud LoadBalancer, or external VIP.

  ## Key Interfaces And Defaults

  - Add repo configuration under infra/libvirt, pki, and k8s:
      - cluster.inventory.yaml: VM names, MACs/IPs, disks, roles, API VIP, pod/service CIDRs, trust domain, private DNS suffix.
      - ca-hierarchy.yaml: TPM-backed root and subordinate CA names, PKCS#11 labels, certificate profiles, rotation windows.
      - Kustomize package roots for every Kubernetes component.

  - Defaults: Kubernetes v1.36.3, Flatcar Stable 4593.2.4, Calico v3.32.1, Gateway API v1.6.1, Istio 1.30.3, cert-manager v1.21.1, SPIRE v1.15.2, Knative Serving v1.22.1, Knative Eventing v1.22.2, Knative net-gateway-api v1.22.1.
  - Use sovereignite.local as SPIFFE trust domain, cluster.local as Kubernetes DNS domain, 192.168.0.0/16 as pod CIDR, and 10.96.0.0/12 as service CIDR unless inventory overrides them.
  - Introduce custom APIs/controllers:
      - TPMClusterIssuer for cert-manager external issuance without CA private keys in Kubernetes Secrets.
      - k8s-tpm-csr-signer for Kubernetes CSR signing while kubeadm runs without ca.key.
      - spire-tpm-keymanager external SPIRE KeyManager plugin so SPIRE CA signing keys stay TPM-resident.

  ## Implementation Changes

  - Extend the Nix dev shell with pinned deployment tools: opentofu, libvirt, butane, kustomize, kubectl, helm, skopeo/crane, tpm2-tools, tpm2-pkcs11, openssl, step-cli, cfssl, and YAML validation tools.
  - Provision Libvirt VMs with Terraform/OpenTofu: Flatcar image import, TPM2/vTPM state, OVMF Secure Boot firmware, virtio disks/NICs, static DHCP leases, and host bridge networking.
  - Generate Butane/Ignition for Flatcar: kubeadm/kubelet/kubectl in /opt/bin or sysext, containerd runtime, locked-down SSH, TPM/Secure Boot verification services, kubeadm config, and HA API endpoint support.
  - Build PKI as external CA:
      - TPM root CA signs Kubernetes CA, front-proxy CA, etcd CA, cert-manager local CA, and SPIRE upstream CA.
      - kubeadm receives only CA public certs plus pre-signed leaf certs; no CA private keys are copied into /etc/kubernetes/pki.
      - Kubernetes CSR rotation is handled by k8s-tpm-csr-signer, not controller-manager’s file-backed signer.

  - Implement the strict Kustomize pipeline:
      - Each upstream chart/resource gets a source kustomization.
      - Run kustomize localize into repo-local vendor directories.
      - Render each component to a derived resource set, split resources into deterministic YAML files, then run kustomize init and kustomize edit add resource ... to create deployable bases.
      - Deploy only from final local overlays with kubectl apply -k; Helm is never used as live release state.

  - Kubernetes packages:
      - Calico with VXLAN or IPIP disabled/enabled by inventory, Kubernetes datastore, NetworkPolicy enabled.
      - Gateway API CRDs and Istio sidecar install with SPIRE CSI/SDS templates.
      - SPIRE hardened chart rendered into Kustomize, with controller-manager auto-registration and TPM DevID node attestation.
      - cert-manager plus TPMClusterIssuer, with no built-in CA issuer private-key Secret.
      - Knative Serving/Eventing YAML install, net-gateway-api, private Gateway resources, default broker/channel, and mesh-compatible STRICT mTLS policies.

  ## Test Plan

  - Validate repo generation: kustomize build works offline from final overlays; no deployed overlay references remote URLs or Helm repos.
  - Validate VM security: each VM reports TPM2 device, Secure Boot enabled, expected PCR measurements, and Flatcar boot/update services healthy.
  - Validate kubeadm PKI: kubeadm certs check-expiration passes, no *-ca.key exists on nodes, and kubelet client/server CSR renewal is signed by the TPM CSR signer.
  - Validate cluster readiness: all 8 nodes Ready, etcd healthy across 3 control-plane nodes, Calico pods Ready, pod-to-pod networking and NetworkPolicy tests pass.
  - Validate identity and mTLS: SPIRE agents attest through TPM DevID, Istio proxies receive SPIRE SDS identities, mesh-wide PeerAuthentication is STRICT, plaintext pod-to-pod traffic is rejected, and mTLS traffic succeeds.
  - Validate Knative private routing: deploy a sample Knative Service and Eventing Broker/Trigger, confirm scale-to-zero/scale-from-zero, Gateway API HTTPRoutes created, and access works only through private/internal routing.

  ## Assumptions And References

  - User choices locked: Libvirt/KVM provisioning, all CA keys TPM-resident, private-only ingress, and Istio sidecar mode to satisfy SPIRE identity.
  - The implementation may add a dedicated PKI signer service/controller; this is required because cert-manager’s built-in CA issuer stores private keys in Secrets and SPIRE has no built-in TPM KeyManager.
  - References used: Kubernetes kubeadm external CA and v1.36 release docs, Flatcar release/kubeadm/security docs, Kustomize docs, Istio SPIRE and ambient limitation docs, cert-manager external issuer docs, SPIRE plugin docs, Calico docs, Knative YAML install docs.

