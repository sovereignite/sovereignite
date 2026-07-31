# TPM-Backed PKI Contract

`pki/ca-hierarchy.yaml` is the source of truth for CA names, PKCS#11 labels,
certificate profiles, and rotation windows.

## Required Properties

- Root and subordinate CA signing keys are TPM-resident.
- Kubernetes nodes receive CA public certificates and pre-signed leaf
  certificates only.
- No `ca.key` or `*-ca.key` file may be staged into Ignition, node PKI bundles,
  Kubernetes Secrets, or `/etc/kubernetes/pki`.
- kube-controller-manager runs without the built-in CSR signing controller.
- kubelet client and serving CSR rotation is handled by
  `k8s-tpm-csr-signer`.
- cert-manager is the lifecycle and request-flow surface for Kubernetes
  `Certificate` resources.
- Non-control-plane CAs are represented as `TPMClusterIssuer` authorities, not
  built-in CA issuers with private-key Secrets.
- SPIRE server CA signing uses the external TPM KeyManager plugin.

See `docs/cert-manager-authorities.md` for the cert-manager authority wiring.

## Expected Output Layout

```text
build/pki/
  root-ca.crt
  kubernetes/
    ca.crt
    front-proxy-ca.crt
    etcd/ca.crt
  cert-manager/
    ca.crt
  spire/
    upstream-ca.crt
    tpm-devid-ca.crt
    tpm-endorsement-ca.crt
  tpm-devid/
    cp-1/
      devid.crt
      devid.priv.blob
      devid.pub.blob
  nodes/
    cp-1/
      pki/
        ca.crt
        apiserver.crt
        apiserver.key
        apiserver-kubelet-client.crt
        apiserver-kubelet-client.key
        front-proxy-ca.crt
        front-proxy-client.crt
        front-proxy-client.key
        etcd/ca.crt
        etcd/server.crt
        etcd/server.key
        etcd/peer.crt
        etcd/peer.key
        etcd/healthcheck-client.crt
        etcd/healthcheck-client.key
        sa.pub
        sa.key
      etc-kubernetes/
        admin.conf
        controller-manager.conf
        scheduler.conf
        super-admin.conf
        kubelet.conf
    cp-2/
      ...
    worker-1/
      pki/
        ca.crt
      etc-kubernetes/
        kubelet.conf
```

`sa.key` is a Kubernetes service-account signing key, not a CA key. Keep it
restricted to control-plane nodes.

The `spire/tpm-devid-ca.crt` and `spire/tpm-endorsement-ca.crt` files populate
the `spire-tpm-attestor-ca` ConfigMap used by the built-in SPIRE `tpm_devid`
NodeAttestor.

Each directory under `build/pki/tpm-devid/<node>` is staged to
`/var/lib/sovereignite/tpm` on that node for SPIRE agent attestation.

## Staging Guard

Run this before copying PKI to nodes:

```bash
scripts/assert-no-ca-private-keys.sh
```

`scripts/generate-kubeadm-external-pki.sh` creates the kubeadm external-CA
bundle by signing kubeadm-generated CSRs with TPM-resident CA keys on the CA
node. `scripts/stage-kubeadm-pki-to-nodes.sh` repeats the no-CA-key check per
node before copying kubeadm PKI into `/etc/kubernetes/pki` and signed
kubeconfigs into `/etc/kubernetes`.

`scripts/stage-pki-to-nodes.sh` remains the full PKI staging path once SPIRE TPM
DevID material exists for every node.
