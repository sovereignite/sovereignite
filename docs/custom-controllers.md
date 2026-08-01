# Custom Controllers

The repository defines the Kubernetes API surface, Go source, Dockerfiles, and
deployment manifests for the custom components required by the TPM-backed PKI
model.

## TPMClusterIssuer

CRD: `tpmclusterissuers.pki.sovereignite.io`
Source: `controllers/tpm-cluster-issuer/cmd/tpm-cluster-issuer`

Purpose:

- Watches cert-manager `CertificateRequest` resources that reference
  `issuerRef.group: pki.sovereignite.io` and
  `issuerRef.kind: TPMClusterIssuer`.
- Keeps cert-manager in charge of `Certificate` lifecycle, renewal, approval,
  and target Secret writes while the controller performs only TPM-backed
  signing.
- Validates requested usages, DNS names, SPIFFE URIs, duration, and approval
  condition.
- Allows CA certificate requests only when the referenced issuer profile is a CA
  profile and issuer policy permits CA requests.
- Signs with a TPM-resident CA key through PKCS#11.
- Writes issued certificates back to the `CertificateRequest` status.

## k8s-tpm-csr-signer

CRD: `tpmcsrsignerpolicies.pki.sovereignite.io`
Source: `controllers/k8s-tpm-csr-signer/cmd/k8s-tpm-csr-signer`

Purpose:

- Watches Kubernetes `CertificateSigningRequest` resources.
- Handles kubelet signer names `kubernetes.io/kube-apiserver-client-kubelet`
  and `kubernetes.io/kubelet-serving`.
- Enforces subject and usage policy before signing.
- Replaces kube-controller-manager file-backed CSR signing.

## spire-tpm-keymanager

CRD: `spiretpmkeymanagers.spire.sovereignite.io`
Plugin source: `controllers/spire-tpm-keymanager/cmd/spire-tpm-keymanager`
Status controller source:
`controllers/spire-tpm-keymanager-controller/cmd/spire-tpm-keymanager-controller`

Purpose:

- Configures and builds the SPIRE external KeyManager plugin.
- Keeps SPIRE CA private keys TPM-resident.
- Exposes plugin state through Kubernetes status without placing CA keys in
  Secrets.

## Build And Verify

```bash
go test ./controllers/...
scripts/build-controller-images.sh
```

The deployable manifests live under `k8s/components/*/base/resources`. The
copies under `controllers/*/config` are kept as the API/controller source
contracts used to produce those local bases.
