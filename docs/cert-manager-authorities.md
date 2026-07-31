# cert-manager Authority Wiring

cert-manager is the Kubernetes certificate lifecycle surface for the cluster.
Services request certificates through cert-manager `Certificate` resources, and
cert-manager creates, approves, renews, and writes the issued leaf certificate
Secrets.

## Authority Model

`pki/ca-hierarchy.yaml` defines one TPM-backed root CA and multiple TPM-backed
subordinate CAs:

- Root: `sovereignite-root`
- Subordinates: `kubernetes-ca`, `kubernetes-front-proxy-ca`, `etcd-ca`,
  `cert-manager-local-ca`, `spire-upstream-ca`, `spire-tpm-devid-ca`,
  `spire-tpm-endorsement-ca`

Each authority is represented as a `TPMClusterIssuer` in
`k8s/components/cert-manager/base/resources/20-tpm-cluster-issuer.yaml`.
Each issuer loads the CA public certificate from a ConfigMap and selects the CA
signing key by PKCS#11 label. CA private keys stay hardware-resident and are not
stored in Kubernetes Secrets.

## Root And Subordinate Policy

The `sovereignite-root` issuer is the only issuer profile that allows
`CertificateRequest.spec.isCA: true`. It exists so subordinate CA certificates
can flow through cert-manager while the root key remains TPM-resident. Root CA
requests should explicitly set CA usages when authored as `Certificate`
resources; the profile also allows cert-manager's default digital signature and
key encipherment usages so generated requests are not rejected before policy can
be reviewed.

The subordinate issuers are present so normal service and platform certificates
can use cert-manager lifecycle with the correct issuing CA. Their
`requestPolicy.denyCARequests` value stays `true`, so they issue leaf
certificates only unless the hierarchy is deliberately extended later.

## Request Flow

The normal flow is:

```text
Certificate -> CertificateRequest -> TPMClusterIssuer controller -> Certificate status -> target Secret
```

cert-manager's external issuer contract keys off
`CertificateRequest.spec.issuerRef.name`, `kind`, and `group`:

```yaml
issuerRef:
  group: pki.sovereignite.io
  kind: TPMClusterIssuer
  name: cert-manager-local-ca
```

The cert-manager controller is granted approval rights for all TPM-backed
external signers by
`k8s/components/cert-manager/base/resources/21-tpm-cluster-issuer-approval-rbac.yaml`.
Without that RBAC, cert-manager can create `CertificateRequest` resources but
the TPM issuer refuses to sign them because they are not approved.

## Runtime Inputs

The public CA ConfigMaps and the `tpm2-pkcs11-pin` Secret are created by
`scripts/update-ca-configmaps.sh` from `build/pki`. The Secret contains TPM
token PINs only. It does not contain CA private keys.

## Consumers

Knative Serving points its external, cluster-local, and system-internal issuer
references at `cert-manager-local-ca` through the normal cert-manager object
reference fields.

Kubernetes kubelet CSR rotation uses the dedicated `k8s-tpm-csr-signer` path
because it signs Kubernetes CSR API objects rather than cert-manager
`CertificateRequest` objects.

SPIRE SVID issuance remains SPIRE's workload identity flow. SPIRE's Kubernetes
Secret-backed certificates should still use the appropriate TPM-backed issuer
through cert-manager instead of handwritten signing paths.

## References

- cert-manager external issuers: https://cert-manager.io/docs/contributing/external-issuers/
- cert-manager CertificateRequest issuer refs and external approver RBAC: https://cert-manager.io/docs/usage/certificaterequest/
- Knative cert-manager integration: https://knative.dev/docs/serving/encryption/configure-certmanager-integration/
