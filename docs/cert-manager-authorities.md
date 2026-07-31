# cert-manager Authority Wiring

cert-manager is the Kubernetes certificate lifecycle surface for the cluster.
Services should request certificates through cert-manager `Certificate`
resources, and cert-manager should create, approve, renew, and write the issued
leaf certificate Secrets.

## Authority Objects

The non-control-plane CAs from `pki/ca-hierarchy.yaml` are exposed to
cert-manager as TPM-backed external issuer authorities:

- `cert-manager-local-ca`
- `spire-upstream-ca`
- `spire-tpm-devid-ca`
- `spire-tpm-endorsement-ca`

The authority manifests live in
`k8s/components/cert-manager/base/resources/20-tpm-cluster-issuer.yaml`.
Each object is a `TPMClusterIssuer` in API group `pki.sovereignite.io`, with the
CA public certificate loaded from a ConfigMap and the CA signing key selected by
PKCS#11 label. CA private keys stay hardware-resident and are not stored in
Kubernetes Secrets.

## Request Flow

The intended flow is:

```text
Certificate -> CertificateRequest -> TPMClusterIssuer controller -> Certificate status -> target Secret
```

cert-manager's external issuer contract keys off
`CertificateRequest.spec.issuerRef.name`, `kind`, and `group`. The
`tpm-cluster-issuer` controller watches for:

```yaml
issuerRef:
  group: pki.sovereignite.io
  kind: TPMClusterIssuer
  name: cert-manager-local-ca
```

The cert-manager controller is granted approval rights for these external
signers by
`k8s/components/cert-manager/base/resources/21-tpm-cluster-issuer-approval-rbac.yaml`.
Without that RBAC, cert-manager can create `CertificateRequest` resources but
the TPM issuer refuses to sign them because they are not approved.

## Consumers

Knative Serving is configured to use cert-manager for certificate provisioning
and points its external, cluster-local, and system-internal issuer references at
`cert-manager-local-ca` through the normal cert-manager object reference fields.

SPIRE SVID issuance remains SPIRE's workload identity flow. The SPIRE CA keys
are still represented by TPM-backed authority objects so cert-manager can own
ordinary Kubernetes certificate lifecycle for any Kubernetes Secret-backed
certificates that need those CAs.

## References

- cert-manager external issuers: https://cert-manager.io/docs/contributing/external-issuers/
- cert-manager CertificateRequest issuer refs and external approver RBAC: https://cert-manager.io/docs/usage/certificaterequest/
- Knative cert-manager integration: https://knative.dev/docs/serving/encryption/configure-certmanager-integration/
