# sovereignite.io

This directory catalogs Sovereignite controllers and custom resources that a
deployment may import. It contains no domain-level kustomization and does not
imply an installation order.

| Path | Provides |
| --- | --- |
| `tpm-cluster-issuer` | TPM-backed cert-manager external issuer API and controller |
| `tpm-cluster-issuers` | Project issuer instances and cert-manager approval RBAC |
| `k8s-tpm-csr-signer` | TPM-backed Kubernetes CSR signer API, controller, and policies |
| `spire-tpm-keymanager` | SPIRE TPM key-manager API, controller, and configured resource |

Consumers must establish each controller API before importing custom resources
that depend on it.
