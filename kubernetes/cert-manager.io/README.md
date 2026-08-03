# cert-manager.io

This directory catalogs cert-manager KRM that a deployment may import. It is a
lexical catalog only and has no aggregate kustomization.

| Path | Provides |
| --- | --- |
| `cert-manager` | Pinned, rendered cert-manager controllers, CRDs, and RBAC |

Project-specific issuers are intentionally separate under
`../sovereignite.io/tpm-cluster-issuers`.
