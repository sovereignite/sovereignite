# tigera.io

This directory catalogs Tigera and Calico KRM that a deployment may import. It
contains no domain-level kustomization; each lifecycle step remains explicit.

| Path | Provides |
| --- | --- |
| `tigera-operator` | Pinned Tigera operator controller and RBAC |
| `installation` | Calico `Installation/default` configuration |
| `apiserver` | Calico `APIServer/default` configuration |

Consumers normally establish the operator before importing the two lifecycle
resources, but this catalog does not aggregate or apply them.
