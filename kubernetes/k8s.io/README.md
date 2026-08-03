# k8s.io

This directory catalogs Kubernetes SIG API resources that a deployment may
import. It contains no aggregate kustomization.

| Path | Provides |
| --- | --- |
| `gateway-api` | Pinned Gateway API CRDs and admission policy resources |

Consumers choose this boundary explicitly before importing resources that use
Gateway API kinds.
