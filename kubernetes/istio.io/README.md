# istio.io

This directory catalogs Istio KRM that a deployment may import. It contains no
domain-level kustomization and does not combine the control plane with policy.

| Path | Provides |
| --- | --- |
| `istio` | Pinned Istio control plane plus standard ingress and egress gateways |
| `mesh-security` | Mesh-wide STRICT mTLS policy |

Import the policy only after the consuming deployment has established the
required Istio APIs and workload identity path.
