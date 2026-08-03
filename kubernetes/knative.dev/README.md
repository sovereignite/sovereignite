# knative.dev

This directory catalogs Knative KRM that a deployment may import. It contains
no domain-level kustomization; operator installation, lifecycle CRs, and tests
remain separate pipeline inputs.

| Path | Provides |
| --- | --- |
| `knative-operator` | Knative Operator APIs and controllers |
| `knative-serving` | Minimal `KnativeServing` lifecycle resource |
| `knative-eventing` | Minimal `KnativeEventing` lifecycle resource |
| `sample` | Optional Serving and Eventing validation sample |

The Serving resource carries only project certificate, domain, and Istio
gateway-selector configuration. It does not include raw Knative release
manifests or separate gateway deployments.
