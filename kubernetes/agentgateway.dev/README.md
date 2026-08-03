# agentgateway.dev

This directory catalogs Agentgateway KRM that a deployment may import. It is
not a kustomization and does not aggregate its children. Import only the exact
deliverable path required by the consuming pipeline.

| Path | Provides |
| --- | --- |
| `crds` | Agentgateway custom resource definitions |
| `agentgateway` | Agentgateway controller and service resources |
| `agentgateway-proxy` | Gateway and namespace resources for the proxy |
| `test/httpbin` | HTTPBin validation workload |
| `test/httpbin-route` | HTTPRoute for the HTTPBin validation workload |

The test inputs are optional and are not implied by importing Agentgateway.
