# argoproj.io

This directory catalogs Argo KRM that a deployment may import. It contains no
domain-level kustomization. Select deliverables explicitly and compose them in
the required order outside this directory.

| Path | Provides |
| --- | --- |
| `argocd-operator` | Argo CD operator APIs and controller |
| `argocd` | Argo CD instance configuration |
| `argo-workflows` | Argo Workflows installation |
| `argo-events` | Argo Events installation |

Importing one path does not implicitly import any other Argo deliverable.
