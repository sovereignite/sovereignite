# spiffe.io

This directory catalogs SPIFFE and SPIRE KRM that a deployment may import. It
contains no aggregate kustomization.

| Path | Provides |
| --- | --- |
| `spire` | SPIRE server, agent, controller-manager APIs, configuration, and registration resources |

The boundary expects its separately maintained TPM and certificate inputs to be
available when a consuming deployment executes it.
