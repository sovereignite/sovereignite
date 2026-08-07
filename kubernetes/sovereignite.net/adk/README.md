# ADK

Agent Development Kit (ADK) for Sovereignite.

## Labels

This package uses the [Kubernetes recommended labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/).

| Label | Description | Usage in Our Setup |
|-------|-------------|-------------------|
| `app.kubernetes.io/name` | The name of the application | Each application (e.g., `shipcrew`) |
| `app.kubernetes.io/instance` | A unique name identifying the instance of an application | `default` for the default instance |
| `app.kubernetes.io/version` | The current version of the application | Stamped during build/tag process |
| `app.kubernetes.io/component` | The component within the architecture | Each component (e.g., `controller`, `crds`) |
| `app.kubernetes.io/part-of` | The name of a higher level application this one is part of | `adk` - The ADK system |
| `app.kubernetes.io/managed-by` | The tool being used to manage the operation of an application | `kustomize` - The tool managing these resources |

## Structure

- `shipcrew/` - Shipcrew controller application
