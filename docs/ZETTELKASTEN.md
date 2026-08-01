# Zettelkasten

FIFO notes. New notes append to the bottom.

## 2026-08-01 - Kustomize Package Conventions

`Zettelkasten` is the spelling. The repository file is
`docs/ZETTELKASTEN.md`.

Kustomize is foundational to the Kubernetes resource model used in this
repository. A directory containing `kustomization.yaml` is a KRM package
boundary. Directories without `kustomization.yaml` are only filesystem taxonomy.
There is no global repository kustomization.

A kustomization is a layer in a resource configuration pipeline. One
kustomization consumes resources, applies declared transformations, and emits a
new configured resource package. That output may become the input resources for
another kustomization.

Each deliverable must be an independently buildable and Argo-addressable
Kustomize package. The deliverable path is the Argo target path. Do not use one
giant application, app-of-apps, or repository-wide kustomization as the security
boundary.

The normal deliverable boundary should not exceed a namespace. Cluster-scoped
resources, CRDs, controllers, and operators are separate deliverables with
separate authority.

Source, captured resources, and deployment consumption are separate concerns:

```text
<package>/
  source/
    kustomization.yaml
  localized/
    kustomization.yaml
    resources/
  kustomization.yaml
```

`source/` is the repeatable resource-production layer. `localized/` is the
captured local KRM artifact. The package root may point at `localized`.
Deployment kustomizations consume deliverable packages from outside the
distributed resource package.

Use Kustomize-native behavior to produce resource files. `kustomize build -o
<directory>` writes resources as files. `kustomize init --autodetect
--recursive` creates the next package manifest from those resources. Do not split
rendered YAML with ad hoc document-index scripts.

Labels and annotations are KRM metadata and pass through kustomization layers.
They are part of the resource contract. Later layers can select resources or
drive substitutions from that metadata when the kustomization declares the
transform.

The SPIRE reference package demonstrates the pattern:

- `commonAnnotations` carries trust metadata on the package resources.
- `buildMetadata` requests managed-by labels and origin annotations.
- `configMapGenerator` creates a local config anchor.
- `vars` read values from metadata annotations on that generated ConfigMap.
- custom transformer configuration extends where substitutions apply.
- imported resources contain placeholders resolved by the package layer.

Kubernetes recommended labels must be applied only by the layer that owns their
meaning:

- `app.kubernetes.io/name`: application or component identity.
- `app.kubernetes.io/instance`: concrete installed instance, only in a consuming
  deployment layer when that layer exists.
- `app.kubernetes.io/version`: version of the owned application or component.
- `app.kubernetes.io/component`: architectural role inside the owned
  application.
- `app.kubernetes.io/part-of`: real parent application membership only; never a
  global ownership stamp over upstream packages.
- `app.kubernetes.io/managed-by`: managing tool or controller for the resource.

Do not relabel upstream or third-party resources as part of a local product.
Composition does not imply ownership.
