# cert-manager

## Scope

This directory acquires a pinned cert-manager release and records its rendered
KRM output. `source` owns the release URL. `localized` is generated and checked
in for reproducibility. The root is a pipeline boundary, not a declaration that
this directory is independently deployable.

Never hand-edit `localized` and never import vars or transformations from a
different project.

## Render And Verify

Run from this directory:

```sh
rm -rf localized
mkdir localized
kustomize build source -o localized
(cd localized && kustomize init --autodetect --recursive)
kustomize cfg tree .
kustomize build . >/dev/null
```

## Upgrades

Update the pinned release URL in `source/kustomization.yaml`, rerender from
scratch so removed objects cannot survive, and review the resulting tree and
diff. Keep project issuer resources outside this work boundary.
