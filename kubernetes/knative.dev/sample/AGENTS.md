# Knative Sample

## Scope

This directory owns the Knative validation sample. `source` is the authored
input. `localized` is the checked-in render. The root exposes the render to a
later test or deployment pipeline; it does not install Knative itself.

Do not hand-edit `localized`. Keep sample dependencies explicit and do not
import vars, labels, annotations, or names from another project.

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

Change the sample only in `source`, rerender from scratch, and verify the tree.
Runtime validation requires the relevant Serving and Eventing APIs but should
not be encoded as a repository-wide aggregate kustomization.
