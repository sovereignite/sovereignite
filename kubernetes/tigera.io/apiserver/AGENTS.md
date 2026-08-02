# Tigera API Server

## Scope

This directory is the work boundary for the Tigera `APIServer/default` resource.
`source` is authoritative. `localized` is the checked-in rendered output. The
root kustomization passes that output to later pipeline stages; none of these
boundaries is assumed to be independently deployable.

Do not edit generated files under `localized`. Do not import vars,
transformers, labels, annotations, or names from another project.

## Render And Verify

Run from this directory after changing `source`:

```sh
rm -rf localized
mkdir localized
kustomize build source -o localized
(cd localized && kustomize init --autodetect --recursive)
kustomize cfg tree .
kustomize build . >/dev/null
```

## Upgrades

Keep the API version compatible with the Tigera operator source. Change only
the authored input in `source`, rerender, and review the tree before accepting
the generated diff.
