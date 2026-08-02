# Knative Operator

## Scope

This directory acquires a pinned Knative Operator release. `source` owns the
release URL. `localized` is its checked-in rendered output. The root makes that
output available to later pipeline stages; it does not aggregate the Knative
Serving or Eventing resources.

Do not edit generated files under `localized` and do not import external vars,
labels, annotations, or naming.

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

Update the pinned operator release in `source/kustomization.yaml`, rerender from
scratch, and verify that the `KnativeServing` and `KnativeEventing` CRDs remain
present before updating their separate work boundaries.
