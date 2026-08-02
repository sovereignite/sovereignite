# Mesh Security

## Scope

This directory owns the mesh-wide Istio security policy. `source` contains the
authored policy. `localized` is the checked-in render. The root makes that
output available to later pipeline stages.

Do not hand-edit `localized`. Keep this work boundary independent from the
Istio chart rendering and Knative configuration. Do not import transformations
or naming from another project.

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

Change the policy API or behavior only in `source`, rerender, and confirm the
tree still contains the intended `PeerAuthentication` identity and namespace.
