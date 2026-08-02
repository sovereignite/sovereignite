# Knative Serving

## Scope

This directory owns the minimal `KnativeServing` resource consumed by the
Knative Operator. `source` contains the namespace and CR. `localized` is the
checked-in render. The root passes that render to later pipeline stages and is
not an aggregation of the stack rendered by the operator.

Keep this CR minimal: project certificate settings, domain settings, and the
Istio gateway selectors required to attach to existing gateway deployments.
Do not add raw Serving release manifests or gateway workloads here. Do not
hand-edit `localized`.

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

The operator owns the installed Serving stack. Update only supported
`KnativeServing` fields in `source`, rerender, and confirm that the output still
contains one Namespace and one `KnativeServing`. Never copy configuration vars
from another project.
