# Istio

## Scope

This directory renders the pinned Istio Helm inputs for the control plane and
the standard ingress and egress gateways. `source` owns chart versions and the
small project-specific Istio configuration. `localized` is checked-in rendered
KRM. The root is a pipeline boundary and is not necessarily deployable alone.

Keep Knative configuration out of this directory. Preserve Helm chart defaults
for both gateway deployments; the egress gateway's `service.type: ClusterIP` is
the only gateway value override. Do not hand-edit `localized`.

## Render And Verify

Run from this directory:

```sh
rm -rf localized source/charts
mkdir localized
kustomize build source --enable-helm -o localized
(cd localized && kustomize init --autodetect --recursive)
rm -rf source/charts
kustomize cfg tree .
kustomize build . >/dev/null
```

The final tree must contain `Deployment/istiod`,
`Deployment/istio-ingressgateway`, and `Deployment/istio-egressgateway` in
`istio-system`.

## Upgrades

Update every Istio chart version together in `source/kustomization.yaml`,
rerender from scratch, remove the transient chart cache, and review the tree
and generated diff. Do not import values files or transformers from another
project.
