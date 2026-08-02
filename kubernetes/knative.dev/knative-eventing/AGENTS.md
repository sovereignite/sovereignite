# Knative Eventing

## Scope

This directory owns the minimal `KnativeEventing` resource consumed by the
Knative Operator. `source` contains the namespace and CR. `localized` is the
checked-in render. The root exposes that render to later pipeline stages.

Do not add raw Eventing release manifests, default Brokers, or Channels unless
they become explicit requirements of this work boundary. Do not hand-edit
`localized` or import vars and transformations from another project.

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

The operator owns the installed Eventing stack. Change only supported
`KnativeEventing` fields in `source`, rerender, and confirm that the output
still contains one Namespace and one `KnativeEventing`.
