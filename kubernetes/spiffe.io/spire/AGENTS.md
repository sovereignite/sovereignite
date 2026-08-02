# SPIRE

## Scope

This directory owns the project SPIRE server, agent, controller-manager APIs,
configuration, registration policy, and node entries. `source` is the authored
authority. `localized` is the checked-in rendered KRM output. The root exposes
that output to later pipeline stages and is not necessarily deployable alone.

Do not hand-edit `localized`. Keep inter-resource names and namespaces stable,
and do not introduce vars, labels, annotations, or naming from another project.

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

Update images, APIs, and project configuration only in `source`. Rerender from
scratch and review the complete tree because SPIRE server, agent, controller,
TPM trust material, and registration resources are coupled by explicit names.
