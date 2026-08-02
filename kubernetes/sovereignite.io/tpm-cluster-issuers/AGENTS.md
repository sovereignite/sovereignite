# TPM Cluster Issuers

## Scope

This directory owns the project `TPMClusterIssuer` instances and their
cert-manager approval RBAC. `source` contains authored inputs. `localized` is
the checked-in render. The root only exposes that render to later composition.

Do not hand-edit `localized`. Keep issuer names, signer names, and approval RBAC
resource names aligned. Do not carry vars or naming from another project.

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

Make issuer or RBAC changes only in `source`, rerender from scratch, and verify
the tree. Coordinate API changes with the separately maintained
`tpm-cluster-issuer` controller boundary.
