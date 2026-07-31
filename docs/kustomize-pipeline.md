# Kustomize Pipeline

Each component has two entrypoints:

- `source/`: pinned upstream release YAML or Helm chart inputs.
- `base/`: local, deployable Kustomize base consumed by overlays.

The source tree is never applied to a cluster. To refresh upstream manifests:

```bash
scripts/materialize-k8s-components.sh
```

For each upstream component the script:

1. Runs `kustomize localize` into `k8s/components/<component>/vendor`.
2. Runs `kustomize build` from the localized vendor directory.
3. Splits the rendered result into deterministic YAML files under
   `k8s/components/<component>/base/upstream/resources`.
4. Rewrites only `k8s/components/<component>/base/upstream/kustomization.yaml`.

Local hardening, issuer, Gateway, mesh, and Knative configuration files remain
under `base/resources` and are not overwritten.

The deployable path is:

```bash
kubectl apply -k k8s/overlays/local
```

Validate that this path remains local-only:

```bash
scripts/verify-repo.sh
```
