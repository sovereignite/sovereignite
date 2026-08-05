# Kubernetes

DaemonSets are under `kubernetes/sovereignite.io/<service>/` with the
`source/`→`localized/` pattern. Edit values in `source/kustomization.yaml`
and render with:

```bash
kustomize build kubernetes/sovereignite.io/keymanager/source
```

## Dependency Chain

Services start in order:
1. `keymanager` — TPM key initialization
2. `libp2p-init` — libp2p identity from TPM
3. `ipfs` — Kubo node with IPNS signing
4. `trust` — trust domain and certificates
5. `discovery` — mDNS/BLE broadcaster
6. `bootstrap` — cluster orchestration
7. `keyvalidation` — gRPC validation

Each service's DaemonSet waits for its dependencies via init containers.
