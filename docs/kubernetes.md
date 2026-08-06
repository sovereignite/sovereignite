# Kubernetes

## Reusable Process

Directory structure = label hierarchy.

kustomization.yaml applies labels at each level.

kpt validates the structure.

Gatekeeper validates labels match directory paths.

### Pattern

```
<any-domain>/
├── kustomization.yaml
│   └── app.kubernetes.io/part-of: <domain>
│
└── <app>/
    ├── kustomization.yaml
    │   └── app.kubernetes.io/name: <app>
    │
    ├── <component>/
    │   ├── kustomization.yaml
    │   │   └── app.kubernetes.io/component: <component>
    │   │
    │   └── <instance>/
    │       ├── kustomization.yaml
    │       │   └── app.kubernetes.io/instance: <instance>
    │       │
    │       └── *.yaml
    │
    └── <component>/
        ├── kustomization.yaml
        │   └── app.kubernetes.io/component: <component>
        │
        └── <instance>/
            ├── kustomization.yaml
            │   └── app.kubernetes.io/instance: <instance>
            │
            └── *.yaml
```

### Gatekeeper Validates

- Directory path = label values
- kustomization.yaml applies label for its level
- Resources in correct directories

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
