# Sovereignite

Secure Kubernetes Platform for Everyone.

## Services

| Service | Description |
| --- | --- |
| `keymanager` | Non-exportable TPM signing keys by reviewed role and persistent-handle policy |
| `libp2p-init` | Lifetime-stable libp2p identity from TPM signing key |
| `ipfs` | Full Kubo node with TPM-backed IPNS signing and publication |
| `trust` | Trust domain management and certificate issuance |
| `discovery` | mDNS/BLE discovery broadcaster |
| `bootstrap` | Nine-step cluster bootstrap orchestrator |
| `keyvalidation` | gRPC key validation and JWT issuance |

## Build

```bash
ko build --local ./cmd/keymanager
```

All 7 services are defined in `.ko.yaml` and built with `ko`. Container images are
`linux/amd64` with `CGO_ENABLED=1` on a Fedora 44 base.

## Kubernetes

DaemonSets are under `kubernetes/sovereignite.io/<service>/` with the
`source/`→`localized/` pattern. Edit values in `source/kustomization.yaml`
and render with:

```bash
kustomize build kubernetes/sovereignite.io/keymanager/source
```

## CI/CD

GitHub Actions workflows build and push images to `ghcr.io/sovereignite/sovereignite`.
Per-service workflows trigger only on their own code paths.

## Repository Structure

```
cmd/                          Service entry points
internal/                     Domain packages
pkg/api/proto/sovereignite/v1 Protobuf/gRPC API
kubernetes/sovereignite.io/   DaemonSet kustomizations
.os/systemd/                 systemd unit files
.github/workflows/            CI/CD pipelines
```
