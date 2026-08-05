# Repository Structure

## Services

| Service | Role |
| --- | --- |
| `keymanager` | Non-exportable TPM signing keys by reviewed role and persistent-handle policy |
| `libp2p-init` | Lifetime-stable libp2p identity from TPM signing key |
| `ipfs` | Full Kubo node with TPM-backed IPNS signing and publication |
| `trust` | Trust domain management and certificate issuance |
| `discovery` | mDNS/BLE discovery broadcaster |
| `bootstrap` | Nine-step cluster bootstrap orchestrator |
| `keyvalidation` | gRPC key validation and JWT issuance |

## Layout

```
cmd/                          Service entry points
internal/                     Domain packages
pkg/api/proto/sovereignite/v1 Protobuf/gRPC API
kubernetes/sovereignite.io/   DaemonSet kustomizations
os/systemd/                   systemd unit files
.github/workflows/            CI/CD pipelines
```
