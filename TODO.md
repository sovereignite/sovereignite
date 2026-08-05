# Sovereignite Work State

## Current State Assessment

### What Exists

| Component | Path | Status |
|-----------|------|--------|
| Go module | `go.mod` | `github.com/sovereignite/sovereignite`, Go 1.26 |
| TPM DevID Provisioner | `cmd/tpm-devid-provisioner/` | Complete. Creates SRK + DevID in TPM, writes public blobs. |
| k8s-tpm-csr-signer | `controllers/k8s-tpm-csr-signer/` | Complete. Polling controller, signs Kubernetes CSRs via PKCS#11. |
| tpm-cluster-issuer | `controllers/tpm-cluster-issuer/` | Complete. Polling controller, signs cert-manager CertificateRequests via PKCS#11. |
| spire-tpm-keymanager | `controllers/spire-tpm-keymanager/` | Complete. SPIRE KeyManager plugin via PKCS#11. |
| spire-tpm-keymanager-controller | `controllers/spire-tpm-keymanager-controller/` | Complete. Reconciles SPIRETPMKeyManager CRs. |
| signing package | `controllers/internal/signing/` | Complete. PKCS#11 CSR signing, validation, cert creation. |
| kubeapi package | `controllers/internal/kubeapi/` | Complete. Raw HTTP in-cluster Kubernetes API client. |
| Libvirt infrastructure | `infra/libvirt/` | Complete. 8 VMs (3 cp, 5 worker), shared FCOS ISO, OVMF Secure Boot, TPM2 emulator. |
| Kubernetes overlays | `kubernetes/` | Complete. Kustomize overlays for Calico, cert-manager, Gateway API, Istio, Knative, SPIRE, etc. |
| Rendered K8s manifests | `build/k8s/rendered/` | Present. calico.yaml, cert-manager.yaml, gateway-api.yaml, istio.yaml, knative-*.yaml. |
| Butane template | `infra/libvirt/butane/node.bu.tmpl` | Present. Shell-var-substituted template for node config. NOT used (no Ignition). |
| Cluster inventory | `infra/libvirt/cluster.inventory.yaml` | Complete. 8-node spec with versions, network, firmware, TPM, kubeadm, calico. |
| Development cluster spec | `DEVELOPMENT_CLUSTER.md` | Complete. IPv6 ULA allocation, pod/service CIDRs, Calico config. |
| Zettelkasten | `ZETTELKASTEN.md` | 4 notes on bootstrap order, namespace, inbound traffic, IPv6 derivation. |

### What Does NOT Exist (Required by INVENTORY.md)

| Component | Expected Path | Status |
|-----------|---------------|--------|
| **internal/tpm** | `internal/tpm/` | MISSING. Fail-closed TPM 2.0 backend. |
| **internal/shared** | `internal/shared/` | MISSING. Canonical identity test vector. |
| **internal/endpoint** | `internal/endpoint/` | MISSING. Boot-scoped endpoint registry. |
| **internal/mtls** | `internal/mtls/` | MISSING. Strict TLS 1.3 mTLS configs. |
| **internal/network** | `internal/network/` | MISSING. Certificate-auth Wi-Fi modeling. |
| **cmd/keymanager** | `cmd/keymanager/` | MISSING. TPM key manager service. |
| **cmd/libp2p-init** | `cmd/libp2p-init/` | MISSING. libp2p identity from TPM. |
| **cmd/ipfs** | `cmd/ipfs/` | MISSING. Kubo node with TPM IPNS. |
| **cmd/bootstrap** | `cmd/bootstrap/` | MISSING. 9-step cluster bootstrap orchestrator. |
| **cmd/discovery** | `cmd/discovery/` | MISSING. mDNS/BLE discovery broadcaster. |
| **cmd/keyvalidation** | `cmd/keyvalidation/` | MISSING. gRPC key validation. |
| **internal/bootstrap** | `internal/bootstrap/` | MISSING. Bootstrap service core. |
| **internal/discovery** | `internal/discovery/` | MISSING. Discovery service core. |
| **internal/ipfs** | `internal/ipfs/` | MISSING. IPFS service core. |
| **internal/keymanager** | `internal/keymanager/` | MISSING. Key manager core. |
| **internal/keyvalidation** | `internal/keyvalidation/` | MISSING. Key validation core. |
| **internal/libp2p** | `internal/libp2p/` | MISSING. libp2p init core. |
| **os/systemd/** | `os/systemd/` | MISSING. All systemd unit files. |
| **pkg/api/proto/** | `pkg/api/proto/sovereignite/v1/` | MISSING. Protobuf/gRPC API definitions. |
| **proto/** | `proto/` | MISSING. Protobuf generation toolchain. |

### Dependency Chain (Build Order)

```
Layer 0 (Foundation):
  internal/shared          - Identity derivation, ULA computation
  internal/tpm             - TPM 2.0 backend, non-exportable keys
  internal/endpoint        - Boot-scoped endpoint registry

Layer 1 (Core Services):
  cmd/keymanager           - Depends on: internal/tpm, internal/endpoint
  internal/keymanager

Layer 2 (Identity):
  cmd/libp2p-init          - Depends on: internal/keymanager, internal/endpoint
  internal/libp2p

Layer 3 (Content):
  cmd/ipfs                 - Depends on: internal/libp2p, internal/endpoint
  internal/ipfs

Layer 4 (Trust):
  cmd/trust                - Depends on: internal/keymanager, internal/libp2p, internal/ipfs
  internal/trust

Layer 5 (Network):
  cmd/discovery            - Depends on: internal/libp2p, internal/trust
  internal/discovery
  internal/mtls            - Depends on: internal/trust

Layer 6 (Orchestration):
  cmd/bootstrap            - Depends on: all above
  internal/bootstrap

Layer 7 (Validation):
  cmd/keyvalidation        - Depends on: internal/tpm, internal/mtls
  internal/keyvalidation

Layer 8 (Systemd):
  os/systemd/              - Units for all services

Layer 9 (Deploy):
  Build binaries, deploy to nodes, run bootstrap
```

## Execution Plan

### Phase 1: Foundation Packages

#### 1.1 internal/shared
- [ ] Create `internal/shared/identity.go` - Canonical identity test vector
- [ ] Deterministic Ed25519 public key DER
- [ ] libp2p peer ID derivation
- [ ] Lowercase base36 CIDv1/IPNS name
- [ ] Deterministic IPv6 ULA `/48` from project name
- [ ] Validation that recomputes peer ID, CID/IPNS, ULA
- [ ] Unit tests

#### 1.2 internal/tpm
- [ ] Create `internal/tpm/tpm.go` - Fail-closed TPM 2.0 backend
- [ ] Open configured Linux TPM device
- [ ] Validate owner/object auth
- [ ] Bound HMAC sessions
- [ ] Prepare persistent handles
- [ ] Verify canonical public areas
- [ ] Expose public metadata and signing only
- [ ] No private export, duplication, unseal, auth retrieval, or software fallback
- [ ] Unit tests

#### 1.3 internal/endpoint
- [ ] Create `internal/endpoint/endpoint.go` - Boot-scoped endpoint registry
- [ ] Publish endpoint JSON to `/run/sovereignite/<service>/endpoint.json`
- [ ] Read and validate endpoint records
- [ ] Atomic rename semantics
- [ ] Owner-only file creation (mode 0600)
- [ ] Current boot ID validation
- [ ] Cleanup stale endpoints
- [ ] Unit tests

### Phase 2: Key Manager

#### 2.1 internal/keymanager
- [ ] Create `internal/keymanager/keymanager.go` - Key manager core
- [ ] Manage non-exportable TPM signing keys by reviewed role
- [ ] Persistent-handle policy
- [ ] Persist public-only metadata
- [ ] Verify live TPM state before use
- [ ] Initialization mode
- [ ] Rotation/recovery support
- [ ] Purpose-scoped certificate issuance behind policy hook
- [ ] Unit tests

#### 2.2 cmd/keymanager
- [ ] Create `cmd/keymanager/main.go` - Key manager command
- [ ] CLI modes: `run` (long-running gRPC), `initialize` (one-shot)
- [ ] Flags: `-device` (TPM device path), `-metadata-path`
- [ ] gRPC server on configurable address
- [ ] Readiness publication to `/run/sovereignite/keymanager/ready.json`
- [ ] Unit tests

### Phase 3: Identity

#### 3.1 internal/libp2p
- [ ] Create `internal/libp2p/libp2p.go` - libp2p init core
- [ ] Initialize lifetime-stable libp2p identity from TPM signing key
- [ ] Persist public identity metadata
- [ ] Set hostname to canonical IPNS/libp2p-key name
- [ ] Require real libp2p host
- [ ] Publish boot-scoped local readiness
- [ ] Unit tests

#### 3.2 cmd/libp2p-init
- [ ] Create `cmd/libp2p-init/main.go` - libp2p init command
- [ ] Defaults: state `/var/lib/sovereignite/identity`, runtime `/run/sovereignite/identity`
- [ ] gRPC identity API on loopback
- [ ] Readiness publication to `/run/sovereignite/identity/endpoint.json`
- [ ] Unit tests

### Phase 4: Content

#### 4.1 internal/ipfs
- [ ] Create `internal/ipfs/ipfs.go` - IPFS service core
- [ ] Fail-closed service boundary
- [ ] Maintain full Kubo node
- [ ] TPM-backed IPNS signing
- [ ] Public Trust publication snapshots
- [ ] Monotonic pre-signed IPNS records
- [ ] Durable publication state
- [ ] Boot-scoped readiness
- [ ] Unit tests

#### 4.2 cmd/ipfs
- [ ] Create `cmd/ipfs/main.go` - IPFS command
- [ ] Defaults: state `/var/lib/sovereignite/ipfs`, runtime `/run/sovereignite/ipfs`
- [ ] Owner-only files, atomic/locked patterns
- [ ] Readiness publication to `/run/sovereignite/ipfs/ready.json`
- [ ] Unit tests

### Phase 5: Trust

#### 5.1 internal/trust
- [ ] Create `internal/trust/trust.go` - Trust service core
- [ ] Owns adoption, relationships, certificates, revocation, public trust state
- [ ] Separates prepared state (after step 5) from complete state (after step 9)
- [ ] Durable journal with intent/commit pairs
- [ ] Stable idempotency keys for crash-safe recovery
- [ ] Unit tests

#### 5.2 cmd/trust
- [ ] Create `cmd/trust/main.go` - Trust command
- [ ] gRPC server on loopback
- [ ] Readiness publication to `/run/sovereignite/trust/ready.json`
- [ ] Unit tests

### Phase 6: Network

#### 6.1 internal/mtls
- [ ] Create `internal/mtls/mtls.go` - Strict TLS 1.3 mTLS
- [ ] X.509 SVID-style SPIFFE URI SANs
- [ ] Validate local certs
- [ ] Verify peer chains and trust domains
- [ ] Check SPIFFE ID shape
- [ ] Delegate identity authorization to caller-provided validators
- [ ] Unit tests

#### 6.2 internal/discovery
- [ ] Create `internal/discovery/discovery.go` - Discovery service core
- [ ] Validate strict discovery record
- [ ] Advertise over mDNS and BLE/BlueZ
- [ ] Local gRPC methods: start, stop, list
- [ ] Unit tests

#### 6.3 cmd/discovery
- [ ] Create `cmd/discovery/main.go` - Discovery command
- [ ] Config precedence: flags > env > `/run/sovereignite/discovery/config.env`
- [ ] Required: device ID, trust domain, adoption state, service port, BLE UUID, BlueZ adapter
- [ ] Readiness publication to `/run/sovereignite/discovery/ready.json`
- [ ] Unit tests

### Phase 7: Bootstrap

#### 7.1 internal/bootstrap
- [ ] Create `internal/bootstrap/bootstrap.go` - Bootstrap orchestrator core
- [ ] Nine-step v5 cluster bootstrap sequence
- [ ] Step 1: CA signing
- [ ] Step 2: kubelet config
- [ ] Step 3: Calico IPv6 ULA
- [ ] Step 4: Istio ingress
- [ ] Step 5: SPIRE TPM config
- [ ] Step 6: Kubernetes API server
- [ ] Step 7: control-plane wait
- [ ] Step 8: cluster config apply
- [ ] Step 9: final readiness
- [ ] Record durable public evidence
- [ ] Separate prepared (after 5) from complete (after 9)
- [ ] In-memory journal with component adapters
- [ ] Unit tests

#### 7.2 cmd/bootstrap
- [ ] Create `cmd/bootstrap/main.go` - Bootstrap command
- [ ] Local gRPC server on ephemeral loopback
- [ ] Readiness: prepared at `/run/sovereignite/bootstrap/prepared.json`, complete at `/run/sovereignite/bootstrap/complete.json`
- [ ] Unit tests

### Phase 8: Validation

#### 8.1 internal/keyvalidation
- [ ] Create `internal/keyvalidation/keyvalidation.go` - Key validation core
- [ ] gRPC `ValidateKey` handler
- [ ] gRPC `IssueJWT` handler
- [ ] Unit tests

#### 8.2 cmd/keyvalidation
- [ ] Create `cmd/keyvalidation/main.go` - Key validation command
- [ ] gRPC server on configurable address, default `127.0.0.1:0`
- [ ] Unit tests

### Phase 9: Systemd Units

- [ ] Create `os/systemd/sovereignite-tpm-firstboot.service`
- [ ] Create `os/systemd/sovereignite-keymanager.service`
- [ ] Create `os/systemd/sovereignite-libp2p-init.service`
- [ ] Create `os/systemd/sovereignite-ipfs.service`
- [ ] Create `os/systemd/sovereignite-trust.service`
- [ ] Create `os/systemd/sovereignite-discovery.service`
- [ ] Create `os/systemd/sovereignite-bootstrap.service`
- [ ] Create `os/systemd/sovereignite-pre-kubernetes.target`
- [ ] Create `os/systemd/sovereignite-wait-ready` (readiness helper)

### Phase 10: Build & Deploy

- [ ] Add `.ko.yaml` for each service (fedora:44 base, linux/amd64, CGO_ENABLED=1, ldflags -s -w)
- [ ] Build all service images via `ko build`
- [ ] Transfer container images to nodes
- [ ] Install systemd units on nodes
- [ ] Start services in dependency order
- [ ] Verify readiness chain completes
- [ ] Run cluster bootstrap (kubeadm init/join via bootstrap service)

### Phase 11: Kubernetes Kustomizations

Each service gets `kubernetes/sovereignite.io/<service>/` following the
existing `source/` → `localized/` pattern, with `images:` and `replacements:`
for configurability.

- [ ] `kubernetes/sovereignite.io/keymanager/` — DaemonSet, TPM device mount, image/replacements
- [ ] `kubernetes/sovereignite.io/libp2p-init/` — DaemonSet, identity state mount, image/replacements
- [ ] `kubernetes/sovereignite.io/ipfs/` — DaemonSet, IPFS state mount, image/replacements
- [ ] `kubernetes/sovereignite.io/trust/` — DaemonSet, trust state mount, image/replacements
- [ ] `kubernetes/sovereignite.io/discovery/` — DaemonSet, BLE/Bluetooth device, image/replacements
- [ ] `kubernetes/sovereignite.io/bootstrap/` — DaemonSet, Kubernetes config mounts, image/replacements
- [ ] `kubernetes/sovereignite.io/keyvalidation/` — DaemonSet, image/replacements
- [ ] Each source kustomization.yaml has `images:` for ko-built image and `replacements:` for namespace, image tag, node selector, TPM paths
- [ ] Render each via `kustomize build source -o localized`

## Work Log

| Date | Action | Result |
|------|--------|--------|
| 2026-08-04 | Infrastructure audit | 8 VMs exist, all shut off. Shared FCOS ISO present. No services. |
| 2026-08-04 | INVENTORY.md vs reality audit | INVENTORY.md describes planned state. Most services don't exist. |
| 2026-08-04 | Dependency chain mapped | 10-layer build order documented above. |
| 2026-08-04 | TODO created | This file. |
| 2026-08-04 | go.mod dependencies synced from archive | libp2p, CID, zeroconf, D-Bus, netlink, multiformats added; `go build ./...` clean. |
| 2026-08-04 | internal/shared built | Peer ID, IPNS name, ULA derivation with 7 passing tests. |
| 2026-08-04 | internal/tpm built | Open/Close/ReadPublic with fail-closed boundary. |
| 2026-08-04 | internal/endpoint built | Publish/Read/Validate/Cleanup with atomic rename, boot ID, 5 passing tests. |
| 2026-08-04 | Archive source tree migrated | 146 Go files, 2 proto files extracted from tarball. Module path replaced `sovereignite.net` → `github.com/sovereignite/sovereignite`. `go build ./...` clean. |
| 2026-08-04 | Proto regenerated from .proto source | Fixed corrupted raw descriptor (sed had mangled binary blob). `go_package` updated to new module path. `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc` via nix dev shell. |
| 2026-08-04 | ULA test vectors updated | Domain separator changed from `sovereignite.net` → `github.com/sovereignite/sovereignite`. Updated 3 golden test vectors across `internal/shared` and `internal/ipfs`. All 18 packages pass. |
| 2026-08-04 | Flake updated with proto tooling | Added `protobuf`, `protoc-gen-go`, `protoc-gen-go-grpc` to nix dev shell. |
| 2026-08-04 | .ko.yaml created | Root `.ko.yaml` with builds for all 7 services (fedora:44, linux/amd64, CGO_ENABLED=1, ldflags -s -w). |
| 2026-08-04 | Kustomize DaemonSets created | 7 services: keymanager, libp2p-init, ipfs, trust, discovery, bootstrap, keyvalidation. Each with source/ and localized/, images transformer at top, init container dependency chain, TPM/DBus/containerd volume mounts. All source kustomizations validate. |

## Decisions

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-08-04 | All services built into containers via `ko` | Consistent with existing controller build pattern (fedora:44 base, linux/amd64, CGO). |
| 2026-08-04 | New services deploy as DaemonSets with kustomize images:/replacements: | All sovereignite services (keymanager, libp2p-init, ipfs, trust, discovery, bootstrap) get DaemonSets under `kubernetes/sovereignite.io/` following the existing source/localized pattern with configurable image tags and field replacements. |
| 2026-08-04 | Migrate archive sources, not rewrite | The tarball contains the full working Go source tree (146 files). Strategy: extract, adjust module paths (`sovereignite.net` → `github.com/sovereignite/sovereignite`), fix API diffs, test. |

## Open Questions

1. **Protobuf API**: No .proto files exist. Need to define the 5 services, 13 RPCs per INVENTORY.md.
2. **TPM authority reconciliation**: Existing controllers use PKCS#11 directly. Key Manager should become the single TPM authority. How to reconcile?
3. **Single-node vs multi-node kubeadm**: Unresolved decision from system-pathway.md.
4. **First-trust transport**: How does initial trust establishment work physically?
