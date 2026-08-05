# Sovereignite

Secure Kubernetes Platform for Everyone.

Sovereignite builds secure Kubernetes clusters on hardware you control. Each
node's identity is bound to its TPM chip — a hardware root of trust that
prevents key exfiltration, impersonation, and unauthorized access, even if the
OS is compromised.

## Why Hardware Trust

Traditional Kubernetes clusters protect keys with file permissions. If an attacker
gains root, they can read the private key material and impersonate the node.
Sovereignite's TPM-backed keys never leave the chip — signing happens in
hardware, and the private portion is non-exportable by design.

- Compromised OS cannot leak signing keys
- No certificate authority can impersonate a node
- Trust is physical possession, not administrative access

## Services

### keymanager

Manages non-exportable TPM signing keys by reviewed role and persistent-handle
policy. Persists public-only metadata, verifies live TPM state before use,
supports initialization, rotation/recovery, and purpose-scoped certificate
issuance.

### libp2p-init

Initializes a lifetime-stable libp2p identity from a non-exportable TPM signing
key. Persists public identity metadata, sets the hostname to the canonical
IPNS/libp2p-key name, and serves a local gRPC identity API.

### trust

Runs the trust service, waits for readiness, and validates discovery
configuration. Requires keymanager, libp2p-init, and IPFS services.

### keyvalidation

gRPC key validation service with `ValidateKey` and `IssueJWT` RPC handling.

### discovery

Discovery broadcaster for a configured device identity. Validates a strict
discovery record, advertises over mDNS and BLE/BlueZ, and exposes local gRPC
methods for start, stop, and list.

### bootstrap

Orchestrates a fixed nine-step cluster bootstrap: CA signing, kubelet config,
Calico IPv6 ULA, Istio ingress, SPIRE TPM config, Kubernetes API server,
control-plane wait, cluster config apply, and final readiness.

### ipfs

Fail-closed service boundary around a maintained full Kubo node, TPM-backed
IPNS signing, public Trust publication snapshots, monotonic pre-signed IPNS
records, and durable publication state.

## Learn More

- [Build](docs/build.md)
- [Kubernetes](docs/kubernetes.md)
- [CI/CD](docs/cicd.md)
- [Release Task Workflows](docs/release-task-workflows.md)
- [Repository Structure](docs/structure.md)
