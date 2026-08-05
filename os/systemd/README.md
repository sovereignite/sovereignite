<!-- SPDX-License-Identifier: GPL-2.0-only -->

# Pre-Kubernetes readiness contracts

`sovereignite-pre-kubernetes.target` requires every planned pre-Kubernetes
service. The target has explicit ordering for each dependency and binds its
lifetime to every long-running daemon. The conditional TPM first-boot oneshot
is required and ordered but deliberately not bound: after its durable
`tpm-initialized` result exists, systemd skips that oneshot on later boots.

The kubelet drop-in in `base.bu` requires, waits for, and binds kubelet to the
target. A daemon that exits, fails its bounded readiness probe, or loses its
runtime directory therefore prevents or stops kubelet.

## Boot-scoped marker format

Except for Identity, each daemon atomically renames a mode `0600` regular file
owned by its service user to the path below only after its usable contract
holds:

```json
{"version":1,"service":"SERVICE","boot_id":"BOOT-ID","ready":true}
```

The content is exact. `BOOT-ID` is the current value of
`/proc/sys/kernel/random/boot_id`. Runtime directories are not preserved across
service stops. `/opt/sovereignite/bin/sovereignite-wait-ready` validates the
file and main-process liveness for a bounded interval; it never creates
readiness state.

| Service value | Path | Semantic point |
|---|---|---|
| `keymanager` | `/run/sovereignite/keymanager/ready.json` | TPM inventory/policy reconciled and localhost key API usable |
| `network` | `/run/sovereignite/network/ready.json` | one planned terminal network mode is usable |
| `ipfs` | `/run/sovereignite/ipfs/ready.json` | repository and local Kubo APIs are usable |
| `trust` | `/run/sovereignite/trust/ready.json` | local trust state and mTLS adoption endpoint are usable, and discovery config is published |
| `discovery` | `/run/sovereignite/discovery/ready.json` | Trust handler is bound and both mDNS and BLE registrations are active |
| `bootstrap-prepared` | `/run/sovereignite/bootstrap/prepared.json` | kubelet config and control-plane/API prerequisites are validated |

Bootstrap's later durable `complete.json` status is not the kubelet gate; using
completion there would deadlock the planned bootstrap sequence.

Identity already has a stronger implemented signal. After TPM identity
verification, hostname assignment, loopback bind, and stable-state checks, it
atomically publishes `/run/sovereignite/identity/endpoint.json`. The readiness
helper checks its owner/mode, current boot ID, main PID, service/network/address,
high port, and expected identity.

The currently absent or deliberately fail-closed service implementations do
not publish these markers, so this image correctly blocks kubelet rather than
claiming readiness.

## Network configuration and public identity

Every rendered profile installs root-owned mode `0600`
`/etc/sovereignite/network.env` with exactly these ordered, nonempty keys:

```text
SOVEREIGNITE_NETWORK_INTERFACE
SOVEREIGNITE_STATIC_IPV4_ADDRESS
SOVEREIGNITE_DHCP_POOL_START
SOVEREIGNITE_DHCP_POOL_END
SOVEREIGNITE_HOTSPOT_SSID
```

The Network service accepts no deployment defaults and no identity value from
that file. It reads the canonical public identity only from
`/var/lib/sovereignite/identity/identity.json`. Its private mount namespace
places a read-only temporary filesystem over the identity state directory and
bind-mounts only that exact regular file back read-only. Sibling identity state
is hidden and cannot be written. TPM devices, Key Manager state, Trust state,
public IPFS staging, and Kubernetes state remain inaccessible to Network.

The Network process must validate both files' owner, mode, type, bounded size,
stable inode, and exact schema before use. It decodes the identity's canonical
lowercase base36 CIDv1 `libp2p-key` name to binary multihash bytes for ULA
derivation. Once a planned terminal network mode is actually usable, it
atomically publishes the exact boot-scoped marker above; configuration parsing
alone is never readiness.

## Discovery configuration ownership

Trust is the sole producer and owns both
`/run/sovereignite/trust` and `/run/sovereignite/discovery`. Before publishing
Trust readiness, it atomically renames a root-owned mode `0600` regular file to
`/run/sovereignite/discovery/config.env`. The readiness helper requires exactly
these ordered, nonempty keys and no others:

```text
SOVEREIGNITE_DEVICE_ID
SOVEREIGNITE_TRUST_DOMAIN
SOVEREIGNITE_ADOPTION_STATE
SOVEREIGNITE_SERVICE_PORT
SOVEREIGNITE_BLE_SERVICE_UUID
SOVEREIGNITE_BLUEZ_ADAPTER
```

Discovery retains a non-optional `EnvironmentFile` and explicit flag mapping;
there are no defaults or persistent fallback values.
