# Fedora CoreOS Installer Test

## Status

Selected for the current libvirt VM layer. The Fedora CoreOS installer path has
been tested on all eight nodes with empty provider-owned root disks, per-node
customized live ISOs, OVMF Secure Boot, TPM2/vTPM, SPICE graphics, and the
project-managed libvirt NAT network.

## Official References

- Fedora CoreOS download page: https://fedoraproject.org/coreos/download/?arch=x86_64&stream=stable
- Fedora CoreOS stable stream metadata: https://builds.coreos.fedoraproject.org/streams/stable.json
- CoreOS installer overview: https://coreos.github.io/coreos-installer/
- CoreOS installer getting started: https://coreos.github.io/coreos-installer/getting-started/
- CoreOS installer ISO customization: https://coreos.github.io/coreos-installer/customizing-install/
- CoreOS installer ISO command reference: https://coreos.github.io/coreos-installer/cmd/iso/
- Butane supported specs: https://coreos.github.io/butane/specs/
- Ignition getting started: https://coreos.github.io/ignition/getting-started/
- libvirt Secure Boot: https://libvirt.org/kbase/secureboot.html

## Artifacts

The stable stream metadata was checked on 2026-07-31.

- Stream: `stable`
- Release: `44.20260707.3.1`
- Architecture: `x86_64`
- Live ISO URL: `https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/44.20260707.3.1/x86_64/fedora-coreos-44.20260707.3.1-live-iso.x86_64.iso`
- Live ISO SHA-256: `8ffd0d0fc218eae95c578ec12839fe598d60f96de85fab63d424ad021ed1a62f`
- QEMU image URL, retained for fallback tests: `https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/44.20260707.3.1/x86_64/fedora-coreos-44.20260707.3.1-qemu.x86_64.qcow2.xz`
- QEMU image SHA-256: `35eb8e1f601b2b65545402df54b2dbb2a48e75f1d4483de5dc575d020ddefa1e`

Next stream is retained as a later swap candidate if a newer kernel is needed:

- Stream: `next`
- Release: `44.20260720.1.1`
- Live ISO URL: `https://builds.coreos.fedoraproject.org/prod/streams/next/builds/44.20260720.1.1/x86_64/fedora-coreos-44.20260720.1.1-live-iso.x86_64.iso`
- Live ISO SHA-256: `83a4b249f5e7c06305bf20514ade133f556b2e3df456a6e666889045c78afe38`

## Planned Boot Path

- Keep the libvirt root volume empty and provider-owned.
- Keep the installer ISO as a read-only, shareable disk.
- Generate per-node Ignition configs from the existing Butane template.
- Use `variant: fcos` with the latest stable FCOS Butane spec supported by the
  installed `butane` binary.
- Customize a pristine FCOS live ISO per node with `coreos-installer iso
  customize --dest-device /dev/vda --dest-ignition <node>.ign`.
- Attach the per-node customized ISO to the VM and boot it.
- The live ISO installer installs FCOS onto `/dev/vda`, applies the destination
  Ignition config to the installed system, and reboots into the installed OS.
- Keep the root disk at boot order `1` and the installer ISO at boot order `2`.
  On an empty disk, firmware falls through to the ISO; after installation, the
  root disk boots first and avoids reinstall loops.
- Use explicit packaged OVMF code and the packaged `OVMF_VARS.ms.fd` template on
  this host. Libvirt's active auto-selection metadata points the secure x86_64
  firmware at a no-key vars file, which leaves guests in Setup Mode.
- When changing the OVMF vars template on existing domains, start once with
  `virsh --connect qemu:///system start <node> --reset-nvram` so libvirt copies
  the configured vars template into the VM NVRAM file.

## Test Log

- 2026-07-31: Candidate selected from official FCOS/CoreOS installer docs.
- 2026-07-31: Stable and next stream artifact URLs and checksums recorded.
- 2026-07-31: Pristine stable live ISO downloaded under
  `infra/libvirt/build/images/fedora-coreos/` and verified against SHA-256
  `8ffd0d0fc218eae95c578ec12839fe598d60f96de85fab63d424ad021ed1a62f`.
- 2026-07-31: Eight per-node FCOS live installer ISOs generated with the
  official `quay.io/coreos/coreos-installer:release` container.
- 2026-07-31: OpenTofu created 33 libvirt resources: managed network, eight
  root volumes, eight per-node installer ISO volumes, eight Ignition resources,
  and eight VM domains.
- 2026-07-31: Initial ISO-first boot installed FCOS but risked an install loop.
  The module was corrected to root-first, ISO-second boot order.
- 2026-07-31: cp-1 screenshot confirmed installed Fedora CoreOS
  `44.20260707.3.1` with kernel `7.1.3-200.fc44.x86_64` and applied Ignition.
- 2026-07-31: The first Secure Boot-capable/empty-vars firmware path booted but
  left guests with `SecureBoot=0` and Setup Mode.
- 2026-07-31: Switched to explicit packaged OVMF code plus
  `OVMF_VARS.ms.fd`, reset VM NVRAM through libvirt, and verified all eight
  nodes report Secure Boot enabled, TPM present, kubeadm `v1.36.3`, and active
  containerd.
