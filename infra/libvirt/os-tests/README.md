# OS Installer Test Index

This directory tracks each base OS installer/image path tested for the libvirt
Kubernetes nodes. Each candidate has its own document so the result, artifacts,
and references stay reviewable.

## Selection Criteria

- Official or manufacturer-provided ISO/image artifacts.
- Libvirt/KVM on x86_64 with OVMF EFI, TPM2/vTPM, SPICE graphics, serial console,
  and an empty provider-owned root volume.
- Secure Boot-compatible boot path. Guest Secure Boot state is VM firmware/NVRAM
  state, not host Secure Boot state.
- Idempotent first-boot provisioning through the OS-supported mechanism.
- Minimal immutable or image-based OS, not a Kubernetes appliance distribution.
- Newer kernel preferred.
- Existing kubeadm/libvirt automation is preserved; OS artifacts and Ignition
  handoff are the swappable parts.

## Candidates

| Candidate | Status | Primary artifact | Notes |
| --- | --- | --- | --- |
| Fedora CoreOS | Selected for VM layer | Stable 44.20260707.3.1 live ISO | [fedora-coreos.md](fedora-coreos.md) |
| openSUSE MicroOS | Queued | Installer/Image selection pending | [opensuse-microos.md](opensuse-microos.md) |
| Flatcar Stable | Tested, not selected on this host path | Stable 4593.2.4 installer ISO | [flatcar.md](flatcar.md) |

## Artifact Storage

Downloaded pristine ISOs/images and generated per-node installer ISOs are kept
under `infra/libvirt/build/images/`. That directory is intentionally ignored by
Git, so artifacts can be preserved locally without bloating commits.
