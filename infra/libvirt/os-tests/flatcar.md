# Flatcar Stable Installer Test

## Status

Tested, not selected for the current path. The libvirt/OpenTofu resource model
worked, but the VM did not boot the Flatcar installer ISO successfully on this
host/provider/firmware combination during the recorded attempts.

## Official References

- Flatcar libvirt provisioning documentation: https://www.flatcar.org/docs/latest/installing/cloud/libvirt/
- Flatcar Ignition documentation: https://www.flatcar.org/docs/latest/provisioning/ignition/
- libvirt Secure Boot: https://libvirt.org/kbase/secureboot.html
- libvirt domain XML: https://libvirt.org/formatdomain.html

## Artifacts

- Release: `4593.2.4`
- Installer ISO URL: `https://stable.release.flatcar-linux.net/amd64-usr/4593.2.4/flatcar_production_iso_image.iso`
- QEMU UEFI secure image URL: `https://stable.release.flatcar-linux.net/amd64-usr/4593.2.4/flatcar_production_qemu_uefi_secure_image.img.bz2`
- Ignition fw_cfg entry: `opt/org.flatcar-linux/config`

## Test Log

- 2026-07-31: OpenTofu created empty root volumes, read-only/shareable installer
  ISO attachment, SPICE graphics, serial console, TPM2 emulator, and per-node
  config shares.
- 2026-07-31: libvirt `sys_info.fw_cfg.entry` successfully exposed per-node
  Ignition paths with the Flatcar-specific name `opt/org.flatcar-linux/config`.
- 2026-07-31: With CD-ROM boot order before root disk, cp-1 reached OVMF UiApp
  and reported it could not load the UEFI QEMU DVD-ROM boot option.
- 2026-07-31: Requesting `enrolled-keys=yes` through libvirt firmware
  autoselection failed because this host's `domcapabilities` advertised
  `secureBoot` `yes/no` but only `enrolledKeys=no`.
- 2026-07-31: The stack was destroyed through OpenTofu. No project-managed
  libvirt domains or volumes remain active from this test.

