# Libvirt Deployment Notes

## Confirmed State

- OpenTofu owns the disposable libvirt resources. `tofu destroy -var=create_managed_network=true` destroyed 19 resources, including all eight VM domains, all eight root volumes, the managed network, the imported Flatcar base image volume, and the installer ISO volume.
- The host Secure Boot state is irrelevant to guest Secure Boot. The relevant state is each VM's OVMF NVRAM file, created from the configured vars template.
- Do not use the inventory's custom `/nix/store/.../OVMF_*` files for this deployment. Those files were compiled for a different purpose.
- The active VM boot model is intended to be: empty root disk plus Flatcar installer ISO plus per-node shared config directory.
- Flatcar Ignition must be exposed through QEMU fw_cfg as `opt/org.flatcar-linux/config`. With the current `dmacvicar/libvirt` provider this is configured through `sys_info.fw_cfg.entry`, using the per-node `libvirt_ignition` file path.
- The Terraform Registry docs for newer/forked libvirt providers expose this as `fw_cfg_name`; with this repo's provider schema the equivalent is `sys_info.fw_cfg.entry.name = "opt/org.flatcar-linux/config"`.
- The installer ISO disk must be attached read-only and shareable so all VM domains can use the same provider-managed ISO volume.
- The per-node config share target is `sovereignite`, backed by `infra/libvirt/build/shares/<node>`.
- SPICE graphics, serial console, TPM2 emulator, and the per-node config share are present in the VM XML.

## Attempts

### UEFI Secure Boot Autoselection

- Config: libvirt `firmware = "efi"` with firmware features `secure-boot=yes` and `enrolled-keys=no`.
- Result: OpenTofu apply succeeded and cp-1 XML showed the empty root disk, shareable ISO, TPM, SPICE, and config share.
- Failure: cp-1 booted to OVMF UiApp instead of the Flatcar installer.

### Per-Disk Boot Order

- Config: keep EFI and move boot priority from OS-level `boot_devices` to per-disk boot order, with CD-ROM order `1` and root disk order `2`.
- Result: cp-1 XML showed `<boot order='1'/>` on the ISO CD-ROM and `<boot order='2'/>` on the root disk.
- Failure: cp-1 still reached OVMF and reported `failed to load Boot0001 "UEFI QEMU DVD-ROM QM00001": Not Found`.
- Rejected field: adding `target.tray = "closed"` made the provider return an inconsistent result because libvirt normalized the value to null. Do not use that field with this provider.

### EFI Without Firmware Feature Flags

- Config: keep `firmware = "efi"` but remove `firmware_info` feature requests so libvirt uses its normal EFI firmware selection instead of forcing the secure OVMF code path with the host's available vars template.
- Result: replacing only the cp-1 domain still produced the same secure OVMF loader and NVRAM path. Removing the feature flags is not enough to change firmware selection on this host/provider combination.

### EFI With Secure Boot Disabled

- Config: keep `firmware = "efi"` but explicitly set `secure-boot=no` and `enrolled-keys=no`.
- Purpose: determine whether the Flatcar ISO boot failure is tied to the selected secure OVMF firmware or to the ISO/CD-ROM attachment itself.
- Status: testing.

### Enrolled Keys Firmware Request

- Config: libvirt `firmware = "efi"` with firmware features `secure-boot=yes` and `enrolled-keys=yes`.
- Result: the eight `libvirt_ignition` resources were created, but every VM domain definition failed.
- Failure: libvirt reported `Unable to find 'efi' firmware that is compatible with the current configuration`.
- Host capability check: `virsh domcapabilities --virttype kvm --arch x86_64 --machine q35` advertises `secureBoot` values `yes` and `no`, but `enrolledKeys` only advertises `no`. Auto-selection cannot define an `enrolled-keys=yes` domain on this host.

### Explicit OVMF Secure Loader And MS Vars

- Config: explicit loader `/nix/store/8q4hiprv3kkvhqwji33z4k59hkbk1y4c-OVMF-202411-fd/FV/OVMF_CODE.fd`, `loader_secure = "yes"`, and NVRAM template `/nix/store/8q4hiprv3kkvhqwji33z4k59hkbk1y4c-OVMF-202411-fd/FV/OVMF_VARS.ms.fd`.
- Result: OpenTofu validate passed. OpenTofu destroy/apply rebuilt 19 resources. cp-1 XML showed the explicit secure loader, MS vars template, empty root disk, shareable ISO, TPM, SPICE, and config share.
- Failure: cp-1 still booted to OVMF UiApp instead of the Flatcar installer.
- Rejected: the OVMF files in the inventory are custom host files built for a different purpose and should not be used for this deployment.

## Next Checks

- Current selected OS path is Fedora CoreOS. See `infra/libvirt/os-tests/README.md`
  and `infra/libvirt/os-tests/fedora-coreos.md` for the active test record.
- Fedora CoreOS boots and provisions on all eight VMs from per-node customized
  installer ISOs.
- Secure Boot is enabled after switching to explicit packaged OVMF code plus the
  packaged Microsoft-enrolled vars template and starting existing domains with
  `virsh --connect qemu:///system start <node> --reset-nvram`.
