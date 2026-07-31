# openSUSE MicroOS Installer Test

## Status

Queued as the first fallback if Fedora CoreOS cannot satisfy the libvirt
Secure Boot plus kubeadm host requirements.

## Official References

- MicroOS Ignition documentation: https://en.opensuse.org/Portal:MicroOS/Ignition
- Ignition getting started: https://coreos.github.io/ignition/getting-started/
- libvirt Secure Boot: https://libvirt.org/kbase/secureboot.html

## Notes

The MicroOS Ignition documentation supports multiple config handoff paths:

- A disk labeled `ignition` containing `ignition/config.ign`.
- An ISO labeled `ignition` containing `ignition/config.ign`.
- libvirt/QEMU `fw_cfg` with entry name `opt/com.coreos/config`.

This remains a viable fallback because it keeps provisioning standard and avoids
Kubernetes-appliance distributions. It has not been boot-tested in this repo yet.

## Test Log

- 2026-07-31: Candidate queued from official MicroOS Ignition docs.

