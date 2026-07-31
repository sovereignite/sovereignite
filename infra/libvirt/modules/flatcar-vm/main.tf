resource "libvirt_volume" "root" {
  name     = "${var.name}.qcow2"
  pool     = var.pool
  capacity = var.disk_bytes
  type     = "file"

  target = {
    format = {
      type = "qcow2"
    }
  }
}

resource "libvirt_domain" "this" {
  name        = var.name
  type        = "kvm"
  memory      = var.memory_mib
  memory_unit = "MiB"
  vcpu        = var.vcpu
  autostart   = true

  cpu = {
    mode = "host-passthrough"
  }

  os = {
    firmware     = "efi"
    type         = "hvm"
    type_arch    = "x86_64"
    type_machine = "q35"
    firmware_info = {
      features = [
        {
          enabled = "yes"
          name    = "enrolled-keys"
        },
        {
          enabled = "yes"
          name    = "secure-boot"
        }
      ]
    }
    boot_devices = [
      { dev = "cdrom" },
      { dev = "hd" }
    ]
  }

  features = {
    acpi = true
    apic = {}
    smm = {
      state = "on"
    }
  }

  devices = {
    disks = [
      {
        type   = "file"
        device = "disk"
        driver = {
          name = "qemu"
          type = "qcow2"
        }
        source = {
          file = {
            file = libvirt_volume.root.path
          }
        }
        target = {
          dev = "vda"
          bus = "virtio"
        }
      },
      {
        type   = "file"
        device = "cdrom"
        driver = {
          name = "qemu"
          type = "raw"
        }
        source = {
          file = {
            file = var.installer_iso
          }
        }
        target = {
          dev = "sda"
          bus = "sata"
        }
        read_only = true
      }
    ]

    interfaces = [
      {
        type = "bridge"
        mac = {
          address = var.mac
        }
        model = {
          type = "virtio"
        }
        source = {
          bridge = {
            bridge = var.bridge
          }
        }
        wait_for_ip = {
          source  = "none"
          timeout = 1
        }
      }
    ]

    filesystems = [
      {
        access_mode = "passthrough"
        driver = {
          type = "path"
        }
        source = {
          mount = {
            dir = var.share_path
          }
        }
        target = {
          dir = "sovereignite"
        }
        model     = "virtio"
        read_only = true
      }
    ]

    graphics = [
      {
        spice = {
          auto_port = true
          listen    = "127.0.0.1"
          listeners = [
            {
              address = {
                address = "127.0.0.1"
              }
            }
          ]
        }
      }
    ]

    videos = [
      {
        model = {
          type    = "virtio"
          heads   = 1
          primary = "yes"
        }
      }
    ]

    serials = [
      {
        target = {
          type = "isa-serial"
          port = 0
          model = {
            name = "isa-serial"
          }
        }
      }
    ]

    consoles = [
      {
        target = {
          type = "serial"
          port = 0
        }
      }
    ]

    tpms = [
      {
        model = var.tpm_model
        backend = {
          emulator = {
            version          = var.tpm_version
            persistent_state = "yes"
            source = {
              dir = {
                path = var.tpm_state_path
              }
            }
            active_pcr_banks = {
              sha256 = true
            }
          }
        }
      }
    ]
  }

}
