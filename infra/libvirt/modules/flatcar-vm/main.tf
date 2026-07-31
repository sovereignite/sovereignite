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

  backing_store = {
    path = var.base_volume_path
    format = {
      type = "qcow2"
    }
  }
}

resource "libvirt_ignition" "this" {
  name    = "${var.name}.ign"
  content = var.ignition_content
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
    firmware        = "efi"
    type            = "hvm"
    type_arch       = "x86_64"
    type_machine    = "q35"
    loader          = var.ovmf_code
    loader_readonly = "yes"
    loader_secure   = "yes"
    loader_type     = "pflash"
    nv_ram = {
      nv_ram   = var.nvram_path
      template = var.ovmf_vars_template
    }
    boot_devices = [
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

  qemu_commandline = {
    args = [
      { value = "-fw_cfg" },
      { value = "name=opt/com.coreos/config,file=${libvirt_ignition.this.path}" }
    ]
  }
}
