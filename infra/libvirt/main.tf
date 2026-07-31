resource "libvirt_pool" "cluster" {
  name = local.libvirt.pool
  type = "dir"

  target = {
    path = local.libvirt.poolPath
  }
}

resource "libvirt_volume" "flatcar_base" {
  name = local.libvirt.flatcarImage.decompressedName
  pool = libvirt_pool.cluster.name
  type = "file"

  target = {
    format = {
      type = "qcow2"
    }
  }

  create = {
    content = {
      url = "file://${local.flatcar_image_path}"
    }
  }
}

resource "libvirt_network" "managed" {
  count = var.create_managed_network ? 1 : 0

  name      = "${local.name}-net"
  autostart = true

  bridge = {
    name  = "${local.name}0"
    stp   = "on"
    delay = "0"
  }

  forward = {
    mode = "nat"
  }

  domain = {
    name       = local.cluster.privateDnsSuffix
    local_only = "yes"
  }

  ips = [
    {
      family  = "ipv4"
      address = local.network.gateway
      prefix  = tonumber(split("/", local.network.cidr)[1])
      dhcp = {
        hosts = [
          for node in local.spec.nodes : {
            name = node.name
            mac  = node.mac
            ip   = node.ip
          }
        ]
      }
    }
  ]

  dns = {
    enable = "yes"
    host = concat(
      [
        for node in local.spec.nodes : {
          ip = node.ip
          hostnames = [
            { hostname = node.name },
            { hostname = "${node.name}.${local.cluster.privateDnsSuffix}" }
          ]
        }
      ],
      [
        {
          ip = local.cluster.apiVip
          hostnames = [
            { hostname = local.cluster.apiEndpoint }
          ]
        }
      ]
    )
  }
}

module "flatcar_vm" {
  source = "./modules/flatcar-vm"

  for_each = local.nodes_by_name

  name             = each.value.name
  role             = each.value.role
  pool             = libvirt_pool.cluster.name
  base_volume_path = libvirt_volume.flatcar_base.path
  ignition_content = file(abspath("${path.module}/build/ignition/${each.value.name}.ign"))

  vcpu       = each.value.vcpu
  memory_mib = each.value.memoryMiB
  disk_bytes = each.value.diskGiB * 1024 * 1024 * 1024
  mac        = each.value.mac

  bridge = var.create_managed_network ? "${local.name}0" : local.network.bridge

  ovmf_code          = local.firmware.ovmfCode
  ovmf_vars_template = local.firmware.ovmfVarsTemplate
  nvram_path         = "${local.firmware.nvramDir}/${each.value.name}_VARS.fd"
  tpm_state_path     = "${local.tpm.stateDir}/${each.value.name}"
  tpm_model          = local.tpm.model
  tpm_version        = local.tpm.version
}
