resource "libvirt_volume" "installer_iso" {
  for_each = local.nodes_by_name

  name = "${each.value.name}-${local.installer_iso_name}"
  pool = local.libvirt.pool
  type = "file"

  target = {
    format = {
      type = "iso"
    }
  }

  create = {
    content = {
      url = "file://${local.node_installer_iso_paths[each.key]}"
    }
  }
}

resource "libvirt_ignition" "node" {
  for_each = local.nodes_by_name

  name    = "${each.value.name}.ign"
  content = file("${path.module}/build/ignition/${each.value.name}.ign")
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

  name                 = each.value.name
  role                 = each.value.role
  pool                 = local.libvirt.pool
  installer_iso        = libvirt_volume.installer_iso[each.key].path
  ignition_path        = libvirt_ignition.node[each.key].path
  ignition_fw_cfg_name = local.ignition_fw_cfg_name
  share_path           = abspath("${path.module}/build/shares/${each.value.name}")

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
