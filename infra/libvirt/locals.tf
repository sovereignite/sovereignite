locals {
  inventory_file = startswith(var.inventory_path, "/") ? var.inventory_path : abspath("${path.module}/${var.inventory_path}")
  inventory      = yamldecode(file(local.inventory_file))
  spec           = local.inventory.spec

  name     = local.inventory.metadata.name
  versions = local.spec.versions
  cluster  = local.spec.cluster
  node_os  = try(local.spec.nodeOs, null)
  libvirt  = local.spec.libvirt
  network  = local.libvirt.network
  firmware = local.libvirt.firmware
  tpm      = local.libvirt.tpm

  nodes_by_name       = { for node in local.spec.nodes : node.name => node }
  control_plane_nodes = [for node in local.spec.nodes : node if node.role == "control-plane"]
  worker_nodes        = [for node in local.spec.nodes : node if node.role == "worker"]

  node_os_id = coalesce(
    try(local.node_os.id, null),
    "flatcar"
  )

  installer_iso_name = coalesce(
    try(local.node_os.artifacts.installerIso.name, null),
    local.libvirt.flatcarInstallerIso.name
  )
  ignition_fw_cfg_name = coalesce(
    try(local.node_os.ignition.fwCfgName, null),
    "opt/org.flatcar-linux/config"
  )
  installer_iso_dir = abspath("${path.module}/build/images/${local.node_os_id}")
  installer_iso_path = coalesce(
    var.installer_iso_path,
    "${local.installer_iso_dir}/${local.installer_iso_name}"
  )
  customize_installer_iso = coalesce(
    try(local.node_os.installer.customize, null),
    false
  )
  node_installer_iso_paths = {
    for name, node in local.nodes_by_name : name => (
      local.customize_installer_iso
      ? "${local.installer_iso_dir}/${node.name}-${local.installer_iso_name}"
      : local.installer_iso_path
    )
  }
}
