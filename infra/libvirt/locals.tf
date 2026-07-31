locals {
  inventory_file = startswith(var.inventory_path, "/") ? var.inventory_path : abspath("${path.module}/${var.inventory_path}")
  inventory      = yamldecode(file(local.inventory_file))
  spec           = local.inventory.spec

  name     = local.inventory.metadata.name
  versions = local.spec.versions
  cluster  = local.spec.cluster
  libvirt  = local.spec.libvirt
  network  = local.libvirt.network
  firmware = local.libvirt.firmware
  tpm      = local.libvirt.tpm

  nodes_by_name       = { for node in local.spec.nodes : node.name => node }
  control_plane_nodes = [for node in local.spec.nodes : node if node.role == "control-plane"]
  worker_nodes        = [for node in local.spec.nodes : node if node.role == "worker"]

  flatcar_image_path = coalesce(
    var.flatcar_image_path,
    abspath("${path.module}/build/images/${local.libvirt.flatcarImage.decompressedName}")
  )
  flatcar_iso_path = coalesce(
    var.flatcar_iso_path,
    abspath("${path.module}/build/images/${local.libvirt.flatcarInstallerIso.name}")
  )
}
