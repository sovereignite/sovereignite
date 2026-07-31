variable "inventory_path" {
  description = "Path to the cluster inventory YAML, relative to infra/libvirt unless absolute."
  type        = string
  default     = "cluster.inventory.yaml"
}

variable "flatcar_image_path" {
  description = "Path to a decompressed Flatcar qcow2 image. Defaults to build/images/<inventory decompressedName>."
  type        = string
  default     = null
  nullable    = true
}

variable "create_managed_network" {
  description = "Create a libvirt NAT network instead of attaching VMs to the inventory bridge."
  type        = bool
  default     = false
}
