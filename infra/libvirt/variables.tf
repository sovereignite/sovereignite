variable "inventory_path" {
  description = "Path to the cluster inventory YAML, relative to infra/libvirt unless absolute."
  type        = string
  default     = "cluster.inventory.yaml"
}

variable "installer_iso_path" {
  description = "Path to a single OS installer ISO. Defaults to build/images/<nodeOs.id>/<inventory installer ISO name>."
  type        = string
  default     = null
  nullable    = true
}

variable "create_managed_network" {
  description = "Create a libvirt NAT network instead of attaching VMs to the inventory bridge."
  type        = bool
  default     = false
}
