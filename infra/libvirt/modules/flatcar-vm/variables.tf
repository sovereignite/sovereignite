variable "name" {
  type = string
}

variable "role" {
  type = string
}

variable "pool" {
  type = string
}

variable "base_volume_path" {
  type = string
}

variable "ignition_content" {
  type = string
}

variable "vcpu" {
  type = number
}

variable "memory_mib" {
  type = number
}

variable "disk_bytes" {
  type = number
}

variable "mac" {
  type = string
}

variable "bridge" {
  type = string
}

variable "ovmf_code" {
  type = string
}

variable "ovmf_vars_template" {
  type = string
}

variable "nvram_path" {
  type = string
}

variable "tpm_state_path" {
  type = string
}

variable "tpm_model" {
  type = string
}

variable "tpm_version" {
  type = string
}
