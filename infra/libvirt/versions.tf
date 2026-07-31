terraform {
  required_version = ">= 1.8.0"

  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.8"
    }

    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}
