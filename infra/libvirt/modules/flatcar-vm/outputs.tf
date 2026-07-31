output "name" {
  value = libvirt_domain.this.name
}

output "domain_id" {
  value = libvirt_domain.this.id
}

output "root_volume_id" {
  value = libvirt_volume.root.id
}
