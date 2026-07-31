output "cluster_name" {
  value = local.name
}

output "api_endpoint" {
  value = "https://${local.cluster.apiEndpoint}:${local.cluster.apiServerPort}"
}

output "api_vip" {
  value = local.cluster.apiVip
}

output "control_plane_nodes" {
  value = {
    for node in local.control_plane_nodes : node.name => {
      ip  = node.ip
      mac = node.mac
    }
  }
}

output "worker_nodes" {
  value = {
    for node in local.worker_nodes : node.name => {
      ip  = node.ip
      mac = node.mac
    }
  }
}

output "ssh_config" {
  value = join("\n", [
    for node in local.spec.nodes : format(
      "Host %s\n  HostName %s\n  User core\n  StrictHostKeyChecking accept-new\n",
      node.name,
      node.ip
    )
  ])
}
