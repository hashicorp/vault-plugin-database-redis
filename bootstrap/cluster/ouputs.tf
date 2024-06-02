output "cluster-nodes" {
  value = flatten([for o in docker_container.redis-nodes : o.network_data[0].ip_address])
}
output "use-tls" {
  value = var.use-tls
}
