output "primary_host" {
   value = docker_container.redis-master.network_data[0].ip_address
}
output "secondaries" {
   value = flatten([for o in docker_container.redis-replica : o.network_data[0].ip_address])
}
