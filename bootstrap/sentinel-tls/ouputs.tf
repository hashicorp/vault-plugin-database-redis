output "s2" {
  value = { for o in docker_container.redis-sentinels : o.hostname => o.network_data[0].ip_address }
}
output "env_var" {
  value = flatten([for o in docker_container.redis-sentinels : o.network_data[0].ip_address])
}
output "env_master" {
  value = local.my-master-name
}
