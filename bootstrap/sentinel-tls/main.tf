provider "docker" {}
provider "random" {}

resource "docker_image" "redis" {
  name         = "redis:7.2.3"
  keep_locally = true
}

resource "random_pet" "master-name" {
  separator = "_"
}

locals {
  my-master-name = random_pet.master-name.id
}

resource "docker_image" "haproxy" {
  name         = "haproxytech/haproxy-alpine:2.4"
  keep_locally = true
}

resource "docker_container" "redis-master" {
  image        = docker_image.redis.image_id
  name         = "redis-master"
  hostname     = "redis-master"
  network_mode = "bridge"
  command      = ["/tmp/data/redis.sh"]
  logs         = true

  volumes {
    host_path      = "${path.cwd}/data"
    container_path = "/tmp/data"
  }
  networks_advanced {
    name    = docker_network.private_network.name
    aliases = ["redis-master"]
  }
}

resource "docker_container" "redis-replica" {
  #attach = true
  count        = 2
  image        = docker_image.redis.image_id
  name         = "redis-replica-${count.index}"
  hostname     = "redis-replica-${count.index}"
  network_mode = "bridge"
  command      = ["/tmp/data/redis.sh", "--replicaof", "redis-master", "6379"]
  #logs = true

  volumes {
    host_path      = "${path.cwd}/data"
    container_path = "/tmp/data"
  }
  networks_advanced {
    name    = docker_network.private_network.name
    aliases = ["redis-replica-${count.index}"]
  }
}

resource "docker_container" "redis-sentinels" {
  #attach = true
  count        = 3
  image        = docker_image.redis.image_id
  name         = "redis-sentinel-${count.index}"
  hostname     = "redis-sentinel-${count.index}"
  network_mode = "bridge"
  command      = ["/tmp/data/sentinel.sh", "redis-master", "26379", "${local.my-master-name}"]
  #logs = true

  volumes {
    host_path      = "${path.cwd}/data"
    container_path = "/tmp/data"
  }
  networks_advanced {
    name    = docker_network.private_network.name
    aliases = ["redis-sentinel-${count.index}"]
  }
  depends_on = [
    docker_container.redis-master
  ]
}

resource "docker_network" "private_network" {
  name = "sentinel_network"

  ipam_driver  = "default"
  ipam_options = {}
  ipv6         = false
  options      = {}

  ipam_config {
    aux_address = {}
    subnet      = "192.168.200.0/28"
  }
}


