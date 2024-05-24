provider "docker" {}

resource "docker_image" "redis" {
  name         = "redis:7.2.3"
  keep_locally = true
}

resource "docker_container" "redis-master" {
  image        = docker_image.redis.image_id
  name         = "redis-master"
  hostname     = "redis-master"
  network_mode = "bridge"
  command      = ["/tmp/data/redis.sh"]
  logs = true

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

resource "docker_network" "private_network" {
  name = "prim-sec-network"
}

