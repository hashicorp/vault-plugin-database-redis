provider "docker" {}

resource "docker_image" "redis" {
  name         = "redis:7.2.3"
  keep_locally = true
}

resource "docker_container" "redis-nodes" {
  #attach = true
  count        = 6
  image        = docker_image.redis.image_id
  name         = "redis-node-${count.index}"
  hostname     = "redis-node-${count.index}"
  network_mode = "bridge"
  command      = ["/tmp/data/redis.sh"]
  #logs = true

  volumes {
    host_path      = "${path.cwd}/data"
    container_path = "/tmp/data"
  }
  networks_advanced {
    name    = docker_network.private_network.name
    aliases = ["redis-node-${count.index}"]
  }
}
resource "docker_container" "redis-cluster-creator" {
  #attach       = true
  image        = docker_image.redis.image_id
  name         = "redis-cluster-creator"
  network_mode = "bridge"
  command      = ["redis-cli", "--tls", "--cert", "/tmp/data/tls.crt", "--key",  "/tmp/data/tls.key", "--cacert", "/tmp/data/ca.crt", "-a", "default-pa55w0rd", "--cluster", "create", "redis-node-0:6379", "redis-node-1:6379", "redis-node-2:6379", "redis-node-3:6379", "redis-node-4:6379", "redis-node-5:6379", "--cluster-replicas", "1", "--cluster-yes"]
  logs         = true
  networks_advanced {
    name    = docker_network.private_network.name
    aliases = ["redis-cluster-creator"]
  }
  volumes {
    host_path      = "${path.cwd}/data"
    container_path = "/tmp/data"
  }
  depends_on = [
    docker_container.redis-nodes
  ]
}

resource "docker_network" "private_network" {
  name = "redis-cluster-network"
  ipam_driver  = "default"
  ipam_options = {}
  ipv6         = false
  options      = {}

  ipam_config {
    aux_address = {}
    subnet      = "192.168.200.0/28"
  }
}
