provider "docker" {}

resource "docker_image" "redis" {
  name         = "redis:7.2.3"
  keep_locally = true
}

resource "docker_image" "haproxy" {
  name         = "haproxytech/haproxy-alpine:2.4"
  keep_locally = true
}

resource "docker_container" "redis-node" {
  #attach = true
  count        = 6
  image        = docker_image.redis.image_id
  name         = format("redis-node-%d", count.index + 1)
  hostname     = format("redis-node-%d", count.index + 1)
  network_mode = "bridge"
  command      = ["/tmp/data/redis.sh", "${var.proxy_hostname}", format("%d", 7001 + count.index)]
  #logs = true

  volumes {
    host_path      = "${path.cwd}/data"
    container_path = "/tmp/data"
  }
  networks_advanced {
    name    = docker_network.private_network.name
    aliases = [format("redis-node-%d", count.index + 1)]
  }
}
resource "docker_container" "redis-cluster-creator" {
  #attach       = true
  image        = docker_image.redis.image_id
  name         = "redis-cluster-creator"
  network_mode = "bridge"
  command      = ["redis-cli", "-a", "default-pa55w0rd", "--cluster", "create", "${var.proxy_hostname}:7001", "${var.proxy_hostname}:7002", "${var.proxy_hostname}:7003", "${var.proxy_hostname}:7004", "${var.proxy_hostname}:7005", "${var.proxy_hostname}:7006", "--cluster-replicas", "1", "--cluster-yes"]
  logs         = true
  networks_advanced {
    name    = docker_network.private_network.name
    aliases = ["redis-cluster-creator"]
  }
  depends_on = [
    docker_container.haproxy,
  ]
}

locals {
  fe_ports = {
    for i in range(7001, 7007) : i => i + 2000
  }
  be_ports = {
    for i in range(7101, 7107) : i => i + 2000
  }
}

resource "docker_container" "haproxy" {
  #attach = true
  image        = docker_image.haproxy.image_id
  name         = "haproxy"
  network_mode = "bridge"
  logs = true     

  ports {
    internal = 8404
    external = 8404
  }

  dynamic "ports" {
    for_each = local.fe_ports
    content {
      internal = ports.value
      external = ports.key
    }
  }


  dynamic "ports" {
    for_each = local.be_ports
    content {
      internal = ports.value
      external = ports.key
    }
  }
  volumes {
    host_path      = "${path.cwd}/haproxy"
    container_path = "/usr/local/etc/haproxy"
  }
  depends_on = [
    docker_container.redis-node
  ]
  networks_advanced {
    name    = docker_network.private_network.name
    #aliases = ["haproxy"]
  }
}

resource "docker_network" "private_network" {
  name = "my_network"
}
