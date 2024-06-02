
variable "use-tls" {
  description = "Do you want TLS or not, true or false?"
  type        = bool
}

variable "redis-tls-cluster-command" {
  type    = list(string)
  default = ["redis-cli", "--tls", "--cert", "/tmp/data/tls.crt", "--key", "/tmp/data/tls.key", "--cacert", "/tmp/data/ca.crt", "-a", "default-pa55w0rd", "--cluster", "create", "redis-node-0:6379", "redis-node-1:6379", "redis-node-2:6379", "redis-node-3:6379", "redis-node-4:6379", "redis-node-5:6379", "--cluster-replicas", "1", "--cluster-yes"]
}

variable "redis-cluster-command" {
  type    = list(string)
  default = ["redis-cli", "-a", "default-pa55w0rd", "--cluster", "create", "redis-node-0:6379", "redis-node-1:6379", "redis-node-2:6379", "redis-node-3:6379", "redis-node-4:6379", "redis-node-5:6379", "--cluster-replicas", "1", "--cluster-yes"]
}
