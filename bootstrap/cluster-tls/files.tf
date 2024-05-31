
resource "local_file" "redis-sh"{
  content = <<-EOT
ANNOUNCE_IP=$1
ANNOUNCE_PORT=$(expr $2)
ANNOUNCE_BUS_PORT=$(expr $ANNOUNCE_PORT + 100)

CONF_FILE="/tmp/redis.conf"
ACL_FILE="/tmp/users.acl"

# generate redis.conf file
echo "port 0
tls-port 6379
#tls-auth-clients no
tls-cluster yes
tls-cert-file /tmp/data/tls.crt
tls-key-file /tmp/data/tls.key
tls-ca-cert-file /tmp/data/ca.crt
cluster-enabled yes
cluster-config-file nodes.conf
cluster-node-timeout 5000
appendonly yes
loglevel debug
requirepass default-pa55w0rd 
masterauth  default-pa55w0rd
protected-mode no
#cluster-announce-ip $ANNOUNCE_IP
#cluster-announce-port $ANNOUNCE_PORT
#cluster-announce-bus-port $ANNOUNCE_BUS_PORT
aclfile $ACL_FILE
" >> $CONF_FILE

echo "user default on sanitize-payload #338b13e36315b0a2114e0ea1b2157327e8310edb5faacbb9120b1f643ba1130b ~* &* +@all" > $ACL_FILE

# start server
redis-server $CONF_FILE
EOT
  filename = "${path.module}/data/redis.sh"
}

