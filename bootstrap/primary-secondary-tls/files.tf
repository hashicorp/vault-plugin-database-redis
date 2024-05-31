
resource "local_file" "redis-sh" {
  content = <<-EOT
FLAG=$1
MASTER=$2
MASTER_PORT=$3

CONF_FILE="/tmp/redis.conf"
ACL_FILE="/tmp/users.acl"

# generate redis.conf file
echo "port 0
tls-port 6379
tls-cert-file /tmp/data/tls.crt
tls-key-file /tmp/data/tls.key
tls-ca-cert-file /tmp/data/ca.crt
#tls-auth-clients no
tls-replication yes
appendonly yes
loglevel debug
requirepass default-pa55w0rd 
masterauth  default-pa55w0rd
protected-mode no
aclfile $ACL_FILE
" > $CONF_FILE

echo "user default on sanitize-payload #338b13e36315b0a2114e0ea1b2157327e8310edb5faacbb9120b1f643ba1130b ~* &* +@all" > $ACL_FILE

# start server
redis-server $CONF_FILE $FLAG $MASTER $MASTER_PORT
EOT
  filename = "${path.module}/data/redis.sh"
}

