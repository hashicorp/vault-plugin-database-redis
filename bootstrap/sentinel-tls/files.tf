resource "local_file" "sentinel-sh" {
  content  = <<-EOT
MASTER_IP=$(getent hosts $1)
SENTINEL_PORT=$(expr $2)
MASTER_NAME=$3
#ANNOUNCE_IP=$(getent hosts $1)
#ANNOUNCE_PORT=$(expr $2)

CONF_FILE="/tmp/sentinel.conf"
ACL_FILE="/tmp/users.acl"

# generate sentinel.conf 7.x version
echo "port 0
tls-port $SENTINEL_PORT
tls-cert-file /tmp/data/tls.crt
tls-key-file /tmp/data/tls.key
tls-ca-cert-file /tmp/data/ca.crt
#tls-auth-clients no
tls-replication yes
sentinel monitor $MASTER_NAME $${MASTER_IP%% *} 6379 2
sentinel down-after-milliseconds $MASTER_NAME 50000
sentinel failover-timeout $MASTER_NAME 60000
sentinel parallel-syncs $MASTER_NAME 1
sentinel auth-pass $MASTER_NAME default-pa55w0rd
sentinel auth-user $MASTER_NAME default
sentinel sentinel-user default
sentinel sentinel-pass default-pa55w0rd
#requirepass default-pa55w0rd
#sentinel announce-ip $${ANNOUNCE_IP%% *}
#sentinel announce-port $ANNOUNCE_PORT
aclfile $ACL_FILE
" > $CONF_FILE

echo "user default on sanitize-payload #338b13e36315b0a2114e0ea1b2157327e8310edb5faacbb9120b1f643ba1130b ~* &*  +@all
user Administrator on sanitize-payload #5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 resetchannels -@all +@admin
" > $ACL_FILE

# start server
redis-server $CONF_FILE --sentinel
EOT
  filename = "${path.module}/data/sentinel.sh"
}

resource "local_file" "redis-sh" {
  content  = <<-EOT
#ANNOUNCE_IP=$1
#ANNOUNCE_PORT=$(expr $2)
#ANNOUNCE_BUS_PORT=$(expr $ANNOUNCE_PORT + 100)
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

