resource "local_file" "sentinel-sh" {
  content = <<-EOT
MASTER_IP=$(getent hosts $1)
SENTINEL_PORT=$(expr $2)
MASTER_NAME=$3
#ANNOUNCE_IP=$(getent hosts $1)
#ANNOUNCE_PORT=$(expr $2)

CONF_FILE="/tmp/sentinel.conf"
ACL_FILE="/tmp/users.acl"

# generate sentinel.conf 7.x version
echo "port $SENTINEL_PORT
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
#aclfile $ACL_FILE
" > $CONF_FILE

echo "user default on sanitize-payload #338b13e36315b0a2114e0ea1b2157327e8310edb5faacbb9120b1f643ba1130b ~* &*  +client +subscribe +publish +ping +info +multi +slaveof +config +client +exec
user Administrator on sanitize-payload #5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 resetchannels +client +subscribe +publish +ping +info +multi +slaveof +config +client +exec" > $ACL_FILE

# start server
redis-server $CONF_FILE --sentinel
EOT
  filename = "${path.module}/data/sentinel.sh"
}

resource "local_file" "redis-sh" {
  content = <<-EOT
#ANNOUNCE_IP=$1
#ANNOUNCE_PORT=$(expr $2)
#ANNOUNCE_BUS_PORT=$(expr $ANNOUNCE_PORT + 100)
FLAG=$1
MASTER=$2
MASTER_PORT=$3

CONF_FILE="/tmp/redis.conf"
ACL_FILE="/tmp/users.acl"

# generate redis.conf file
echo "port 6379
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

resource "local_file" "haproxy-cfg" {
  content  = <<-EOT
global
  stats socket /var/run/api.sock user haproxy group haproxy mode 660 level admin expose-fd listeners
  log stdout format raw local0 info

defaults
  mode tcp
  timeout client 600s
  timeout connect 5s
  timeout server 600s
  timeout http-request 10s
  log global

frontend stats
  mode http
  bind *:8404
  stats enable
  stats uri /stats
  stats refresh 10s
  stats admin if LOCALHOST

# frontend
frontend redisfe
  bind :9001-9006
  bind :9101-9106
  use_backend redisbe1 if { dst_port 9001 }
  use_backend redisbe2 if { dst_port 9002 }
  use_backend redisbe3 if { dst_port 9003 }
  use_backend redisbe4 if { dst_port 9004 }
  use_backend redisbe5 if { dst_port 9005 }
  use_backend redisbe6 if { dst_port 9006 }
  use_backend redisbusbe1 if { dst_port 9101 }
  use_backend redisbusbe2 if { dst_port 9102 }
  use_backend redisbusbe3 if { dst_port 9103 }
  use_backend redisbusbe4 if { dst_port 9104 }
  use_backend redisbusbe5 if { dst_port 9105 }
  use_backend redisbusbe6 if { dst_port 9106 }

# Server 1
backend redisbe1
  server be1 redis-node-1:6379 check

backend redisbusbe1
  server busbe1 redis-node-1:16379 check

# Server 2
backend redisbe2
  server be2 redis-node-2:6379 check

backend redisbusbe2
  server busbe2 redis-node-2:16379 check

# Server 3
backend redisbe3
  server be3 redis-node-3:6379 check

backend redisbusbe3
  server busbe3 redis-node-3:16379 check

# Server 4
backend redisbe4
  server be4 redis-node-4:6379 check

backend redisbusbe4
  server busbe4 redis-node-4:16379 check

# Server 5
backend redisbe5
  server be5 redis-node-5:6379 check

backend redisbusbe5
  server busbe5 redis-node-5:16379 check

# Server 6
backend redisbe6
  server be6 redis-node-6:6379 check

backend redisbusbe6
  server busbe6 redis-node-6:16379 check
EOT
  filename = "${path.module}/haproxy/haproxy.cfg"
}
