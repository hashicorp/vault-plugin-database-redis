docker run -d \
  -p 6379:6379 \
  -u "${UID}:${GID}" \
  -e ALLOW_EMPTY_PASSWORD=false \
  -e REDIS_USERNAME=default \
  -e REDIS_PASSWORD=the-strong-one \
  -e REDIS_DISABLE_COMMANDS=FLUSHDB,FLUSHALL \
  -e REDIS_TLS_CERT_FILE=/tls/redis.crt \
  -e REDIS_TLS_KEY_FILE=/tls/redis.key \
  -e REDIS_TLS_CA_FILE=/tls/ca.crt \
  -e REDIS_TLS_ENABLED=yes \
  -e REDIS_TLS_PORT=6379 \
  -e REDIS_TLS_AUTH_CLIENTS=no \
  -v redis_data:/bitnami/redis/data \
  -v $(pwd)/tests/tls:/tls \
  --volume-driver local \
  --name vault_redis_test \
  docker.io/bitnami/redis:6.2