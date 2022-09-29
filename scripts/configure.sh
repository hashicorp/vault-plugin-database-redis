PLUGIN_DIR=$1
PLUGIN_NAME=$2

TEST_REDIS_HOST=$3
TEST_REDIS_PORT=$4
TEST_REDIS_USERNAME=$5
TEST_REDIS_PASSWORD=$6
TEST_REDIS_CACERT_PATH=$7

vault plugin deregister "$PLUGIN_NAME"
vault secrets disable database
killall "$PLUGIN_NAME"

rm "$PLUGIN_DIR"/"$PLUGIN_NAME"
cp ./bin/"$PLUGIN_NAME" "$PLUGIN_DIR"/"$PLUGIN_NAME"

vault secrets enable database
vault plugin register \
      -sha256="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')" \
      database "local-$PLUGIN_NAME"

vault write database/config/local-redis \
        plugin_name="local-$PLUGIN_NAME" \
    	allowed_roles="*" \
    	host="$TEST_REDIS_HOST" \
    	port="$TEST_REDIS_PORT" \
    	username="$TEST_REDIS_USERNAME" \
    	password="$TEST_REDIS_PASSWORD" \
    	ca_cert="$(cat "$TEST_REDIS_CACERT_PATH")" \
    	tls=true \
    	insecure_tls=true
