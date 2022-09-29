PLUGIN_DIR=$1
PLUGIN_NAME=$2

TEST_REDIS_HOST=$3
TEST_REDIS_PORT=$4
TEST_REDIS_USERNAME=$5
TEST_REDIS_PASSWORD=$6
TEST_REDIS_CACERT_PATH=$7

LOCAL_PLUGIN_NAME=local-"$PLUGIN_NAME"
PLUGIN_BINARY_LOCATION="$PLUGIN_DIR"/"$LOCAL_PLUGIN_NAME"

vault plugin deregister "$LOCAL_PLUGIN_NAME"
vault secrets disable database
killall "$LOCAL_PLUGIN_NAME"

rm "$PLUGIN_BINARY_LOCATION"
cp ./bin/"$PLUGIN_NAME" "$PLUGIN_BINARY_LOCATION"

vault secrets enable database
vault plugin register \
      -sha256="$(shasum -a 256 "$PLUGIN_BINARY_LOCATION" | awk '{print $1}')" \
      database "$LOCAL_PLUGIN_NAME"


vault write database/config/local-redis \
        plugin_name="$LOCAL_PLUGIN_NAME" \
    	allowed_roles="*" \
    	host="$TEST_REDIS_HOST" \
    	port="$TEST_REDIS_PORT" \
    	username="$TEST_REDIS_USERNAME" \
    	password="$TEST_REDIS_PASSWORD" \
    	ca_cert="$(cat "$TEST_REDIS_CACERT_PATH")" \
    	tls=true \
    	insecure_tls=true
