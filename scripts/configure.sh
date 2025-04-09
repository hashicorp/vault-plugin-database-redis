#! /usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -eu -o pipefail

PLUGIN_DIR="${1}"
PLUGIN_NAME="${2}"
TEST_REDIS_HOST="${3:-localhost}"
TEST_REDIS_PORT="${4:-6379}"
TEST_REDIS_USERNAME="${5:-us4rn4m3}"
TEST_REDIS_PASSWORD="${6:-user-pa55w0rd}"

vault plugin deregister "$PLUGIN_NAME" 2> /dev/null || true
vault secrets disable database 2> /dev/null || true
killall "$PLUGIN_NAME" 2> /dev/null || true

if ! [ -f "$PLUGIN_DIR/$PLUGIN_NAME" ]; then
  echo "Plugin binary not found at $PLUGIN_DIR/$PLUGIN_NAME"
  exit 1
fi

# Sets up the binary with local changes
vault secrets enable database
vault plugin register \
      -sha256="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')" \
      database "$PLUGIN_NAME"

# Configure & test the new registered plugin
vault write database/config/local-redis \
      plugin_name="$PLUGIN_NAME" \
    	allowed_roles="*" \
    	host="$TEST_REDIS_HOST" \
    	port="$TEST_REDIS_PORT" \
    	username="$TEST_REDIS_USERNAME" \
    	password="$TEST_REDIS_PASSWORD" \
    	insecure_tls=true

vault write database/roles/my-dynamic-role \
    db_name="local-redis" \
    creation_statements='["+@read"]' \
    default_ttl="5m" \
    max_ttl="1h"

vault read database/creds/my-dynamic-role
