#!/bin/bash

export TEST_REDIS_SENTINELS=$(opentofu output -json env_var | jq 'join(":26379,") + ":26370"' | tr -d \")
export TEST_REDIS_SENTINEL_MASTER_NAME=$(opentofu output -raw env_master)

unset TEST_REDIS_PRIMARY_HOST TEST_REDIS_PRIMARY_PORT TEST_REDIS_SECONDARIES TEST_REDIS_CLUSTER