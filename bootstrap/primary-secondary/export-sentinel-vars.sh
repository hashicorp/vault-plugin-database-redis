#!/bin/bash

export TEST_REDIS_SECONDARIES=$(opentofu output -json secondaries | jq 'join(":6379,") + ":6379"' | tr -d \")
export TEST_REDIS_PRIMARY_HOST=$(opentofu output -raw primary_host)
export TEST_REDIS_PRIMARY_PORT=6379

unset TEST_REDIS_SENTINELS TEST_REDIS_SENTINEL_MASTER_NAME
