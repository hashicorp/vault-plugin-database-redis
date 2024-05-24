#!/bin/bash

export TEST_REDIS_SENTINELS=$(opentofu output -json env_var | jq 'join(":26379,")')
export TEST_REDIS_SENTINEL_MASTER_NAME=$(opentofu output -raw env_master)
