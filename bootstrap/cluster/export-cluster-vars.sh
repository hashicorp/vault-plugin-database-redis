#!/bin/bash
HERE="$(dirname ${BASH_SOURCE})"

cd $HERE

export TEST_REDIS_CLUSTER=$(terraform output -json cluster-nodes | gojq 'join(":6379,") + ":6379"' | tr -d \")
export TEST_REDIS_TLS=$(terraform output -raw use-tls)
if [ $TEST_REDIS_TLS == "false" ]
then
  export TEST_REDIS_TLS=""
fi
export CA_CERT_FILE=$PWD/data/ca.crt
export TLS_CERT_FILE=$PWD/data/tls.crt
export TLS_KEY_FILE=$PWD/data/tls.key

unset TEST_REDIS_PRIMARY_HOST TEST_REDIS_PRIMARY_PORT TEST_REDIS_SECONDARIES TEST_REDIS_SENTINELS TEST_REDIS_SENTINEL_MASTER_NAME

cd -
