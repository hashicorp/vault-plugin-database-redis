resource "null_resource" "setup_redis_docker" {
  triggers = {
    always = timestamp()
  }

  provisioner "local-exec" {
    command = "cd ../../scripts && ./gen-test-certs.sh && docker run --name vault_redis_test -p 6379:6379 -d redis"
  }
}

resource "null_resource" "teardown_redis_docker" {
  triggers = {
    always = timestamp()
  }

  provisioner "local-exec" {
    when = destroy
    command = "docker stop vault_redis_test && docker rm vault_redis_test"
  }
}

resource "local_file" "setup_environment_file" {
  filename = "local_environment_setup.sh"
  content  = <<EOF
export TEST_REDIS_HOST=localhost &&\
export TEST_REDIS_PORT=6379 &&\
export TEST_REDIS_USERNAME=default &&\
export TEST_REDIS_PASSWORD=the-strong-one &&\
export TEST_REDIS_CACERT_RELATIVE_PATH=/scripts/tests/tls/ca.crt &&\
export TEST_REDIS_TLS=true
EOF
}
