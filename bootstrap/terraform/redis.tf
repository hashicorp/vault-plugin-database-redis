resource "null_resource" "setup_redis_docker" {
  triggers = {
    always = timestamp()
  }

  provisioner "local-exec" {
    command = "cd ../../scripts && ./gen-test-certs.sh && docker-compose up -d"
  }
}

resource "local_file" "setup_environment_file" {
  filename = "local_environment_setup.sh"
  content  = <<EOF
export TEST_REDIS_HOST=localhost &&\
export TEST_REDIS_PORT=6379 &&\
export TEST_REDIS_USERNAME=default &&\
export TEST_REDIS_PASSWORD=the-strong-one &&\
export TEST_REDIS_CACERT_RELATIVE_PATH=/scripts/tests/tls/ca.crt
EOF
}
