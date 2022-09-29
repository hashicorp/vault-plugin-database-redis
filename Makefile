PLUGIN_NAME := $(shell command ls cmd/)
PLUGIN_DIR := $(HOME)/vault-plugins
TEST_PATH := $(shell pwd)$(TEST_REDIS_CACERT_RELATIVE_PATH)

.PHONY: default
default: dev

.PHONY: dev
dev:
	CGO_ENABLED=0 go build -o bin/$(PLUGIN_NAME) cmd/$(PLUGIN_NAME)/main.go

.PHONY: test
test:
	CGO_ENABLED=0 go test -v ./... $(TESTARGS) -timeout=20m

.PHONY: testacc
testacc:
	ACC_TEST_ENABLED=1 CA_CERT_FILE=$(TEST_PATH) REDIS_HOST=$(TEST_REDIS_HOST) REDIS_TLS=true CGO_ENABLED=0 go test -v ./... $(TESTARGS) -timeout=20m

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	gofumpt -l -w . && cd bootstrap/terraform && terraform fmt

.PHONY: setup-env
setup-env:
	cd bootstrap/terraform && terraform init && terraform apply -auto-approve


.PHONY: teardown-env
teardown-env:
	cd bootstrap/terraform && terraform init && terraform destroy -auto-approve

.PHONY: configure
configure: dev
	@./scripts/configure.sh \
	$(PLUGIN_DIR) \
	$(PLUGIN_NAME) \
	$(TEST_REDIS_HOST) \
	$(TEST_REDIS_PORT) \
	$(TEST_REDIS_USERNAME) \
	$(TEST_REDIS_PASSWORD) \
	$(TEST_PATH)
