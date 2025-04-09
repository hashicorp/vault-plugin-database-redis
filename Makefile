REPO_DIR := $(shell basename $(CURDIR))
PLUGIN_DIR := $(GOPATH)/vault-plugins
PLUGIN_NAME := vault-plugin-database-redis

.PHONY: default
default: dev

.PHONY: dev
dev:
	CGO_ENABLED=0 go build -o bin/$(PLUGIN_NAME) cmd/$(PLUGIN_NAME)/main.go

.PHONY: bootstrap
bootstrap:
	@echo "Downloading tools ..."
	@go generate -tags tools tools/tools.go
	# This should only ever be performed once, so we lean on the cmd/ directory
	# to indicate whether this has already been done.
	@if [ "$(PLUGIN_NAME)" != "$(REPO_DIR)" ]; then \
		echo "Renaming cmd/$(PLUGIN_NAME) to cmd/$(REPO_DIR) ..."; \
		mv cmd/$(PLUGIN_NAME) to cmd/$(REPO_DIR); \
		echo "Renaming Go module to github.com/hashicorp/$(REPO_DIR) ..."; \
        go mod edit -module github.com/hashicorp/$(REPO_DIR); \
	fi

.PHONY: test
test: fmtcheck
	CGO_ENABLED=0 go test -v ./... $(TESTARGS) -timeout=20m

.PHONY: testacc
testacc: fmtcheck
	CGO_ENABLED=0 VAULT_ACC=1 go test -v ./... $(TESTARGS) -timeout=20m

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	gofumpt -l -w . && cd bootstrap/terraform && terraform fmt

.PHONY: setup-env
setup-env: docker-compose
	mkdir -p build/terraform/state
	cp -a bootstrap/terraform/* build/terraform/state/.
	export PATH="$(CURDIR)/bin:$(PATH)"; cd build/terraform/state && \
	terraform init && \
	terraform apply -auto-approve

.PHONY: teardown-env
teardown-env:
	cd bootstrap/terraform && terraform init && terraform destroy -auto-approve

.PHONY: configure
configure: dev
	./scripts/configure.sh \
	$(PLUGIN_DIR) \
	$(PLUGIN_NAME) \
	$(TEST_REDIS_HOST) \
	$(TEST_REDIS_PORT) \
	$(TEST_REDIS_USERNAME) \
	$(TEST_REDIS_PASSWORD)

clean:
	rm -rf build &> /dev/null

.PHONY: docker-compose
DOCKER_COMPOSE = ./bin/docker-compose
docker-compose: ## Download terraform locally if necessary.
ifeq (,$(wildcard $(DOCKER_COMPOSE)))
ifeq (,$(shell which $(notdir $(DOCKER_COMPOSE)x) 2>/dev/null))
	{ \
	set -e ;\
	mkdir -p $(dir $(DOCKER_COMPOSE)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH | sed -e 's/arm64/aarch64/' -e 's/amd64/x86_64/') && \
	curl -vfLo $(DOCKER_COMPOSE) https://github.com/docker/compose/releases/download/v2.34.0/docker-compose-$${OS}-$${ARCH}; \
	chmod +x $(DOCKER_COMPOSE) ; \
	}
else
TERRAFORM = $(shell which terraform)
endif
endif
