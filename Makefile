VERSION ?= dev
GO_PACKAGES = $(shell go list ./...)

.PHONY: build lint vet govulncheck test-unit test-integration test-e2e test-all test-scripts \
        tidy compose-config mermaid-check

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/tunneld ./cmd/tunneld

# Three passes, one per build-tag set: files behind `//go:build integration` / `//go:build e2e` are
# INVISIBLE to an untagged run, so a single `golangci-lint run ./...` silently skips every tagged
# test file. Each pass compiles a different file set, so all three are required.
lint:
	golangci-lint run ./...
	golangci-lint run --build-tags=integration ./...
	golangci-lint run --build-tags=e2e ./...
	shellcheck deploy/scripts/*.sh deploy/fetcher/command.sh scripts/*.sh
	$(MAKE) compose-config

vet:
	go vet $(GO_PACKAGES)

# govulncheck is pinned via the go.mod `tool` directive, NOT @latest: resolving @latest needs an
# uncacheable /@v/list query to the proxy on every run, and an upstream release could turn CI red
# with no code change. `go tool` uses the version + checksum recorded in go.mod/go.sum.
govulncheck:
	go tool govulncheck ./...

test-unit:
	go test -short -race -count=1 $(GO_PACKAGES)

test-integration:
	go test -tags=integration -race -count=1 -timeout 30m -v ./...

test-e2e:
	go test -tags=e2e -race -count=1 -timeout 20m -v ./e2e/...

test-all: test-unit test-integration test-e2e

test-scripts:
	sh deploy/scripts/scripts_test.sh

tidy:
	go mod tidy

# compose-config validates the deployment stack; --env-file supplies placeholder values so a bare
# checkout / CI (no .env) does not fail the ${DEPLOY_UID:?} interpolation.
compose-config:
	docker compose --env-file deploy/.env.example -f deploy/docker-compose.yml config -q

# Validates every ```mermaid block in README.md and under docs/ via mmdc (mermaid-cli).
mermaid-check:
	sh scripts/mermaid-check.sh README.md $(shell find docs -name '*.md')
