VERSION ?= dev
GO_PACKAGES = $(shell go list ./...)

.PHONY: build lint vet govulncheck test-unit test-integration test-e2e test-all test-scripts \
        tidy compose-config mermaid-check attest-probe tunnel-app

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

# The integration + e2e tiers start ephemeral containers via testcontainers-go and require a working
# Docker daemon: Valkey, MinIO (a plain-S3 stand-in), and a hermetic ACME test CA (Pebble +
# pebble-challtestsrv). No env/config is needed — the tiers provision everything (see
# internal/tunneltest/containers.go). The e2e tier also has an adb-gated real-attestation test that
# self-deploys a committed probe APK (support/attest-probe/, built via `make attest-probe`) and SKIPS
# unless a single adb device is present (never wired to CI-with-device).
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

# Builds, signs (debug keystore), and publishes the on-device attestation probe used by the adb-gated
# e2e test (see support/attest-probe/README.md). Requires the LOCAL Android SDK — Gradle finds it via
# support/attest-probe/local.properties (gitignored) or ANDROID_HOME — plus the build-tools apksigner.
# NOT a default quality gate. Regenerates the committed fixtures under fixtures/attest-probe/.
ANDROID_SDK ?= $(or $(ANDROID_HOME),$(ANDROID_SDK_ROOT),$(HOME)/Android/Sdk)
APKSIGNER ?= $(shell ls -1 $(ANDROID_SDK)/build-tools/*/apksigner 2>/dev/null | sort -V | tail -1)
attest-probe:
	@test -n "$(APKSIGNER)" || { echo "apksigner not found under $(ANDROID_SDK)/build-tools; set ANDROID_HOME"; exit 1; }
	cd support/attest-probe && ./gradlew assembleDebug
	mkdir -p fixtures/attest-probe
	cp support/attest-probe/app/build/outputs/apk/debug/app-debug.apk \
	    fixtures/attest-probe/attest-probe.apk
	sha256sum fixtures/attest-probe/attest-probe.apk | awk '{print $$1}' \
	    > fixtures/attest-probe/attest-probe.apk.sha256
	{ echo "# Debug signing-cert SHA-256 for the attest-probe APK (regenerate via 'make attest-probe')."; \
	  $(APKSIGNER) verify --print-certs fixtures/attest-probe/attest-probe.apk \
	    | awk -F': ' '/certificate SHA-256 digest/ {print tolower($$NF); exit}'; \
	} > fixtures/attest-probe/signers.allow

# Builds, signs (debug keystore), and publishes the on-device REFERENCE TUNNEL CLIENT used by the adb-gated
# TestE2E_ReferenceTunnelApp e2e test (see support/tunnel-app/README.md). Requires the LOCAL Android SDK —
# Gradle finds it via support/tunnel-app/local.properties (gitignored) or ANDROID_HOME — plus the
# build-tools apksigner. NOT a default quality gate. Regenerates the committed fixtures under
# fixtures/tunnel-app/.
tunnel-app:
	@test -n "$(APKSIGNER)" || { echo "apksigner not found under $(ANDROID_SDK)/build-tools; set ANDROID_HOME"; exit 1; }
	cd support/tunnel-app && ./gradlew assembleDebug
	mkdir -p fixtures/tunnel-app
	cp support/tunnel-app/app/build/outputs/apk/debug/app-debug.apk \
	    fixtures/tunnel-app/tunnel-app.apk
	sha256sum fixtures/tunnel-app/tunnel-app.apk | awk '{print $$1}' \
	    > fixtures/tunnel-app/tunnel-app.apk.sha256
	{ echo "# Debug signing-cert SHA-256 for the tunnel-app APK (regenerate via 'make tunnel-app')."; \
	  $(APKSIGNER) verify --print-certs fixtures/tunnel-app/tunnel-app.apk \
	    | awk -F': ' '/certificate SHA-256 digest/ {print tolower($$NF); exit}'; \
	} > fixtures/tunnel-app/signers.allow
