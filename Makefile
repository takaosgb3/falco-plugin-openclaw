PLUGIN_NAME := openclaw
SRC_DIR := ./cmd/plugin-sdk
GO_BUILD_FLAGS := -buildmode=c-shared
GO_RELEASE_FLAGS := -buildmode=c-shared -trimpath -ldflags="-s -w"

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    BINARY := lib$(PLUGIN_NAME)-plugin-darwin-arm64.dylib
    GO_ENV := CGO_ENABLED=1 GOOS=darwin GOARCH=arm64
  else
    BINARY := lib$(PLUGIN_NAME)-plugin-darwin-amd64.dylib
    GO_ENV := CGO_ENABLED=1 GOOS=darwin GOARCH=amd64
  endif
else
  BINARY := lib$(PLUGIN_NAME)-plugin-linux-amd64.so
  GO_ENV := CGO_ENABLED=1 GOOS=linux GOARCH=amd64
endif

.PHONY: build build-release test lint clean verify package vet

# Build the plugin as a shared library
# P002: -buildmode=c-shared is REQUIRED (without it, Falco cannot load the plugin)
# This will only work on Linux (macOS cannot cross-compile with CGO)
build:
	$(GO_ENV) go build $(GO_BUILD_FLAGS) -o $(BINARY) $(SRC_DIR)/

# Build optimized release binary (smaller, stripped)
build-release:
	$(GO_ENV) go build $(GO_RELEASE_FLAGS) -o $(BINARY) $(SRC_DIR)/

# Run all tests
test:
	go test ./... -v

# Run tests with coverage
test-coverage:
	go test ./pkg/... -v -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Run linter
lint:
	golangci-lint run

# Run static analysis (works on macOS)
vet:
	go vet ./...

# Clean build artifacts
clean:
	rm -f $(BINARY) *.h coverage.out checksums.sha256

# Verify the binary is a valid ELF shared object
# P001: Must be "ELF 64-bit LSB shared object" (NOT Mach-O, NOT executable)
verify:
	@echo "Verifying binary..."
	@file $(BINARY) | grep -q "ELF 64-bit LSB shared object" \
		&& echo "OK: Valid ELF shared object" \
		|| (echo "ERROR: Not a valid ELF shared object"; file $(BINARY); exit 1)
	@echo "Binary size: $$(du -h $(BINARY) | cut -f1)"

# Create release package with checksums
package: build-release verify
	sha256sum $(BINARY) > checksums.sha256
	sha256sum rules/$(PLUGIN_NAME)_rules.yaml >> checksums.sha256
	@echo ""
	@echo "Release package ready:"
	@echo "  - $(BINARY)"
	@echo "  - rules/$(PLUGIN_NAME)_rules.yaml"
	@echo "  - checksums.sha256"
	@cat checksums.sha256

# Install plugin to Falco plugins directory
install: verify
	sudo cp $(BINARY) /usr/share/falco/plugins/lib$(PLUGIN_NAME)-plugin.so
	sudo cp rules/$(PLUGIN_NAME)_rules.yaml /etc/falco/rules.d/
	@echo "Plugin installed"

# --- E2E Test Targets ---

E2E_PATTERNS_DIR := test/e2e/patterns/categories
E2E_RESULTS_DIR := e2e/results
E2E_SCRIPTS_DIR := e2e/scripts
E2E_ALLURE_DIR := e2e/allure
FALCO_BIN ?= falco
FALCO_BIN_NATIVE ?= /tmp/falco-build/build/userspace/falco/falco
FALCO_CONFIG ?= falco-local.yaml

.PHONY: e2e-pattern e2e-pipeline e2e-ci e2e-native e2e-report e2e-serve e2e e2e-all

# Level 1: Pattern coverage tests (Go test, no Falco needed)
e2e-pattern:
	go test ./test/e2e/ -v -race -run TestPattern -count=1

# Level 2: Plugin pipeline tests (Go test, no Falco needed)
e2e-pipeline:
	go test ./cmd/plugin-sdk/ -v -race -run TestPipeline -count=1 -timeout 120s

# Level 3: Falco integration tests (Linux CI/CD)
# Requires: Falco installed, plugin .so built
e2e-ci: build
	mkdir -p $(E2E_RESULTS_DIR)
	bash $(E2E_SCRIPTS_DIR)/inject_patterns.sh \
		-c $(FALCO_CONFIG) \
		-p $(E2E_PATTERNS_DIR) \
		-o $(E2E_RESULTS_DIR)/falco-output.log \
		-f $(FALCO_BIN)
	python3 $(E2E_SCRIPTS_DIR)/batch_analyzer.py \
		--patterns $(E2E_PATTERNS_DIR) \
		--falco-log $(E2E_RESULTS_DIR)/falco-output.log \
		--test-ids $(E2E_RESULTS_DIR)/test-ids.json \
		--output $(E2E_RESULTS_DIR)/test-results.json \
		--summary-output $(E2E_RESULTS_DIR)/summary.json

# Level 3: Falco integration tests (macOS native)
# Requires: Falco 0.43.0 MINIMAL_BUILD, plugin .dylib built
e2e-native: build
	mkdir -p $(E2E_RESULTS_DIR)
	bash $(E2E_SCRIPTS_DIR)/inject_patterns.sh \
		-c falco-local.yaml \
		-p $(E2E_PATTERNS_DIR) \
		-o $(E2E_RESULTS_DIR)/falco-output.log \
		-f $(FALCO_BIN_NATIVE)
	python3 $(E2E_SCRIPTS_DIR)/batch_analyzer.py \
		--patterns $(E2E_PATTERNS_DIR) \
		--falco-log $(E2E_RESULTS_DIR)/falco-output.log \
		--test-ids $(E2E_RESULTS_DIR)/test-ids.json \
		--output $(E2E_RESULTS_DIR)/test-results.json \
		--summary-output $(E2E_RESULTS_DIR)/summary.json

# Generate Allure report data from test-results.json
e2e-report:
	cd $(E2E_ALLURE_DIR) && python3 -m pytest test_e2e_wrapper.py \
		--test-results=../../$(E2E_RESULTS_DIR)/test-results.json \
		--logs-dir=../../$(E2E_RESULTS_DIR) \
		--alluredir=../../allure-results \
		-v

# Open Allure report in browser (local development)
e2e-serve:
	allure serve allure-results

# Level 1 + Level 2 combined (CI fast path, no Falco needed)
e2e: e2e-pattern e2e-pipeline

# All levels + Allure report (full E2E suite)
# Note: e2e-ci already depends on build, so no explicit build dependency needed here
e2e-all: e2e e2e-ci e2e-report
