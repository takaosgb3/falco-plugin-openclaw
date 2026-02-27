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
