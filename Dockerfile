# Multi-stage build: Build plugin on Linux, run with Falco
# Stage 1: Build the plugin as a Linux shared library
FROM golang:1.22-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# P002: -buildmode=c-shared is REQUIRED
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -buildmode=c-shared \
    -o libopenclaw-plugin.so ./cmd/plugin-sdk/

# Stage 2: Run Falco with the plugin
FROM falcosecurity/falco-no-driver:0.39.2

# Copy plugin binary
COPY --from=builder /build/libopenclaw-plugin.so /usr/share/falco/plugins/

# Copy rules
COPY rules/openclaw_rules.yaml /etc/falco/rules.d/

# Copy Falco config
COPY falco-docker.yaml /etc/falco/falco.yaml

# Create log directories that will be mounted
RUN mkdir -p /openclaw-logs/sessions /openclaw-logs/logs

# P009: Falco runs as entrypoint
ENTRYPOINT ["falco"]
CMD ["--disable-source", "syscall"]
