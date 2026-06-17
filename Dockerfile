# syntax=docker/dockerfile:1

# ---- Build stage ----
# go.mod declares `go 1.26.4`, so the builder must be >= 1.26 (the
# task text mentions 1.22, but that predates the current go.mod and
# would fail to build / trigger a toolchain auto-download).
FROM golang:1.26-bookworm AS builder

# Same toolchain used throughout local development: clang/llvm compile
# the .bpf.c programs, libbpf-dev provides the headers bpf2go needs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache module downloads on their own layer.
COPY go.mod go.sum ./
RUN go mod download

# Bring in the rest of the source.
COPY . .

# Pure-Go binary (cilium/ebpf uses CO-RE, no cgo needed). bpf2go still
# shells out to clang during `go generate`, which is why this stage has it.
ENV CGO_ENABLED=0
RUN go generate ./... \
    && go build -o /out/traceguard .

# ---- Runtime stage ----
FROM alpine:3.20

# ca-certificates lets the optional -webhook flag's HTTPS POST verify
# TLS; alpine's base image ships no CA bundle.
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/traceguard /usr/local/bin/traceguard
COPY rules.yaml /etc/traceguard/rules.yaml

WORKDIR /etc/traceguard

# Loading eBPF at runtime needs root/elevated capabilities; that's
# supplied at `docker run` time (--privileged or appropriate caps),
# so deliberately no USER directive here.
ENTRYPOINT ["/usr/local/bin/traceguard", "-rules", "/etc/traceguard/rules.yaml"]
