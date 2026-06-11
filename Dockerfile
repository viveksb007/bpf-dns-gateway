# Multi-stage build for bpf-dns-gateway.
#
# Stage 1 compiles the eBPF C (via bpf2go + clang) and builds the static
# Go binary. Stage 2 is a minimal image carrying just the binary, used
# for CI artifacts and the optional DaemonSet deployment (deploy/
# daemonset.yaml). The systemd/AMI path uses the bare binary, not this
# image.
#
# Build:  docker build -t bpf-dns-gateway:dev .
# The bpf2go step needs clang + libbpf headers (bpf_helpers.h, etc.);
# bpf/headers/vmlinux.h is vendored in the repo.

# ---- Stage 1: builder ----
# Pinned to linux/amd64: the bpf2go directive in internal/ebpf/gen.go
# generates amd64-tagged bindings (-target amd64), so the build is
# x86_64-only in MVP. Building on/for arm64 would exclude the generated
# file and fail. (IPv4-only, amd64-only are documented MVP constraints.)
FROM --platform=linux/amd64 golang:1.25-bookworm AS builder

# clang/llvm for eBPF compilation; libbpf-dev provides <bpf/bpf_helpers.h>
# and <bpf/bpf_endian.h> on the clang include path.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Fetch modules first (cached layer). Needs a reachable Go module proxy
# (GOPROXY); standard for CI runners with internet access.
COPY go.mod go.sum ./
RUN go mod download

# Source.
COPY . .

# Regenerate the bpf2go objects from bpf/dns_gateway.c (does not trust
# any pre-generated .o), then build a static binary. CGO off so the
# binary runs in a scratch/distroless image.
ENV CGO_ENABLED=0
RUN go generate ./internal/ebpf/... \
    && go build -trimpath -ldflags="-s -w" -o /out/bpf-dns-gateway ./cmd/bpf-dns-gateway

# ---- Stage 2: runtime ----
# Distroless static: no shell, no package manager, minimal attack
# surface. Runs as ROOT (not :nonroot): the program creates the bpffs
# pin dir under the root-owned /sys/fs/bpf and needs CAP_BPF /
# CAP_NET_ADMIN / CAP_SYS_ADMIN to load eBPF, attach TCX, and subscribe
# to netlink. The bpffs mount + caps are supplied by the pod/host.
FROM --platform=linux/amd64 gcr.io/distroless/static-debian12:latest AS runtime

COPY --from=builder /out/bpf-dns-gateway /usr/local/bin/bpf-dns-gateway

# Metrics + health port (see config metricsAddr).
EXPOSE 9153

# Config is mounted at runtime (ConfigMap for the DaemonSet, or a host
# file for bare-metal). Default path matches the binary's --config
# default.
ENTRYPOINT ["/usr/local/bin/bpf-dns-gateway"]
CMD ["--config", "/etc/bpf-dns-gateway/config.yaml"]
