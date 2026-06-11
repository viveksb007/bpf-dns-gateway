# Phase 4 · Task 19 — Dockerfile for CI builds

**Status:** complete
**Commit:** (this commit)
**Files:** `Dockerfile`, `go.sum`

## What
Multi-stage Dockerfile:
- **Stage 1 (`--platform=linux/amd64 golang:1.25-bookworm`)**: installs `clang`/`llvm`/`libbpf-dev`/`make`, `go mod download`, then `go generate ./internal/ebpf/...` (recompiles the eBPF C via bpf2go — does not trust any checked-in `.o`), then `go build` a static (`CGO_ENABLED=0`, `-trimpath -ldflags="-s -w"`) binary.
- **Stage 2 (`--platform=linux/amd64 gcr.io/distroless/static-debian12:latest`)**: carries only the binary, runs as **root**. `EXPOSE 9153`, entrypoint `bpf-dns-gateway --config /etc/bpf-dns-gateway/config.yaml`.

## How tested
- Local `go build ./...` + `go vet ./...` clean.
- `go generate ./internal/ebpf/...` regenerates with **no diff** → deterministic codegen.
- `docker build` succeeded end-to-end (apt deps, eBPF recompile, static build, distroless copy) during development; the `:nonroot`→root and amd64-pin fixes were rebuilt and verified. `docker run --help` prints the expected flags (binary statically linked, runs in distroless with no libs). Image ~13MB.
- NOTE: the final no-vendor Dockerfile cannot be `docker build`-tested on THIS host — its Go module proxy resolves to a corp DNS sinkhole, so `go mod download` has no network path. That is a host quirk; the Dockerfile uses the standard `go mod download` against `GOPROXY`, which works on any CI runner with internet. The earlier (vendored) variant built successfully here, proving the clang/libbpf/codegen/distroless stages are correct; only the module-fetch step depends on the proxy.
- Not run privileged in-image; the binary is already live-verified on EKS in #15/#16/#17/#18. The DaemonSet (#21) exercises this image under privilege.

## Review
Reviewed with the Codex plugin (`/codex:review`).
- P1: `:nonroot` distroless (UID 65532) would fail `os.MkdirAll` under root-owned `/sys/fs/bpf` and lacks the caps for eBPF/TCX/netlink. Fixed → root distroless (`:latest`), documented.
- P2: `go generate` emits amd64-tagged bindings (`-target amd64` in gen.go); on an arm64 builder the generated file is excluded and the build breaks. Fixed → pinned both stages to `--platform=linux/amd64` (consistent with the documented amd64-only MVP).
- Re-review after the P1/P2 fixes + vendor removal: clean, no findings.
- Final: clean.

## Decisions
- **No `vendor/`.** Vendoring was briefly added to dodge this host's sinkholed Go proxy, then removed per user direction: it added ~19MB to the repo for a host-specific quirk. CI runners have proxy access, so the Dockerfile uses plain `go mod download`. Trade-off: cannot `docker build` on this sinkholed host (acceptable — not a CI constraint).
- **amd64-only image.** Matches the MVP's documented x86_64 scope (`gen.go` `-target amd64`). arm64 is future work alongside the bpf2go multi-target directive.
