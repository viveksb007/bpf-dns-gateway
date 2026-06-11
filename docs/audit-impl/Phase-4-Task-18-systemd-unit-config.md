# Phase 4 · Task 18 — systemd unit + example config

**Status:** complete
**Commit:** (this commit)
**Files:** `deploy/bpf-dns-gateway.service`, `deploy/config.yaml`, `internal/config/deploy_example_test.go`

## What
- `deploy/bpf-dns-gateway.service` — `Type=notify` unit. `After/Wants=network-online.target`, `After/Requires=sys-fs-bpf.mount` (map pinning needs bpffs), `Before=kubelet.service` (attach before pods start). `LimitMEMLOCK=infinity` (eBPF map alloc), `Restart=always`/`RestartSec=5`, `TimeoutStopSec=30` (drain window for bypass→detach→unpin), `OOMScoreAdjust=-500`, install hints in header comment.
- `deploy/config.yaml` — example with CoreDNS ClusterIP guidance, required `hostResolverIP` (VPC base+2 or 169.254.169.253, with the systemd-resolved-stub warning), S3/ECR/STS wildcard rules, `metricsAddr`, healthCheck block, logLevel. Notes the case-sensitive-matching MVP caveat.
- `internal/config/deploy_example_test.go` — regression guard: parses `deploy/config.yaml` through the real loader so schema drift breaks the build.

## How tested
- `deploy/config.yaml` parses + validates via the real `config.Load` (new `TestDeployExampleConfigValid`, PASS).
- `systemd-analyze verify deploy/bpf-dns-gateway.service` — no syntax errors in our unit (only the expected "binary not installed here" note + unrelated pre-existing host-unit warnings).
- Live (EKS), node `ip-192-168-3-205`, privileged hostNetwork pod, `/sys/fs/bpf` bind-mounted: ran the built binary with a fake `NOTIFY_SOCKET` (socat unixgram sink) to exercise the real `Type=notify` path. Captured datagrams: **`READY=1`** on startup and **`STOPPING=1`** on SIGTERM. Confirms sd_notify works for real (it is a no-op only when NOTIFY_SOCKET is unset). Shutdown reached `shutdown complete`, pin dir removed, 0 ERROR lines.

## Review
Reviewed with the Codex plugin (`/codex:review`). Round 1 clean — no findings.

## Decisions
- none. (Hardening kept loose — runs as root with full caps — because eBPF load + TCX attach + netlink + bpffs need CAP_BPF/CAP_NET_ADMIN/CAP_SYS_ADMIN; documented inline.)
