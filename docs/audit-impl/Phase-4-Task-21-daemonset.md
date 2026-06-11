# Phase 4 · Task 21 — DaemonSet deployment template

**Status:** complete
**Commit:** (this commit)
**Files:** `deploy/daemonset.yaml`, `deploy/configmap.yaml`, `docs/design.md` (§3 amended), `docs/audit/001-daemonset-deployment.md` (decision)

## What
Optional Kubernetes-native deployment path (alternative to systemd/AMI), per decision 001:
- `deploy/configmap.yaml` — `bpf-dns-gateway-config` ConfigMap (kube-system) holding `config.yaml`; documents no-auto-reload (roll the DS to apply).
- `deploy/daemonset.yaml` — privileged DS: `hostPID`, `hostNetwork`, `dnsPolicy: ClusterFirstWithHostNet`, `priorityClassName: system-node-critical`, `tolerations: [{operator: Exists}]` (every node), `terminationGracePeriodSeconds: 30` (bypass→detach→unpin drain), `securityContext.privileged`, `/sys/fs/bpf` hostPath with `mountPropagation: Bidirectional`, ConfigMap mounted read-only at `/etc/bpf-dns-gateway`, `/healthz` liveness+readiness on 9153, Prometheus scrape annotations, resource requests/limits.
- `docs/design.md` §3 "What this is NOT" amended: DaemonSet is now a supported optional path, not an anti-goal.

## How tested
- `kubectl apply --dry-run=client` on both manifests: valid.
- Embedded ConfigMap `config.yaml` validated through the real `config.Load` parser (temp test, PASS) — guards against schema drift in the manifest.
- **Live on EKS** (cluster `example-cluster`, both nodes):
  - Built the image (#19 Dockerfile), pushed to ECR `144465910773.dkr.ecr.us-west-2.amazonaws.com/bpf-dns-gateway:dev`.
  - Applied ConfigMap + DS (image ref swapped to the ECR digest for the live run; the committed template keeps the `bpf-dns-gateway:dev` placeholder).
  - DS rolled to **2/2 ready** (readiness `/healthz` passing) on both nodes.
  - Pod logs: `ready`, attached to real pod veths (`eni3031980e328`, `eni0ca8ce2ba2c`).
  - Metrics scraped from a peer pod against node:9153 — `attached_veths 3` (live picked up the scraper pod's veth), `bypass_active 0`, `health_check_failures 0`, `ingress_total_packets 7`, `suffix_rules_loaded 4`.
  - `rollout restart ds/...` → successfully rolled out, new pods `ready`, **0 ERROR** lines.
  - Cleaned up: DS + ConfigMap deleted, local image tar removed. (ECR repo left in the user's account.)

## Review
Reviewed with the Codex plugin (`/codex:review`). 2 P2 findings, both fixed + re-verified live:
- P2: `tolerations: Exists` schedules everywhere but the image is linux/amd64 + needs Linux eBPF/TCX → pods on other platforms fail. Fixed: `nodeSelector: {kubernetes.io/os: linux, kubernetes.io/arch: amd64}`.
- P2: privileged hostNetwork pod got an automounted kube API token it never uses. Fixed: `automountServiceAccountToken: false`. Verified live — pod volumes are only `bpffs` + `config`, no `kube-api-access-*` token volume.
- Re-deployed after the fixes: 2/2 ready on both amd64 nodes.
- Final: clean.

## Decisions
- See `docs/audit/001-daemonset-deployment.md` (DaemonSet as optional path; trade-offs vs systemd: loses start-before-kubelet + adds K8s-API-at-rollout dependency; no code change; TCX auto-detach safety preserved).
