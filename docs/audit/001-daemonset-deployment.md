# Decision 001 — Support DaemonSet deployment alongside systemd

**Status:** accepted
**Date:** 2026-06-11
**Driver:** user request — "we also want to be able to deploy this as a DaemonSet on a k8s cluster"

## Context
`docs/design.md` §3/§4 deliberately scoped this as **not** a Kubernetes
component: it ships as a systemd `Type=notify` service baked into the node AMI,
starting `Before=kubelet.service`. The design "What this is NOT" section
explicitly lists "Not a Kubernetes component — no DaemonSet, no K8s API
dependency, no RBAC."

The user now wants a DaemonSet path as well, for clusters that prefer a
K8s-native rollout over baking the binary into an AMI.

## Decision
Add a DaemonSet as an **additional, optional** deployment artifact (task #21).
The systemd/AMI path remains the primary, recommended one. Both consume the
same binary and config schema; only the delivery/lifecycle wrapper differs.

## Trade-offs (what the DaemonSet path gives up vs systemd)
1. **Start-before-kubelet is lost.** A DaemonSet pod can only start *after*
   kubelet and the CNI are up, so there is a window at node boot where pods may
   send DNS before our programs attach. Mitigated by startup reconciliation
   (the monitor's ListExisting replay attaches to veths that already exist) —
   but queries in the gap go to CoreDNS, which is correct (just unoptimized).
2. **K8s API dependency at rollout.** The DaemonSet controller needs the API
   server reachable to schedule/upgrade pods. The running pod itself has no
   client-go dependency (it still only reads a file + netlink + bpffs), so a
   later API outage does not stop an already-running pod.
3. **Crash/upgrade churn.** Rolling a DaemonSet detaches+reattaches TCX programs
   per node; brief passthrough-to-CoreDNS windows per rollout. Same safety
   posture as a systemd restart.
4. **Privilege surface.** Needs a privileged (or `CAP_BPF`+`CAP_NET_ADMIN`+
   `CAP_SYS_ADMIN`) pod with `hostPID`, `hostNetwork`, and a `/sys/fs/bpf`
   hostPath bind-mount with `Bidirectional` propagation. Equivalent to what the
   systemd service already has on the host, but now expressed as pod security
   that cluster admins must allow (PSA `privileged`).

## Invariants preserved
- No code changes required: the binary already reads config from a file path
  (`--config`), pins under `--pin-dir`, and needs only root + bpffs + netlink —
  all satisfiable in a privileged pod. The DaemonSet is pure packaging.
- TCX auto-detach on process exit still gives safe fallback to CoreDNS on pod
  kill/crash.

## Consequences
- `deploy/daemonset.yaml` + `deploy/configmap.yaml` added (task #21), gated on
  the container image from #19.
- README (#20) documents both paths and when to pick which.
- design.md §3 "What this is NOT" to be amended: DaemonSet is now a supported
  *optional* path, not an anti-goal — update when #21 lands.
