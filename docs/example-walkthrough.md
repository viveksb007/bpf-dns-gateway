# eBPF DNS Matching Walkthrough

End-to-end trace of how a DNS query for `viveksbh-test-bucket.s3.us-west-2.amazonaws.com` flows through the eBPF datapath.

## Setup

Config on the node:

```yaml
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - pattern: "*.s3.amazonaws.com"
    action: host-resolve
  - pattern: "*.s3.us-west-2.amazonaws.com"
    action: host-resolve
```

The controller encodes these rules into the `suffix_rules` BPF hash map:

```
Rule: "*.s3.amazonaws.com"
  strip "*." → "s3.amazonaws.com"
  wire-format key: \x02s3\x09amazonaws\x03com\x00  (zero-padded to 256 bytes)

Rule: "*.s3.us-west-2.amazonaws.com"
  strip "*." → "s3.us-west-2.amazonaws.com"
  wire-format key: \x02s3\x09us-west-2\x09amazonaws\x03com\x00  (zero-padded to 256 bytes)
```

## Step 1: Pod Sends DNS Query

A pod at `10.0.5.23` runs `aws s3 ls s3://viveksbh-test-bucket`. The AWS SDK resolves `viveksbh-test-bucket.s3.us-west-2.amazonaws.com` by sending a UDP DNS query to `10.100.0.10:53` (CoreDNS) from ephemeral port `43721`.

## Step 2: DNS Wire Format

The DNS library encodes the QNAME in wire format — a sequence of (length-byte, label-bytes) terminated by `0x00`:

```
Offset  Hex                                    Meaning
──────  ─────────────────────────────────────  ──────────────────────
 0      14                                     length = 20
 1-20   76 69 76 65 6b 73 62 68 2d 74 65 73   "viveksbh-test-bucket"
        74 2d 62 75 63 6b 65 74
21      02                                     length = 2
22-23   73 33                                  "s3"
24      09                                     length = 9
25-33   75 73 2d 77 65 73 74 2d 32             "us-west-2"
34      09                                     length = 9
35-43   61 6d 61 7a 6f 6e 61 77 73             "amazonaws"
44      03                                     length = 3
45-47   63 6f 6d                               "com"
48      00                                     terminator
```

Total QNAME: 49 bytes, 5 labels.

## Step 3: eBPF Ingress — Fast-Path Filters

The packet arrives on the host-side veth. The TC ingress eBPF program runs. Before any DNS parsing, it applies cheap constant comparisons that reject ~99.9% of packets:

```
ETH header  → h_proto == 0x0800 (IPv4)?           ✓
IP header   → protocol == 17 (UDP)?               ✓
            → daddr == 10.100.0.10 (CoreDNS)?     ✓
UDP header  → dport == 53?                         ✓
DNS header  → QR bit == 0 (query, not response)?   ✓
            → QDCOUNT >= 1?                        ✓
```

All checks pass. The program proceeds to DNS parsing.

## Step 4: Load QNAME into Scratch Buffer

The 49-byte QNAME is copied from the packet into a per-CPU scratch buffer via `bpf_skb_load_bytes`. The scratch buffer lives in a BPF per-CPU array map (not on the stack) to stay within the 512-byte stack limit.

## Step 5: Walk Labels

The eBPF program walks the wire-format labels in a bounded loop (max 20 iterations) to find each label boundary offset:

```
Iteration 0:  pos=0   → label_len=0x14 (20) → valid (≤63, not ≥0xC0)
              label_offsets[0] = 0
              pos = 0 + 1 + 20 = 21

Iteration 1:  pos=21  → label_len=0x02 (2)  → valid
              label_offsets[1] = 21
              pos = 21 + 1 + 2 = 24

Iteration 2:  pos=24  → label_len=0x09 (9)  → valid
              label_offsets[2] = 24
              pos = 24 + 1 + 9 = 34

Iteration 3:  pos=34  → label_len=0x09 (9)  → valid
              label_offsets[3] = 34
              pos = 34 + 1 + 9 = 44

Iteration 4:  pos=44  → label_len=0x03 (3)  → valid
              label_offsets[4] = 44
              pos = 44 + 1 + 3 = 48

Iteration 5:  pos=48  → label_len=0x00       → END OF QNAME, break

Result: num_labels=5, qname_total_len=49
```

If any label had `length >= 0xC0` (compression pointer) or `length > 63` (invalid), the program would immediately return `TC_ACT_OK` — passthrough to CoreDNS, no DNAT.

## Step 6: Lowercase

A bounded loop (max 256 iterations) lowercases the QNAME in the scratch buffer. This domain is already lowercase so nothing changes, but a query for `VIVEKSBH-TEST-BUCKET.S3.US-WEST-2.AMAZONAWS.COM` would be normalized here. DNS is case-insensitive per RFC 1035, and suffix map keys are stored lowercase.

## Step 7: Suffix Matching

This is the core algorithm. The key insight: the wire-format bytes from any label boundary to the end of the QNAME is itself a valid wire-format DNS name. The program tries a hash map lookup for each suffix, starting from the full name and working inward. Any matching suffix triggers redirect (rules are not ordered — all configured rules share the same action in MVP).

**Iteration 0** — offset 0, suffix = full QNAME (49 bytes):

```
lookup buffer (256 bytes, zero-filled):
  \x14viveksbh-test-bucket\x02s3\x09us-west-2\x09amazonaws\x03com\x00[zeros...]

→ bpf_map_lookup_elem(&suffix_rules, lookup) → NULL (no match)
```

This is the full domain name `viveksbh-test-bucket.s3.us-west-2.amazonaws.com`. No rule matches the exact full name.

**Iteration 1** — offset 21, suffix = 28 bytes:

```
lookup buffer (256 bytes, zero-filled):
  \x02s3\x09us-west-2\x09amazonaws\x03com\x00[zeros...]

→ bpf_map_lookup_elem(&suffix_rules, lookup) → ✅ MATCH!
  Matched rule: "*.s3.us-west-2.amazonaws.com", action = HOST_RESOLVE
```

The wire encoding of `s3.us-west-2.amazonaws.com` matches the pre-stored key. The program jumps to DNAT.

Iterations 2–4 are never executed.

### What happens if only `*.s3.amazonaws.com` is configured?

If the regional rule `*.s3.us-west-2.amazonaws.com` were missing from the config, the matching would fail:

```
Iter 0:  \x14viveksbh-test-bucket\x02s3\x09us-west-2\x09amazonaws\x03com\x00
         = "viveksbh-test-bucket.s3.us-west-2.amazonaws.com"  → NO MATCH

Iter 1:  \x02s3\x09us-west-2\x09amazonaws\x03com\x00
         = "s3.us-west-2.amazonaws.com"                       → NO MATCH ❌
         (This is NOT "s3.amazonaws.com" — the "us-west-2" label is in the way)

Iter 2:  \x09us-west-2\x09amazonaws\x03com\x00
         = "us-west-2.amazonaws.com"                          → NO MATCH

Iter 3:  \x09amazonaws\x03com\x00
         = "amazonaws.com"                                    → NO MATCH

Iter 4:  \x03com\x00
         = "com"                                              → NO MATCH

→ All suffixes exhausted → TC_ACT_OK (passthrough to CoreDNS)
```

**`*.s3.amazonaws.com` matches `mybucket.s3.amazonaws.com` but NOT `mybucket.s3.us-west-2.amazonaws.com`**. The suffix matching operates at label boundaries — `s3.us-west-2.amazonaws.com` and `s3.amazonaws.com` are different suffixes. Both rules must be configured:

```yaml
rules:
  - pattern: "*.s3.amazonaws.com"           # global endpoint
    action: host-resolve
  - pattern: "*.s3.us-west-2.amazonaws.com" # regional endpoint
    action: host-resolve
```

## Step 8: DNAT

The suffix matched. The eBPF program rewrites the packet destination:

Assume the DNS header `txid` is `0x8a3f` (resolvers randomize this per query).

```
1. Create conntrack entry:
   key:   {pod_ip: 10.0.5.23, pod_port: 43721, txid: 0x8a3f}
   value: {coredns_ip: 10.100.0.10, timestamp_ns: <now>}

2. Rewrite IP destination address:
   daddr: 10.100.0.10 (CoreDNS) → 10.0.0.2 (VPC DNS)

3. Fix IP header checksum:
   bpf_l3_csum_replace(skb, ..., old_daddr, new_daddr, 4)

4. Fix UDP checksum (pseudo-header includes dst IP):
   bpf_l4_csum_replace(skb, ..., old_daddr, new_daddr,
                        BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4)

5. return TC_ACT_OK
   → kernel routes the modified packet to 10.0.0.2 (VPC DNS resolver)
```

The DNS payload is untouched. Only the IP destination and checksums change.

## Step 9: VPC DNS Resolves

The VPC DNS resolver at `10.0.0.2` receives the query (src=`10.0.5.23:43721`, dst=`10.0.0.2:53`). Because EKS VPC CNI assigns pod IPs from VPC secondary IPs, the pod IP is routable and the VPC resolver can respond directly.

The resolver returns the S3 endpoint IP addresses, optimized for the node's actual location in the VPC.

## Step 10: Response — Egress SNAT

The response arrives: `src=10.0.0.2:53, dst=10.0.5.23:43721`. It travels through the host network stack toward the pod's veth. The TC egress eBPF program fires:

```
1. Parse headers:
   saddr == 10.0.0.2 (host resolver)?   ✓
   sport == 53?                          ✓
   extract txid from DNS hdr → 0x8a3f

2. Conntrack lookup:
   key: {pod_ip: 10.0.5.23, pod_port: 43721, txid: 0x8a3f}
   → value: {coredns_ip: 10.100.0.10, timestamp_ns: T0}   ✓ FOUND

3. TTL check:
   now - T0 < CONNTRACK_TTL_NS (5s)?   ✓ fresh
   (Stale entries are deleted + passthrough so unrelated direct VPC-DNS
    responses with the same {pod_ip, pod_port, txid} cannot be wrongly SNAT'd.)

4. SNAT — rewrite source:
   saddr: 10.0.0.2 → 10.100.0.10 (CoreDNS)

5. Fix IP header checksum
6. Fix UDP checksum

7. Delete conntrack entry (response delivered; no further responses expected)

8. return TC_ACT_OK
   → packet delivered to pod
```

Note: bypass on the gateway does NOT short-circuit egress. If the controller flips bypass while a query is in flight, the response still arrives from VPC DNS and must be SNAT'd back; egress always processes conntrack hits so the pod never sees `src=10.0.0.2`.

## Step 11: Pod Receives Response

The pod at `10.0.5.23` receives a DNS response from `10.100.0.10:53` (CoreDNS) on port `43721`. From the pod's perspective, CoreDNS answered the query. The interception was completely transparent.

```
Before eBPF:     pod ──→ CoreDNS ──→ VPC DNS ──→ CoreDNS ──→ pod
After eBPF:      pod ──→ VPC DNS ──→ pod  (appears as CoreDNS to the pod)
```

## Summary

| Phase | Location | Work |
|-------|----------|------|
| Fast-path filter | eBPF ingress | 5 constant comparisons (~10 ns) |
| QNAME extraction | eBPF ingress | Copy 49 bytes to scratch buffer |
| Label walk | eBPF ingress | 6 iterations, find 5 label boundaries |
| Lowercase | eBPF ingress | 49 byte comparisons (no-op if already lowercase) |
| Suffix matching | eBPF ingress | 2 hash map lookups (match on 2nd) |
| DNAT | eBPF ingress | 1 conntrack write, 1 IP rewrite, 2 checksum fixes |
| SNAT | eBPF egress | 1 conntrack read + delete, 1 IP rewrite, 2 checksum fixes |
