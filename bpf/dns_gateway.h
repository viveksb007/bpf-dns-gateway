#ifndef __DNS_GATEWAY_H__
#define __DNS_GATEWAY_H__

#define TC_ACT_OK      0
#define TC_ACT_SHOT    2
#define TC_ACT_REDIRECT 7

#define ETH_P_IP    0x0800
#define ETH_HLEN    14
#define IPPROTO_UDP 17

#define MAX_DNS_NAME_LEN 128
/* MAX_LABELS bounds the suffix-match loops. Kept at 10 (not the DNS max
 * of ~127) because AWS service names have <=7 labels, and the nested
 * label-walk x per-boundary copy loops drive BPF verifier state; 20
 * exhausted the 1M-instruction limit on kernel 6.18 (passed on 6.12).
 * 10 halves the state and loads across 6.12 and 6.18. */
#define MAX_LABELS       10
#define CONNTRACK_MAX    65536

/* Conntrack entry TTL: max time a DNAT'd query can wait for its response
 * before the entry is treated as stale. Defends against {pod_ip, pod_port,
 * txid} collisions with unrelated direct VPC-DNS responses long after the
 * original query was abandoned. 5 seconds well exceeds typical DNS client
 * retry timeouts.
 */
#define CONNTRACK_TTL_NS (5ULL * 1000ULL * 1000ULL * 1000ULL)

/* Rule / default actions (design.md §6.2). A query's resolved action is
 * the most-specific matching rule's action, else gateway_config
 * .default_action. HOST_RESOLVE → DNAT to the VPC resolver;
 * CLUSTER_RESOLVE → passthrough to CoreDNS. */
#define ACTION_HOST_RESOLVE    1
#define ACTION_CLUSTER_RESOLVE 2

enum metric_id {
	METRIC_TOTAL_PACKETS = 0,
	METRIC_DNS_QUERIES,
	/* Query matched a suffix rule (either action). */
	METRIC_SUFFIX_MATCH,
	/* No rule matched; default_action applied. */
	METRIC_SUFFIX_NO_MATCH,
	METRIC_BYPASS_ACTIVE,
	METRIC_PARSE_ERROR,
	METRIC_EGRESS_SNAT,
	METRIC_EGRESS_CONNTRACK_MISS,
	METRIC_EGRESS_TOTAL,
	/* NAT rewrite helper (bpf_skb_store_bytes / bpf_l{3,4}_csum_replace)
	 * failed; already-applied steps were reverted and the packet passed
	 * through unmodified (ingress: falls back to CoreDNS). */
	METRIC_NAT_ERROR,
	/* The revert itself also failed — packet may be inconsistent
	 * (rewritten address vs stale checksum) and will likely be dropped
	 * downstream. Should never fire; alarm-worthy if it does. */
	METRIC_NAT_REVERT_FAIL,
	/* Resolved action was host-resolve → DNAT'd (rule or default). */
	METRIC_REDIRECTED,
	/* Resolved action was cluster-resolve → deliberately kept on
	 * CoreDNS (rule or default). */
	METRIC_CLUSTER_RESOLVED,
	METRIC__MAX,
};

struct suffix_key {
	__u8 name[MAX_DNS_NAME_LEN];
};

struct suffix_value {
	__u32 action;
	__u32 _pad;
};

struct gateway_config {
	__u32 coredns_ip;
	__u32 host_resolver_ip;
	__u16 dns_port;
	__u16 bypass;
	/* Action for queries matching no suffix rule (ACTION_*). Replaces
	 * the former _pad field — struct size unchanged. 0 (e.g. a stale
	 * pinned map from a pre-defaultAction binary) is treated as
	 * ACTION_CLUSTER_RESOLVE by the ingress program, preserving the
	 * original allowlist behavior. */
	__u32 default_action;
};

struct conntrack_key {
	__u32 pod_ip;
	__u16 pod_port;
	__u16 txid;
};

struct conntrack_value {
	__u32 coredns_ip;
	__u32 _pad;
	__u64 timestamp_ns;
};

struct scratch_buf {
	__u8 qname[MAX_DNS_NAME_LEN];
	__u8 lookup[MAX_DNS_NAME_LEN];
};

#endif /* __DNS_GATEWAY_H__ */
