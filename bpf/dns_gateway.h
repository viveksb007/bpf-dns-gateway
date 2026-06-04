#ifndef __DNS_GATEWAY_H__
#define __DNS_GATEWAY_H__

#define TC_ACT_OK      0
#define TC_ACT_SHOT    2
#define TC_ACT_REDIRECT 7

#define ETH_P_IP    0x0800
#define ETH_HLEN    14
#define IPPROTO_UDP 17

#define MAX_DNS_NAME_LEN 256
#define MAX_LABELS       20
#define CONNTRACK_MAX    65536

/* Conntrack entry TTL: max time a DNAT'd query can wait for its response
 * before the entry is treated as stale. Defends against {pod_ip, pod_port,
 * txid} collisions with unrelated direct VPC-DNS responses long after the
 * original query was abandoned. 5 seconds well exceeds typical DNS client
 * retry timeouts.
 */
#define CONNTRACK_TTL_NS (5ULL * 1000ULL * 1000ULL * 1000ULL)

#define ACTION_HOST_RESOLVE 1

enum metric_id {
	METRIC_TOTAL_PACKETS = 0,
	METRIC_DNS_QUERIES,
	METRIC_SUFFIX_MATCH,
	METRIC_SUFFIX_NO_MATCH,
	METRIC_BYPASS_ACTIVE,
	METRIC_PARSE_ERROR,
	METRIC_EGRESS_SNAT,
	METRIC_EGRESS_CONNTRACK_MISS,
	METRIC_EGRESS_TOTAL,
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
	__u32 _pad;
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
