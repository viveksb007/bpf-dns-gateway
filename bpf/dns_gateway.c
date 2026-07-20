//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "dns_gateway.h"

char _license[] SEC("license") = "GPL";

/* --- Maps --- */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct suffix_key);
	__type(value, struct suffix_value);
	__uint(max_entries, 1024);
} suffix_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct gateway_config);
	__uint(max_entries, 1);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct conntrack_key);
	__type(value, struct conntrack_value);
	__uint(max_entries, CONNTRACK_MAX);
} conntrack_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, METRIC__MAX);
} metrics_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct scratch_buf);
	__uint(max_entries, 1);
} scratch_map SEC(".maps");

/* --- Helpers --- */

static __always_inline void increment_metric(__u32 metric_id)
{
	__u64 *val = bpf_map_lookup_elem(&metrics_map, &metric_id);
	if (val)
		(*val)++;
}

/* --- Ingress: DNS parse + suffix match + DNAT --- */

SEC("tc/ingress")
int dns_gateway_ingress(struct __sk_buff *skb)
{
	increment_metric(METRIC_TOTAL_PACKETS);

	__u32 cfg_key = 0;
	struct gateway_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
	if (!cfg)
		return TC_ACT_OK;

	if (cfg->bypass) {
		increment_metric(METRIC_BYPASS_ACTIVE);
		return TC_ACT_OK;
	}

	/* Parse Ethernet header */
	struct ethhdr eth;
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
		return TC_ACT_OK;
	if (eth.h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* Parse IP header */
	struct iphdr iph;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0)
		return TC_ACT_OK;
	if (iph.protocol != IPPROTO_UDP)
		return TC_ACT_OK;
	if (iph.daddr != cfg->coredns_ip)
		return TC_ACT_OK;
	if (iph.ihl < 5 || iph.ihl > 15)
		return TC_ACT_OK;
	/* Reject IP fragments. We need the UDP+DNS headers in this packet,
	 * and rewriting only the first fragment would leave later fragments
	 * unmodified, breaking reassembly. */
	if (iph.frag_off & bpf_htons(0x3FFF))
		return TC_ACT_OK;

	/* Parse UDP header */
	__u32 ip_hdr_len = (__u32)iph.ihl * 4;
	__u32 udp_offset = ETH_HLEN + ip_hdr_len;
	struct udphdr udp;
	if (bpf_skb_load_bytes(skb, udp_offset, &udp, sizeof(udp)) < 0)
		return TC_ACT_OK;
	if (udp.dest != cfg->dns_port)
		return TC_ACT_OK;

	increment_metric(METRIC_DNS_QUERIES);

	/* Parse DNS header (12 bytes) */
	__u32 dns_offset = udp_offset + sizeof(struct udphdr);
	__u8 dns_hdr[12];
	if (bpf_skb_load_bytes(skb, dns_offset, dns_hdr, 12) < 0)
		return TC_ACT_OK;

	/* Check QR bit = 0 (query) */
	__u16 flags = ((__u16)dns_hdr[2] << 8) | dns_hdr[3];
	if (flags & 0x8000)
		return TC_ACT_OK;

	/* Check QDCOUNT == 1. Multi-question packets are ambiguous (a later
	 * question could be cluster-local) so we passthrough to CoreDNS. */
	__u16 qdcount = ((__u16)dns_hdr[4] << 8) | dns_hdr[5];
	if (qdcount != 1) {
		increment_metric(METRIC_PARSE_ERROR);
		return TC_ACT_OK;
	}

	/* Extract txid (DNS hdr bytes 0..1) for conntrack key. Stored in
	 * network byte order since both ingress and egress read it the same
	 * way and only equality is tested. */
	__u16 txid = ((__u16)dns_hdr[0] << 8) | dns_hdr[1];

	/* Get scratch buffer */
	__u32 scratch_key = 0;
	struct scratch_buf *scratch = bpf_map_lookup_elem(&scratch_map, &scratch_key);
	if (!scratch)
		return TC_ACT_OK;

	/* Load QNAME into scratch buffer.
	 * Use unsigned skb->len comparison to keep the verifier happy. */
	__u32 qname_offset = dns_offset + 12;
	if (qname_offset > skb->len)
		return TC_ACT_OK;
	__u32 remaining = skb->len - qname_offset;
	if (remaining < 1)
		return TC_ACT_OK;
	if (remaining > MAX_DNS_NAME_LEN)
		remaining = MAX_DNS_NAME_LEN;
	/* Explicit AND mask gives the verifier a static upper bound. */
	asm volatile("" : "+r"(remaining));
	remaining &= MAX_DNS_NAME_LEN - 1;
	if (remaining == 0)
		remaining = MAX_DNS_NAME_LEN;
	if (bpf_skb_load_bytes(skb, qname_offset, scratch->qname, remaining) < 0)
		return TC_ACT_OK;

	/* Walk labels to find boundaries */
	__u32 label_offsets[MAX_LABELS];
	__u32 num_labels = 0;
	__u32 pos = 0;

	for (int i = 0; i < MAX_LABELS; i++) {
		if (pos >= remaining || pos >= MAX_DNS_NAME_LEN)
			break;
		__u32 read_idx = pos;
		asm volatile("" : "+r"(read_idx));
		read_idx &= MAX_DNS_NAME_LEN - 1;
		__u8 label_len = scratch->qname[read_idx];

		if (label_len == 0)
			break;
		if (label_len >= 0xC0) {
			increment_metric(METRIC_PARSE_ERROR);
			return TC_ACT_OK;
		}
		if (label_len > 63) {
			increment_metric(METRIC_PARSE_ERROR);
			return TC_ACT_OK;
		}

		label_offsets[num_labels] = pos;
		num_labels++;
		pos += 1 + (__u32)label_len;
	}

	if (num_labels == 0)
		return TC_ACT_OK;

	__u32 qname_total_len = pos + 1;
	if (qname_total_len > MAX_DNS_NAME_LEN || qname_total_len > remaining)
		return TC_ACT_OK;

	/* MVP limitation: case-insensitive matching is NOT performed in
	 * the BPF program. We rely on resolvers emitting lowercase QNAMEs.
	 * Both glibc and musl resolvers, the AWS SDK clients, and CoreDNS
	 * all emit lowercase. Mixed-case queries (including from servers
	 * using DNS 0x20 randomization, RFC 7873) miss the suffix rules
	 * and fall through to CoreDNS — functionally correct, just no
	 * optimization. We tried lowercase loops; the BPF verifier
	 * exhausts its 1M instruction limit due to state-explosion in the
	 * unrolled loop interaction with the suffix matching loop. See
	 * docs/design.md §9.1. */

	/* Suffix matching: try each label boundary */
	for (int i = 0; i < MAX_LABELS; i++) {
		if ((__u32)i >= num_labels)
			break;

		__u32 idx = (__u32)i;
		asm volatile("" : "+r"(idx));
		if (idx >= MAX_LABELS)
			break;
		__u32 suffix_start = label_offsets[idx];
		__u32 suffix_len = qname_total_len - suffix_start;
		if (suffix_len == 0 || suffix_len > MAX_DNS_NAME_LEN)
			break;

		/* Copy suffix into lookup buffer.
		 *
		 * We need to copy `suffix_len` bytes starting at `suffix_start`
		 * inside `scratch->qname` to the start of `scratch->lookup`.
		 * The verifier struggles with `qname[suffix_start + j]` because
		 * `suffix_start` is data-dependent. Solution: a fully unrolled
		 * inner loop of MAX_DNS_NAME_LEN iterations where each iteration
		 * uses a constant offset, and we conditionally copy when that
		 * offset falls inside the suffix range.
		 *
		 * No separate memset needed: the loop writes every index in
		 * [0, MAX_DNS_NAME_LEN) — the suffix bytes for k < sl and 0 for
		 * k >= sl — so the whole lookup buffer is fully defined here.
		 */
		__u32 ss = suffix_start & (MAX_DNS_NAME_LEN - 1);
		/* Cap suffix_len at MAX_DNS_NAME_LEN. We can't mask with
		 * (MAX_DNS_NAME_LEN-1) because that would turn a length of
		 * exactly MAX_DNS_NAME_LEN into 0 and break exact-limit
		 * matches. The earlier `suffix_len > MAX_DNS_NAME_LEN` check
		 * guarantees suffix_len <= MAX_DNS_NAME_LEN here. */
		__u32 sl = suffix_len;
		if (sl > MAX_DNS_NAME_LEN)
			sl = MAX_DNS_NAME_LEN;
		#pragma unroll
		for (__u32 k = 0; k < MAX_DNS_NAME_LEN; k++) {
			__u32 si = (ss + k) & (MAX_DNS_NAME_LEN - 1);
			__u8 b = (k < sl) ? scratch->qname[si] : 0;
			scratch->lookup[k] = b;
		}

		/* Hash map lookup */
		struct suffix_key *key = (struct suffix_key *)scratch->lookup;
		struct suffix_value *val = bpf_map_lookup_elem(&suffix_rules, key);
		if (val && val->action == ACTION_HOST_RESOLVE)
			goto do_dnat;
	}

	/* No match — passthrough to CoreDNS */
	increment_metric(METRIC_SUFFIX_NO_MATCH);
	return TC_ACT_OK;

do_dnat:
	increment_metric(METRIC_SUFFIX_MATCH);

	/* Create conntrack entry */
	struct conntrack_key ct_key = {};
	ct_key.pod_ip = iph.saddr;
	ct_key.pod_port = udp.source;
	ct_key.txid = txid;

	struct conntrack_value ct_val = {};
	ct_val.coredns_ip = cfg->coredns_ip;
	ct_val.timestamp_ns = bpf_ktime_get_ns();

	/* If conntrack insertion fails (e.g. memory pressure), do NOT DNAT —
	 * egress would otherwise miss the entry and the response would reach
	 * the pod with src=host_resolver_ip, which the client's resolver
	 * discards. Falling back to CoreDNS is correct and safe. */
	if (bpf_map_update_elem(&conntrack_map, &ct_key, &ct_val, BPF_ANY) < 0)
		return TC_ACT_OK;

	/* DNAT: rewrite destination IP from CoreDNS to host resolver */
	__u32 old_daddr = iph.daddr;
	__u32 new_daddr = cfg->host_resolver_ip;

	/* IP daddr is at offset ETH_HLEN + 16 */
	bpf_skb_store_bytes(skb, ETH_HLEN + 16, &new_daddr, 4, 0);

	/* Fix IP header checksum (offset ETH_HLEN + 10) */
	bpf_l3_csum_replace(skb, ETH_HLEN + 10, old_daddr, new_daddr, 4);

	/* Fix UDP checksum (pseudo-header includes dst IP) */
	bpf_l4_csum_replace(skb, udp_offset + 6, old_daddr, new_daddr,
			    BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4);

	return TC_ACT_OK;
}

/* --- Egress: conntrack SNAT --- */

SEC("tc/egress")
int dns_gateway_egress(struct __sk_buff *skb)
{
	increment_metric(METRIC_EGRESS_TOTAL);

	__u32 cfg_key = 0;
	struct gateway_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
	if (!cfg)
		return TC_ACT_OK;

	/* NOTE: egress intentionally does NOT check cfg->bypass. In-flight
	 * queries already DNAT'd before bypass flipped will produce responses
	 * from the VPC resolver, and those responses must still be SNAT'd
	 * back to CoreDNS so the pod never sees src=host_resolver_ip. */

	/* Parse Ethernet header */
	struct ethhdr eth;
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
		return TC_ACT_OK;
	if (eth.h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* Parse IP header */
	struct iphdr iph;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0)
		return TC_ACT_OK;
	if (iph.protocol != IPPROTO_UDP)
		return TC_ACT_OK;
	if (iph.saddr != cfg->host_resolver_ip)
		return TC_ACT_OK;
	if (iph.ihl < 5 || iph.ihl > 15)
		return TC_ACT_OK;
	/* Reject IP fragments — only the first fragment carries the UDP+DNS
	 * headers we need. Rewriting only that one would leave later
	 * fragments with src=host_resolver_ip and break reassembly. */
	if (iph.frag_off & bpf_htons(0x3FFF))
		return TC_ACT_OK;

	/* Parse UDP header */
	__u32 ip_hdr_len = (__u32)iph.ihl * 4;
	__u32 udp_offset = ETH_HLEN + ip_hdr_len;
	struct udphdr udp;
	if (bpf_skb_load_bytes(skb, udp_offset, &udp, sizeof(udp)) < 0)
		return TC_ACT_OK;

	if (udp.source != cfg->dns_port)
		return TC_ACT_OK;

	/* Load DNS header and extract txid for conntrack lookup */
	__u32 dns_offset = udp_offset + sizeof(struct udphdr);
	__u8 dns_hdr[12];
	if (bpf_skb_load_bytes(skb, dns_offset, dns_hdr, 12) < 0)
		return TC_ACT_OK;
	__u16 txid = ((__u16)dns_hdr[0] << 8) | dns_hdr[1];

	/* Conntrack lookup */
	struct conntrack_key ct_key = {};
	ct_key.pod_ip = iph.daddr;
	ct_key.pod_port = udp.dest;
	ct_key.txid = txid;

	struct conntrack_value *ct_val = bpf_map_lookup_elem(&conntrack_map, &ct_key);
	if (!ct_val) {
		increment_metric(METRIC_EGRESS_CONNTRACK_MISS);
		return TC_ACT_OK;
	}

	/* TTL check: stale entries (e.g. orphaned by client timeout) might
	 * coincidentally match a later unrelated direct VPC-DNS response with
	 * the same {pod_ip, pod_port, txid}. Drop the stale entry and treat
	 * this packet as not ours. */
	__u64 now = bpf_ktime_get_ns();
	if (now - ct_val->timestamp_ns > CONNTRACK_TTL_NS) {
		bpf_map_delete_elem(&conntrack_map, &ct_key);
		increment_metric(METRIC_EGRESS_CONNTRACK_MISS);
		return TC_ACT_OK;
	}

	/* SNAT: rewrite source IP from host resolver to CoreDNS */
	__u32 old_saddr = iph.saddr;
	__u32 new_saddr = ct_val->coredns_ip;

	/* IP saddr is at offset ETH_HLEN + 12 */
	bpf_skb_store_bytes(skb, ETH_HLEN + 12, &new_saddr, 4, 0);

	/* Fix IP header checksum */
	bpf_l3_csum_replace(skb, ETH_HLEN + 10, old_saddr, new_saddr, 4);

	/* Fix UDP checksum */
	bpf_l4_csum_replace(skb, udp_offset + 6, old_saddr, new_saddr,
			    BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4);

	/* Delete conntrack entry */
	bpf_map_delete_elem(&conntrack_map, &ct_key);

	increment_metric(METRIC_EGRESS_SNAT);
	return TC_ACT_OK;
}
