/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
//#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);		\
})


/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)     ((void) __sync_fetch_and_add(ptr, val))
#endif


#define RULE_NUM 32

struct v4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct bpf_map_def SEC("maps") saddr_db = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct v4_lpm_key),
	.value_size = sizeof(__u8),
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = RULE_NUM,
};

struct bpf_map_def SEC("maps") daddr_db = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__be32),
	.value_size = sizeof(__u8),
	.max_entries = RULE_NUM,
};

struct bpf_map_def SEC("maps") stats_db = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 3,
};


enum stats_enum {
	STATS_PASS_KEY = 0,
	STATS_DROP_KEY,
	STATS_TX_KEY	
};

SEC("xdp_nsd_test")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth =(struct ethhdr *)data;
	struct iphdr *ip = NULL;
	__u32 offset = 0;
	__be32 daddr_key;
	struct v4_lpm_key saddr_key;
	int stats_key; 
	int xdp_verdict;
	__u8 *val;
	__u32 *stats_value;
	
	offset = sizeof(struct ethhdr);
	if (data + offset > data_end) {
		return XDP_ABORTED;
	}

	if (eth->h_proto == __constant_htons(ETH_P_IP)) {
		ip = (struct iphdr *)(data + offset);
		offset += sizeof(struct iphdr); 
		if (data + offset > data_end) {
			return XDP_ABORTED;
		}

		saddr_key.prefixlen = 32;
		saddr_key.addr = ip->saddr;
		daddr_key = ip->daddr;
	}
	else {
		stats_key = STATS_PASS_KEY;	
		xdp_verdict = XDP_PASS;
		goto udpate_stats_and_return;
	}
	
	//look up in source prefix DB. XXX LPM MATCH	
	val = (__u8 *)bpf_map_lookup_elem(&saddr_db, &saddr_key);
	if (val) {
		stats_key = STATS_TX_KEY;	
		xdp_verdict = XDP_TX;
		goto udpate_stats_and_return;
	} 

	//look up in destination prefix DB. XXX EXACT HASH MATCH 	
	val = (__u8 *)bpf_map_lookup_elem(&daddr_db, &daddr_key);
	if (val) {
		stats_key = STATS_TX_KEY;	
		xdp_verdict = XDP_TX;
		goto udpate_stats_and_return;
	} 
	else {
		stats_key = STATS_DROP_KEY;	
		xdp_verdict = XDP_DROP;
	}
		
udpate_stats_and_return:
	stats_value = bpf_map_lookup_elem(&stats_db, &stats_key);
	if (!stats_value) {
		return XDP_ABORTED;
	}
	lock_xadd(stats_value, 1);
	return xdp_verdict;
}


char _license[] SEC("license") = "GPL";
