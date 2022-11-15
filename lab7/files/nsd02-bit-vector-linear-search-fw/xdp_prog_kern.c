/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>
#include <linux/udp.h>


#define DEBUG 1
#define PRINT_RULE_ID 1
 
#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);		\
})

#define FW_RULE_NUM 32
#define FW_BITVECTOR_LEN 4

struct v4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct fw_key {
  __be32 saddr;
  __be32 daddr;
  __u16 sport;
  __u16 dport;
  __u8 proto;
};

struct bpf_map_def SEC("maps") saddr_db = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct v4_lpm_key),
	.value_size = FW_BITVECTOR_LEN,
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = FW_RULE_NUM,
};

struct bpf_map_def SEC("maps") daddr_db = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct v4_lpm_key),
	.value_size = FW_BITVECTOR_LEN,
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = FW_RULE_NUM,
};

struct bpf_map_def SEC("maps") proto_db = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u8),
	.value_size = FW_BITVECTOR_LEN,
	.max_entries = FW_RULE_NUM,
};

struct bpf_map_def SEC("maps") sport_db = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u16),
	.value_size = FW_BITVECTOR_LEN,
	.max_entries = FW_RULE_NUM,
};

struct bpf_map_def SEC("maps") dport_db = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u16),
	.value_size = FW_BITVECTOR_LEN,
	.max_entries = FW_RULE_NUM,
};

SEC("xdp_fw")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct fw_key key;
	struct iphdr *ip = NULL;
	struct udphdr *l4 = NULL;
	__u32 *bitvector = NULL;
        __u32 res_bitvector = 0xffffffff; 	
	struct v4_lpm_key lpm_key;
	__u32 offset = 0;
	__u16 port_default=0;
	__u8 proto_default = 0;
	
	struct ethhdr *eth =(struct ethhdr *)data;
	offset = sizeof(struct ethhdr);
	if (data + offset > data_end) {
		return XDP_DROP;
	}

	if (eth->h_proto == __constant_htons(ETH_P_IP)) {
		ip = (struct iphdr *)(data + offset);
		offset += sizeof(struct iphdr); 
		if (data + offset > data_end) {
			return XDP_DROP;
		}

		if (ip->ihl != 5) {
			return XDP_DROP;
		}

		key.saddr = ip->saddr;
		key.daddr = ip->daddr;
		key.proto = ip->protocol;
		
		l4 = (struct udphdr *)(data + offset);
		if (ip->protocol == IPPROTO_TCP) {
			offset += sizeof(struct tcphdr);
		}
		else if (ip->protocol == IPPROTO_UDP) {
			offset += sizeof(struct udphdr);
		}
		else {
			return XDP_PASS;
		}
		
		if (data + offset > data_end) {
			return XDP_DROP;
		}

		key.sport = l4->source;
		key.dport = l4->dest;

	}
	else {
		return XDP_PASS;
	}
	
	//look up in source prefix DB	
    	lpm_key.prefixlen = 32;
        lpm_key.addr = (__be32)key.saddr;
	bitvector = bpf_map_lookup_elem(&saddr_db, &lpm_key);
	if (bitvector) {
		res_bitvector = res_bitvector & *bitvector; 
#if DEBUG
		bpf_printk("saddr lookup %u %u", *bitvector, res_bitvector);
#endif
	} else {
#if DEBUG
		bpf_printk("no saddr in db. DROP\n");
#endif
		return XDP_DROP;
	}

	//look up in destination prefix DB	
    	lpm_key.prefixlen = 32;
        lpm_key.addr = (__be32)key.daddr;
	bitvector = bpf_map_lookup_elem(&daddr_db, &lpm_key);
	if (bitvector) {
		res_bitvector = res_bitvector & *bitvector; 

#if DEBUG
		bpf_printk("daddr lookup %u %u", *bitvector, res_bitvector);
#endif
	} else {
#if DEBUG
		bpf_printk("no daddr in db. DROP\n");
#endif
		return XDP_DROP;
	}

	//lookup in source port DB
	bitvector = bpf_map_lookup_elem(&sport_db, &key.sport);
	if (!bitvector) {
		bitvector = bpf_map_lookup_elem(&sport_db, &port_default);
	}
	if (bitvector) {
		res_bitvector = res_bitvector & *bitvector; 
#if DEBUG
		bpf_printk("sport lookup %u %u", *bitvector, res_bitvector);
#endif
	} else {
#if DEBUG
		bpf_printk("no sport in db. DROP\n");
#endif
		return XDP_DROP;
	}

	//lookup in destination port DB
	bitvector = bpf_map_lookup_elem(&dport_db, &key.dport);
	if (!bitvector) {
		bitvector = bpf_map_lookup_elem(&dport_db, &port_default);
	}
	if (bitvector) {
		res_bitvector = res_bitvector & *bitvector; 
#if DEBUG
		bpf_printk("dport lookup %u %u", *bitvector, res_bitvector);
#endif
	} else {
#if DEBUG
		bpf_printk("no dport in db. DROP\n");
#endif
		return XDP_DROP;
	}

	//lookup in protocol DB
	bitvector = bpf_map_lookup_elem(&proto_db, &key.proto);
	if (!bitvector) {
		bitvector = bpf_map_lookup_elem(&proto_db, &proto_default);
	}
	if (bitvector) {
		res_bitvector = res_bitvector & *bitvector; 
#if DEBUG
		bpf_printk("proto lookup %u %u", *bitvector, res_bitvector);
#endif

	} else {
#if DEBUG
		bpf_printk("no proto in cb. DROP\n");
#endif
		return XDP_DROP;
	}

	if (res_bitvector == 0) { 
#if DEBUG
		bpf_printk("NULL rule bitvector interception. DROP\n");
#endif
		return XDP_DROP;
	}
#ifdef PRINT_RULE_ID
{
	int pos=0, k=0, j=0;
	if (res_bitvector) {
		__u8 *p = (__u8 *) &res_bitvector;
        	for (k=0; k<4; k++) {
			if (p[k] != 0) {
				for (j=0; j<8; j++) {
					if ((0xff & (p[k]>>j))==1) {
						pos = k*8 + 8-j-1;
						break;
					}
				}
				if (pos) break;
			} 
		}       

		bpf_printk("res bitvector: %d matched rule: %d\n", res_bitvector, pos);
	} 
	else {
		bpf_printk("no rule matched\n");
	}
}
#endif
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
