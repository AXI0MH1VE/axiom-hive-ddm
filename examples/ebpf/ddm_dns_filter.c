// SPDX-License-Identifier: GPL-2.0
/*
 * Axiom Hive DDM - DNS Defense Module
 * eBPF DNS Filter Implementation
 *
 * This program intercepts DNS queries at the TC (Traffic Control) egress layer
 * and enforces the Closed Manifold policy with entropy filtering.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_PORT 53
#define MAX_QNAME_LEN 253
#define SCALE 65536  // 2^16 for fixed-point arithmetic

/* DNS Header Structure */
struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
} __attribute__((packed));

/* Parsed DNS Query */
struct dns_query {
    char qname[MAX_QNAME_LEN];
    __u16 qname_len;
    __u16 qtype;
    __u16 qclass;
};

/* Manifold Entry */
struct manifold_entry {
    __u8 type;  // 0 = exact, 1 = wildcard
    __u32 entropy_max_scaled;
    __u64 valid_until;
    __u8 flags;
};

/* Violation Event for Logging */
struct violation_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char domain[MAX_QNAME_LEN];
    char reason[32];
    __u32 entropy_scaled;
};

/* Statistics */
struct stats {
    __u64 packets_total;
    __u64 packets_allowed;
    __u64 packets_dropped;
    __u64 not_in_manifold;
    __u64 entropy_exceeded;
    __u64 expired;
};

/* eBPF Maps */

// Manifold database (exact matches)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, char[MAX_QNAME_LEN]);
    __type(value, struct manifold_entry);
} manifold_exact SEC(".maps");

// Manifold wildcards
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, char[MAX_QNAME_LEN]);
    __type(value, struct manifold_entry);
} manifold_wildcards SEC(".maps");

// Event ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} statistics SEC(".maps");

/* Helper Functions */

static __always_inline void update_stats(__u64 *counter) {
    __u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&statistics, &key);
    if (s) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline void log_violation(
    const char *domain,
    __u16 domain_len,
    const char *reason,
    __u32 entropy
) {
    struct violation_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->entropy_scaled = entropy;
    
    // Copy domain (bounded)
    __u16 copy_len = domain_len < MAX_QNAME_LEN ? domain_len : MAX_QNAME_LEN - 1;
    __builtin_memcpy(event->domain, domain, copy_len);
    event->domain[copy_len] = '\0';
    
    // Copy reason
    __builtin_memcpy(event->reason, reason, sizeof(event->reason));
    
    bpf_ringbuf_submit(event, 0);
}

/* Fixed-Point Entropy Computation */
static __always_inline __u32 compute_entropy_scaled(const char *str, __u16 len) {
    __u32 freq[256] = {0};
    __u32 entropy_scaled = 0;
    
    if (len == 0 || len > MAX_QNAME_LEN)
        return 0;
    
    // Count character frequencies
    #pragma unroll
    for (int i = 0; i < MAX_QNAME_LEN; i++) {
        if (i >= len)
            break;
        __u8 c = (__u8)str[i];
        if (c < 256)
            freq[c]++;
    }
    
    // Compute entropy using integer approximation
    // H = -Σ p(x) * log2(p(x))
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0)
            continue;
        
        // p(x) = freq[x] / len (scaled)
        __u32 p_scaled = (freq[i] * SCALE) / len;
        
        // Approximate log2(p) using bit position
        // This is a simplified approximation
        __u32 log_approx = 0;
        __u32 temp = p_scaled;
        
        // Count leading zeros to get log2
        for (int bit = 15; bit >= 0; bit--) {
            if (temp & (1 << bit)) {
                log_approx = bit;
                break;
            }
        }
        
        // H += p * log2(p) (all scaled)
        entropy_scaled += (p_scaled * log_approx) / SCALE;
    }
    
    return entropy_scaled;
}

/* Manifold Lookup */
static __always_inline struct manifold_entry *
lookup_manifold(char *domain, __u16 len) {
    struct manifold_entry *entry;
    
    // Try exact match first
    entry = bpf_map_lookup_elem(&manifold_exact, domain);
    if (entry)
        return entry;
    
    // Try wildcard matches
    // For simplicity, this example only checks a few common patterns
    // A production implementation would need more sophisticated matching
    
    char pattern[MAX_QNAME_LEN];
    __builtin_memset(pattern, 0, sizeof(pattern));
    
    // Find first dot and try wildcard from there
    #pragma unroll
    for (int i = 0; i < MAX_QNAME_LEN && i < len; i++) {
        if (domain[i] == '.') {
            // Construct *.suffix pattern
            pattern[0] = '*';
            __builtin_memcpy(pattern + 1, domain + i, len - i);
            
            entry = bpf_map_lookup_elem(&manifold_wildcards, pattern);
            if (entry)
                return entry;
            
            break;
        }
    }
    
    return NULL;
}

/* DNS Packet Parsing */
static __always_inline int parse_dns_query(
    struct __sk_buff *skb,
    struct dns_query *query
) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;
    
    // IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    if (ip->protocol != IPPROTO_UDP)
        return -1;
    
    // UDP header
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return -1;
    
    if (bpf_ntohs(udp->dest) != DNS_PORT)
        return -1;
    
    // DNS header
    struct dnshdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return -1;
    
    if (bpf_ntohs(dns->qdcount) == 0)
        return -1;
    
    // Parse QNAME
    __u8 *qname_ptr = (__u8 *)(dns + 1);
    __u16 offset = 0;
    
    #pragma unroll
    for (int i = 0; i < 32; i++) {  // Max 32 labels
        if ((void *)(qname_ptr + 1) > data_end)
            return -1;
        
        __u8 label_len = *qname_ptr;
        
        if (label_len == 0) {
            query->qname[offset] = '\0';
            query->qname_len = offset;
            return 0;
        }
        
        if (label_len > 63)
            return -1;
        
        qname_ptr++;
        
        // Copy label
        #pragma unroll
        for (int j = 0; j < 63; j++) {
            if (j >= label_len)
                break;
            
            if ((void *)(qname_ptr + 1) > data_end)
                return -1;
            
            if (offset >= MAX_QNAME_LEN - 1)
                return -1;
            
            query->qname[offset++] = *qname_ptr++;
        }
        
        if (offset < MAX_QNAME_LEN - 1)
            query->qname[offset++] = '.';
    }
    
    return -1;
}

/* Main eBPF Program */
SEC("tc")
int ddm_dns_filter(struct __sk_buff *skb) {
    struct dns_query query;
    __u32 key = 0;
    struct stats *s;
    
    // Update packet counter
    s = bpf_map_lookup_elem(&statistics, &key);
    if (s)
        __sync_fetch_and_add(&s->packets_total, 1);
    
    // Parse DNS packet
    if (parse_dns_query(skb, &query) < 0) {
        // Not a DNS packet or parse error
        return TC_ACT_OK;
    }
    
    // Lookup in manifold
    struct manifold_entry *entry = lookup_manifold(query.qname, query.qname_len);
    
    if (!entry) {
        // Not in manifold -> DROP
        log_violation(query.qname, query.qname_len, "not_in_manifold", 0);
        
        if (s)
            __sync_fetch_and_add(&s->not_in_manifold, 1);
        
        if (s)
            __sync_fetch_and_add(&s->packets_dropped, 1);
        
        return TC_ACT_SHOT;
    }
    
    // Check temporal validity
    if (entry->valid_until > 0) {
        __u64 now = bpf_ktime_get_ns() / 1000000000;
        if (now > entry->valid_until) {
            log_violation(query.qname, query.qname_len, "expired", 0);
            
            if (s)
                __sync_fetch_and_add(&s->expired, 1);
            
            if (s)
                __sync_fetch_and_add(&s->packets_dropped, 1);
            
            return TC_ACT_SHOT;
        }
    }
    
    // Check entropy bound (if specified)
    if (entry->entropy_max_scaled > 0) {
        __u32 observed_entropy = compute_entropy_scaled(query.qname, query.qname_len);
        
        if (observed_entropy > entry->entropy_max_scaled) {
            log_violation(query.qname, query.qname_len, "entropy_exceeded", observed_entropy);
            
            if (s)
                __sync_fetch_and_add(&s->entropy_exceeded, 1);
            
            if (s)
                __sync_fetch_and_add(&s->packets_dropped, 1);
            
            return TC_ACT_SHOT;
        }
    }
    
    // All checks passed -> ALLOW
    if (s)
        __sync_fetch_and_add(&s->packets_allowed, 1);
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
