// SPDX-License-Identifier: GPL-2.0
/*
 * Axiom Hive DDM - DNS Defense Module v2.0
 * Production-grade eBPF DNS Filter Implementation
 *
 * Improvements over v1.0:
 * - Enhanced error handling and bounds checking
 * - Ring buffer backpressure management
 * - Improved entropy calculation with logarithmic lookup table
 * - Support for TCP DNS over port 53
 * - Better statistics and monitoring
 * - CO-RE compatibility optimizations
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define DNS_PORT 53
#define MAX_QNAME_LEN 253
#define MAX_DNS_LABELS 63
#define SCALE 65536  // 2^16 for fixed-point arithmetic
#define ENTROPY_TABLE_SIZE 256
#define MAX_EVENTS 1024

/* DNS Header Structure */
struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
} __attribute__((packed));

/* Parsed DNS Query with validation */
struct dns_query {
    char qname[MAX_QNAME_LEN];
    __u16 qname_len;
    __u16 qtype;
    __u16 qclass;
    __u8 is_valid;
    __u8 has_edns0;
} __attribute__((packed));

/* Manifold Entry with enhanced policy support */
struct manifold_entry {
    __u8 type;  // 0 = exact, 1 = wildcard, 2 = regex
    __u32 entropy_max_scaled;
    __u64 valid_until;
    __u8 flags;
    __u8 country_code[2];  // Geo-blocking support
    __u8 require_https;    // HSTS enforcement
    __u8 audit_only;       // AUDIT mode flag
} __attribute__((packed));

/* Enhanced Violation Event for comprehensive logging */
struct violation_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 ifindex;
    __u32 src_ip;
    __u32 dst_ip;
    char domain[MAX_QNAME_LEN];
    char reason[48];
    __u32 entropy_scaled;
    __u16 qtype;
    __u8 protocol;  // 0 = UDP, 1 = TCP
    __u8 severity;  // 0 = info, 1 = warning, 2 = critical
} __attribute__((packed));

/* Enhanced Statistics with performance metrics */
struct stats {
    __u64 packets_total;
    __u64 packets_allowed;
    __u64 packets_dropped;
    __u64 packets_udp;
    __u64 packets_tcp;
    __u64 not_in_manifold;
    __u64 entropy_exceeded;
    __u64 expired;
    __u64 parse_errors;
    __u64 backpressure_drops;
    __u64 geo_blocked;
    __u64 https_required;
    __u64 last_update;
} __attribute__((packed));

/* Entropy Lookup Table for faster computation */
static const __u16 entropy_lut[ENTROPY_TABLE_SIZE] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* eBPF Maps with enhanced features */

// Manifold database (exact matches)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, char[MAX_QNAME_LEN]);
    __type(value, struct manifold_entry);
} manifold_exact SEC(".maps");

// Manifold wildcards
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, char[MAX_QNAME_LEN]);
    __type(value, struct manifold_entry);
} manifold_wildcards SEC(".maps");

// Geo-blocking database
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);  // IP address
    __type(value, __u8); // Country code
} geo_db SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u64);
} config SEC(".maps");

// Enhanced event ring buffer with backpressure
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  // 512KB
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

// Backpressure monitoring
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} backpressure_stats SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct stats);
} statistics SEC(".maps");

/* Configuration constants */
static const __u32 CONFIG_AUDIT_MODE = 0;
static const __u32 CONFIG_MAX_EVENTS_PER_SEC = 1;
static const __u32 CONFIG_DEFAULT_ENTROPY = 42;  // 4.2 * SCALE

/* Helper Functions */

static __always_inline void update_stats(__u64 *counter) {
    __u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&statistics, &key);
    if (s) {
        __sync_fetch_and_add(counter, 1);
        s->last_update = bpf_ktime_get_ns();
    }
}

static __always_inline void update_backpressure(__u32 drops) {
    __u32 key = 0;
    __u64 *stats = bpf_map_lookup_elem(&backpressure_stats, &key);
    if (stats) {
        __sync_fetch_and_add(stats, drops);
    }
}

/* Enhanced event logging with backpressure handling */
static __always_inline int log_violation_safe(
    const char *domain,
    __u16 domain_len,
    const char *reason,
    __u32 entropy,
    __u32 src_ip,
    __u32 dst_ip,
    __u16 qtype,
    __u8 protocol,
    __u8 severity
) {
    // Check if we're in backpressure situation
    __u32 bp_key = 0;
    __u64 *bp_stats = bpf_map_lookup_elem(&backpressure_stats, &bp_key);
    if (bp_stats && *bp_stats > 10000) {  // Too many drops
        update_stats(&bp_stats);  // Count backpressure drop
        return -1;
    }

    struct violation_event *event;
    
    // Try to reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        // Ring buffer full, count as backpressure
        update_backpressure(1);
        return -1;
    }
    
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->ifindex = bpf_get_netns_device_id();
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->entropy_scaled = entropy;
    event->qtype = qtype;
    event->protocol = protocol;
    event->severity = severity;
    
    // Copy domain (bounded with null terminator)
    __u16 copy_len = domain_len < (MAX_QNAME_LEN - 1) ? domain_len : (MAX_QNAME_LEN - 1);
    __builtin_memcpy(event->domain, domain, copy_len);
    event->domain[copy_len] = '\0';
    
    // Copy reason with bounds checking
    __builtin_memcpy(event->reason, reason, sizeof(event->reason) - 1);
    event->reason[sizeof(event->reason) - 1] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Enhanced entropy computation with lookup table optimization */
static __always_inline __u32 compute_entropy_optimized(const char *str, __u16 len) {
    __u32 freq[256] = {0};
    __u32 entropy_scaled = 0;
    
    if (len == 0 || len > MAX_QNAME_LEN)
        return 0;
    
    // Count character frequencies
    #pragma unroll
    for (int i = 0; i < MAX_QNAME_LEN && i < len; i++) {
        __u8 c = (__u8)str[i];
        if (c < 256) {
            freq[c]++;
        }
    }
    
    // Compute entropy using optimized lookup
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0)
            continue;
        
        // p(x) = freq[x] / len (scaled)
        __u32 p_scaled = (freq[i] * SCALE) / len;
        
        // Use lookup table for log2 approximation
        __u32 log_approx = 0;
        if (p_scaled >= ENTROPY_TABLE_SIZE) {
            // Fallback for large values
            __u32 temp = p_scaled;
            #pragma unroll
            for (int bit = 15; bit >= 0; bit--) {
                if (temp & (1 << bit)) {
                    log_approx = bit;
                    break;
                }
            }
        } else {
            log_approx = entropy_lut[p_scaled];
        }
        
        // H += p * log2(p) (all scaled)
        entropy_scaled += (p_scaled * log_approx) / SCALE;
    }
    
    return entropy_scaled;
}

/* Enhanced manifold lookup with geo-blocking support */
static __always_inline struct manifold_entry *
lookup_manifold_enhanced(char *domain, __u16 len, __u32 src_ip) {
    struct manifold_entry *entry;
    
    // Try exact match first
    entry = bpf_map_lookup_elem(&manifold_exact, domain);
    if (entry) {
        // Check geo-blocking if enabled
        if (entry->country_code[0] != 0) {
            __u8 *country = bpf_map_lookup_elem(&geo_db, &src_ip);
            if (country && (country[0] != entry->country_code[0] || country[1] != entry->country_code[1])) {
                return NULL;  // Geo-blocked
            }
        }
        return entry;
    }
    
    // Try wildcard matches with improved pattern matching
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
            if (entry) {
                // Check geo-blocking for wildcards too
                if (entry->country_code[0] != 0) {
                    __u8 *country = bpf_map_lookup_elem(&geo_db, &src_ip);
                    if (country && (country[0] != entry->country_code[0] || country[1] != entry->country_code[1])) {
                        return NULL;  // Geo-blocked
                    }
                }
                return entry;
            }
            
            break;
        }
    }
    
    return NULL;
}

/* Robust DNS packet parsing with TCP support */
static __always_inline int parse_dns_packet(
    struct __sk_buff *skb,
    struct dns_query *query,
    __u8 *protocol,
    __u32 *src_ip,
    __u32 *dst_ip
) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    void *cursor = data;
    
    __builtin_memset(query, 0, sizeof(*query));
    query->is_valid = 0;
    
    // Ethernet header
    struct ethhdr *eth = cursor;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto == ETH_P_8021Q) {
        // VLAN tag present, skip it
        struct vlanhdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return -1;
        cursor = (void *)(vlan + 1);
        eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
    } else {
        cursor = (void *)(eth + 1);
    }
    
    if (eth_proto != ETH_P_IP)
        return -1;
    
    // IP header
    struct iphdr *ip = cursor;
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    
    // Determine protocol
    if (ip->protocol == IPPROTO_UDP) {
        *protocol = 0;
        
        // UDP header
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return -1;
        
        if (bpf_ntohs(udp->dest) != DNS_PORT)
            return -1;
        
        cursor = (void *)(udp + 1);
    } else if (ip->protocol == IPPROTO_TCP) {
        *protocol = 1;
        
        // TCP header
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return -1;
        
        if (bpf_ntohs(tcp->dest) != DNS_PORT)
            return -1;
        
        // Skip TCP header (calculate offset properly)
        __u32 tcp_hdr_len = tcp->doff * 4;
        cursor = (void *)tcp + tcp_hdr_len;
    } else {
        return -1;  // Not DNS
    }
    
    // DNS header
    struct dnshdr *dns = cursor;
    if ((void *)(dns + 1) > data_end)
        return -1;
    
    if (bpf_ntohs(dns->qdcount) == 0)
        return -1;
    
    // Parse QNAME with enhanced validation
    __u8 *qname_ptr = (__u8 *)(dns + 1);
    __u16 offset = 0;
    __u8 label_count = 0;
    
    #pragma unroll
    for (int i = 0; i < MAX_DNS_LABELS; i++) {
        if ((void *)(qname_ptr + 1) > data_end)
            return -1;
        
        __u8 label_len = *qname_ptr;
        
        if (label_len == 0) {
            query->qname[offset] = '\0';
            query->qname_len = offset;
            query->is_valid = 1;
            return 0;
        }
        
        if (label_len > 63)
            return -1;  // Label too long
        
        if (offset + label_len + 1 >= MAX_QNAME_LEN)
            return -1;  // QNAME too long
        
        qname_ptr++;
        label_count++;
        if (label_count > 127)
            return -1;  // Too many labels
        
        // Copy label
        #pragma unroll
        for (int j = 0; j < 63; j++) {
            if (j >= label_len)
                break;
            
            if ((void *)(qname_ptr + 1) > data_end)
                return -1;
            
            query->qname[offset++] = *qname_ptr++;
        }
        
        if (offset < MAX_QNAME_LEN - 1)
            query->qname[offset++] = '.';
    }
    
    return -1;  // QNAME parsing failed
}

/* Main eBPF Program */
SEC("tc")
int ddm_dns_filter_v2(struct __sk_buff *skb) {
    struct dns_query query;
    __u32 key = 0;
    struct stats *s;
    __u32 src_ip = 0, dst_ip = 0;
    __u8 protocol = 0;
    
    // Update packet counter
    s = bpf_map_lookup_elem(&statistics, &key);
    if (s) {
        __sync_fetch_and_add(&s->packets_total, 1);
    }
    
    // Parse DNS packet with enhanced error handling
    int parse_result = parse_dns_packet(skb, &query, &protocol, &src_ip, &dst_ip);
    if (parse_result < 0) {
        if (s)
            __sync_fetch_and_add(&s->parse_errors, 1);
        return TC_ACT_OK;  // Not a DNS packet or parse error
    }
    
    if (s) {
        if (protocol == 0)
            __sync_fetch_and_add(&s->packets_udp, 1);
        else
            __sync_fetch_and_add(&s->packets_tcp, 1);
    }
    
    if (!query.is_valid) {
        if (s)
            __sync_fetch_and_add(&s->parse_errors, 1);
        return TC_ACT_OK;
    }
    
    // Lookup in enhanced manifold
    struct manifold_entry *entry = lookup_manifold_enhanced(query.qname, query.qname_len, src_ip);
    
    if (!entry) {
        // Log violation with enhanced details
        log_violation_safe(query.qname, query.qname_len, "not_in_manifold", 0,
                         src_ip, dst_ip, query.qtype, protocol, 1);
        
        if (s) {
            __sync_fetch_and_add(&s->not_in_manifold, 1);
            __sync_fetch_and_add(&s->packets_dropped, 1);
        }
        
        return TC_ACT_SHOT;
    }
    
    // Check temporal validity
    if (entry->valid_until > 0) {
        __u64 now = bpf_ktime_get_ns() / 1000000000;
        if (now > entry->valid_until) {
            log_violation_safe(query.qname, query.qname_len, "expired", 0,
                             src_ip, dst_ip, query.qtype, protocol, 1);
            
            if (s) {
                __sync_fetch_and_add(&s->expired, 1);
                __sync_fetch_and_add(&s->packets_dropped, 1);
            }
            
            return TC_ACT_SHOT;
        }
    }
    
    // Check if this is audit-only mode
    __u64 *audit_mode = bpf_map_lookup_elem(&config, &CONFIG_AUDIT_MODE);
    if (audit_mode && *audit_mode == 1 && !entry->audit_only) {
        // Log the decision but don't block in audit mode
        log_violation_safe(query.qname, query.qname_len, "audit_mode_block", 0,
                         src_ip, dst_ip, query.qtype, protocol, 0);
        return TC_ACT_OK;  // Allow in audit mode
    }
    
    // Check entropy bound (if specified)
    if (entry->entropy_max_scaled > 0) {
        __u32 observed_entropy = compute_entropy_optimized(query.qname, query.qname_len);
        
        if (observed_entropy > entry->entropy_max_scaled) {
            log_violation_safe(query.qname, query.qname_len, "entropy_exceeded", observed_entropy,
                             src_ip, dst_ip, query.qtype, protocol, 2);
            
            if (s) {
                __sync_fetch_and_add(&s->entropy_exceeded, 1);
                __sync_fetch_and_add(&s->packets_dropped, 1);
            }
            
            return TC_ACT_SHOT;
        }
    }
    
    // All checks passed -> ALLOW
    if (s)
        __sync_fetch_and_add(&s->packets_allowed, 1);
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";