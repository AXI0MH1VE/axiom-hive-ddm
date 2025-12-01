# Linux eBPF Implementation

## Overview

The Linux implementation of the DDM leverages **eBPF (Extended Berkeley Packet Filter)** to provide kernel-level DNS interception and enforcement without requiring custom kernel modules. This approach offers strong safety guarantees, excellent performance, and simplified deployment.

## eBPF Fundamentals

### What is eBPF?

eBPF is a revolutionary technology that allows running sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules.

**Key Properties:**

- **Safety**: Programs are verified before execution
- **Performance**: JIT-compiled to native machine code
- **Flexibility**: Can attach to various kernel hooks
- **Portability**: Works across kernel versions (with BPF CO-RE)

### eBPF Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  User Space                             │
│  ┌──────────────────────────────────────────────────┐   │
│  │  DDM Control Plane                               │   │
│  │  - Manifold management                           │   │
│  │  - Policy updates                                │   │
│  │  - Monitoring and alerts                         │   │
│  └──────────────────┬───────────────────────────────┘   │
└─────────────────────┼───────────────────────────────────┘
                      │ bpf() syscall
┌─────────────────────▼───────────────────────────────────┐
│                  Kernel Space                           │
│  ┌──────────────────────────────────────────────────┐   │
│  │  eBPF Verifier                                   │   │
│  │  - Static analysis                               │   │
│  │  - Safety checks                                 │   │
│  └──────────────────┬───────────────────────────────┘   │
│                     │                                    │
│  ┌──────────────────▼───────────────────────────────┐   │
│  │  eBPF JIT Compiler                               │   │
│  │  - Translate to native code                      │   │
│  └──────────────────┬───────────────────────────────┘   │
│                     │                                    │
│  ┌──────────────────▼───────────────────────────────┐   │
│  │  eBPF Program (DDM Shim)                         │   │
│  │  - DNS packet interception                       │   │
│  │  - Entropy computation                           │   │
│  │  - Manifold lookup                               │   │
│  │  - Packet verdict (ALLOW/DROP)                   │   │
│  └──────────────────┬───────────────────────────────┘   │
│                     │                                    │
│  ┌──────────────────▼───────────────────────────────┐   │
│  │  eBPF Maps                                       │   │
│  │  - Manifold database                             │   │
│  │  - Statistics counters                           │   │
│  │  - Event ring buffer                             │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Hook Points

### Available Attachment Points

The DDM can attach to multiple points in the network stack:

| Hook Type | Layer | Use Case | Performance | Attribution |
|-----------|-------|----------|-------------|-------------|
| **XDP** | NIC driver | Raw packet filtering | Highest | Limited |
| **TC** | Qdisc | Pre-transmit filtering | High | Moderate |
| **Socket** | Socket layer | Process-aware filtering | Moderate | Excellent |
| **Kprobe** | Function entry | Deep inspection | Lower | Excellent |

### Recommended Architecture

**Multi-Layer Approach:**

```c
// Layer 1: TC Egress (Fast Path)
// Attach to network interface egress
// Drop obvious violations before they leave the host

SEC("tc/egress")
int ddm_tc_egress(struct __sk_buff *skb) {
    // Parse DNS packet
    // Quick manifold check
    // Drop if obviously unauthorized
    return TC_ACT_OK;  // or TC_ACT_SHOT to drop
}

// Layer 2: Socket Filter (Attribution Path)
// Attach to socket operations
// Full context: PID, UID, cgroup, container

SEC("socket")
int ddm_socket_filter(struct __sk_buff *skb) {
    // Extract process metadata
    // Detailed manifold + entropy check
    // Log violations with full attribution
    return 0;  // 0 = allow, non-zero = drop
}

// Layer 3: Kprobe (Deep Inspection)
// Attach to kernel DNS functions
// Fallback for encrypted DNS (DoH/DoT)

SEC("kprobe/udp_sendmsg")
int ddm_kprobe_udp_sendmsg(struct pt_regs *ctx) {
    // Inspect UDP payload
    // Detect DNS over non-standard ports
    return 0;
}
```

## DNS Packet Parsing

### UDP DNS Structure

```c
// Ethernet header (14 bytes)
struct ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __be16 h_proto;  // 0x0800 for IPv4, 0x86DD for IPv6
};

// IPv4 header (20 bytes minimum)
struct iphdr {
    __u8 ihl:4;
    __u8 version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;  // 17 for UDP
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

// UDP header (8 bytes)
struct udphdr {
    __be16 source;
    __be16 dest;  // 53 for DNS
    __be16 len;
    __sum16 check;
};

// DNS header (12 bytes)
struct dnshdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;  // Number of questions
    __be16 ancount;  // Number of answers
    __be16 nscount;  // Number of authority records
    __be16 arcount;  // Number of additional records
};
```

### Parsing Implementation

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_PORT 53
#define MAX_QNAME_LEN 253

struct dns_query {
    char qname[MAX_QNAME_LEN];
    __u16 qname_len;
    __u16 qtype;
    __u16 qclass;
};

// Parse DNS query from packet
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
    
    // IPv4 header
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
        return -1;  // No questions
    
    // Parse QNAME (domain name)
    __u8 *qname_ptr = (__u8 *)(dns + 1);
    __u16 offset = 0;
    
    #pragma unroll
    for (int i = 0; i < 64; i++) {  // Max 64 labels
        if ((void *)(qname_ptr + 1) > data_end)
            return -1;
        
        __u8 label_len = *qname_ptr;
        
        if (label_len == 0) {
            // End of QNAME
            query->qname[offset] = '\0';
            query->qname_len = offset;
            break;
        }
        
        if (label_len > 63)
            return -1;  // Invalid label length
        
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
        
        // Add dot separator
        if (offset < MAX_QNAME_LEN - 1)
            query->qname[offset++] = '.';
    }
    
    return 0;
}
```

## Manifold Lookup

### Data Structures

```c
// Manifold entry
struct manifold_entry {
    __u8 type;  // 0 = exact, 1 = wildcard
    __u32 entropy_max_scaled;  // Fixed-point entropy bound
    __u64 valid_until;  // Timestamp for temporal entries
    __u8 merkle_root[32];  // For proof verification
};

// Hash map for exact domains
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, char[MAX_QNAME_LEN]);
    __type(value, struct manifold_entry);
} manifold_exact SEC(".maps");

// Wildcard patterns (separate map for efficiency)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, char[MAX_QNAME_LEN]);
    __type(value, struct manifold_entry);
} manifold_wildcards SEC(".maps");
```

### Lookup Algorithm

```c
// Check if domain is in manifold
static __always_inline struct manifold_entry *
lookup_manifold(char *domain, __u16 len) {
    struct manifold_entry *entry;
    
    // 1. Try exact match
    entry = bpf_map_lookup_elem(&manifold_exact, domain);
    if (entry)
        return entry;
    
    // 2. Try wildcard matches
    // Extract base domain and check patterns
    // Example: "api.cdn.example.com" -> check "*.example.com", "*.cdn.example.com"
    
    char pattern[MAX_QNAME_LEN];
    __u16 dot_count = 0;
    
    // Count dots to determine subdomain levels
    #pragma unroll
    for (int i = 0; i < MAX_QNAME_LEN && i < len; i++) {
        if (domain[i] == '.')
            dot_count++;
    }
    
    // Try wildcard at each level
    #pragma unroll
    for (int level = 0; level < 5; level++) {  // Max 5 levels
        if (level > dot_count)
            break;
        
        // Construct wildcard pattern
        // This is simplified; real implementation needs careful string manipulation
        __builtin_memcpy(pattern, "*.", 2);
        // ... copy suffix after 'level' dots ...
        
        entry = bpf_map_lookup_elem(&manifold_wildcards, pattern);
        if (entry)
            return entry;
    }
    
    return NULL;  // Not found
}
```

## Entropy Computation

### Fixed-Point Shannon Entropy

```c
#define SCALE 65536  // 2^16 for fixed-point arithmetic
#define LOG2_TABLE_SIZE 256

// Precomputed log2 table (scaled)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, LOG2_TABLE_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} log2_table SEC(".maps");

// Compute Shannon entropy in fixed-point
static __always_inline __u32
compute_entropy_scaled(char *str, __u16 len) {
    __u32 freq[256] = {0};  // Character frequency
    __u32 entropy_scaled = 0;
    
    // Count character frequencies
    #pragma unroll
    for (int i = 0; i < MAX_QNAME_LEN && i < len; i++) {
        __u8 c = str[i];
        freq[c]++;
    }
    
    // Compute entropy: H = -Σ p(x) * log2(p(x))
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0)
            continue;
        
        // p(x) = freq[x] / len
        __u32 p_scaled = (freq[i] * SCALE) / len;
        
        // log2(p) via lookup table
        __u32 idx = (p_scaled * LOG2_TABLE_SIZE) / SCALE;
        if (idx >= LOG2_TABLE_SIZE)
            idx = LOG2_TABLE_SIZE - 1;
        
        __u32 *log_val = bpf_map_lookup_elem(&log2_table, &idx);
        if (!log_val)
            continue;
        
        // H += p * log2(p)
        entropy_scaled += (p_scaled * (*log_val)) / SCALE;
    }
    
    return entropy_scaled;
}
```

### Entropy Threshold Check

```c
// Check if entropy exceeds allowed bound
static __always_inline bool
entropy_violation(char *domain, __u16 len, struct manifold_entry *entry) {
    if (entry->entropy_max_scaled == 0)
        return false;  // No entropy limit
    
    __u32 observed_entropy = compute_entropy_scaled(domain, len);
    
    return observed_entropy > entry->entropy_max_scaled;
}
```

## Main eBPF Program

### Complete TC Egress Filter

```c
SEC("tc/egress")
int ddm_dns_filter(struct __sk_buff *skb) {
    struct dns_query query;
    
    // Parse DNS packet
    if (parse_dns_query(skb, &query) < 0)
        return TC_ACT_OK;  // Not DNS or parse error, allow
    
    // Lookup in manifold
    struct manifold_entry *entry = lookup_manifold(query.qname, query.qname_len);
    
    if (!entry) {
        // Not in manifold -> DROP
        log_violation(skb, &query, "not_in_manifold");
        return TC_ACT_SHOT;
    }
    
    // Check temporal validity
    __u64 now = bpf_ktime_get_ns() / 1000000000;  // Convert to seconds
    if (entry->valid_until > 0 && now > entry->valid_until) {
        log_violation(skb, &query, "expired");
        return TC_ACT_SHOT;
    }
    
    // Check entropy bound
    if (entropy_violation(query.qname, query.qname_len, entry)) {
        log_violation(skb, &query, "entropy_exceeded");
        return TC_ACT_SHOT;
    }
    
    // All checks passed -> ALLOW
    increment_counter("allowed");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

## Process Attribution

### Socket-Level Hooks

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);  // PID + TID
    __type(value, struct process_info);
} process_cache SEC(".maps");

struct process_info {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[16];  // Process name
    char cgroup[64];  // Container ID
};

SEC("socket")
int ddm_socket_filter(struct __sk_buff *skb) {
    struct dns_query query;
    
    if (parse_dns_query(skb, &query) < 0)
        return 0;
    
    // Get process context
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    struct process_info proc = {
        .pid = pid,
        .uid = uid,
    };
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));
    
    // Manifold check (same as above)
    struct manifold_entry *entry = lookup_manifold(query.qname, query.qname_len);
    
    if (!entry) {
        // Log with full attribution
        log_violation_with_process(skb, &query, &proc, "not_in_manifold");
        return 1;  // Drop
    }
    
    return 0;  // Allow
}
```

## Event Logging

### Ring Buffer for Events

```c
struct violation_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char domain[MAX_QNAME_LEN];
    char reason[32];
    __u32 entropy_scaled;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} events SEC(".maps");

static __always_inline void
log_violation(struct __sk_buff *skb, struct dns_query *query, const char *reason) {
    struct violation_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    __builtin_memcpy(event->domain, query->qname, query->qname_len);
    __builtin_memcpy(event->reason, reason, sizeof(event->reason));
    
    event->entropy_scaled = compute_entropy_scaled(query->qname, query->qname_len);
    
    bpf_ringbuf_submit(event, 0);
}
```

## User-Space Control Plane

### Loading and Managing eBPF Programs

```c
// Using libbpf
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, map_fd;
    
    // Load eBPF object file
    obj = bpf_object__open_file("ddm_dns_filter.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    // Load into kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }
    
    // Find program
    prog = bpf_object__find_program_by_name(obj, "ddm_dns_filter");
    prog_fd = bpf_program__fd(prog);
    
    // Attach to TC egress
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = if_nametoindex("eth0"),
        .attach_point = BPF_TC_EGRESS
    );
    
    bpf_tc_hook_create(&hook);
    
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = prog_fd
    );
    
    bpf_tc_attach(&hook, &opts);
    
    // Get map FDs for manifold updates
    map_fd = bpf_object__find_map_fd_by_name(obj, "manifold_exact");
    
    // Update manifold
    char domain[] = "api.example.com";
    struct manifold_entry entry = {
        .type = 0,  // exact
        .entropy_max_scaled = 0,
        .valid_until = 0,
    };
    
    bpf_map_update_elem(map_fd, domain, &entry, BPF_ANY);
    
    printf("DDM DNS filter loaded and attached\n");
    
    // Monitor events
    monitor_events(obj);
    
    return 0;
}
```

### Event Monitoring

```c
static int handle_event(void *ctx, void *data, size_t len) {
    struct violation_event *event = data;
    
    char timestamp[64];
    time_t t = event->timestamp / 1000000000;
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    printf("[%s] VIOLATION: domain=%s reason=%s pid=%u uid=%u entropy=%.2f\n",
           timestamp,
           event->domain,
           event->reason,
           event->pid,
           event->uid,
           (float)event->entropy_scaled / SCALE);
    
    return 0;
}

void monitor_events(struct bpf_object *obj) {
    struct ring_buffer *rb;
    int map_fd;
    
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return;
    }
    
    printf("Monitoring DNS violations...\n");
    
    while (1) {
        ring_buffer__poll(rb, 100);  // Poll every 100ms
    }
    
    ring_buffer__free(rb);
}
```

## Performance Optimization

### Per-CPU Data Structures

```c
// Per-CPU hash map for better concurrency
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 100000);
    __type(key, char[MAX_QNAME_LEN]);
    __type(value, struct manifold_entry);
} manifold_percpu SEC(".maps");
```

### Bloom Filter for Fast Negatives

```c
// Bloom filter for quick "definitely not in manifold" checks
struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, 1000000);
    __uint(value_size, MAX_QNAME_LEN);
} manifold_bloom SEC(".maps");

static __always_inline bool quick_manifold_check(char *domain) {
    // Fast negative lookup
    if (bpf_map_peek_elem(&manifold_bloom, domain) != 0)
        return false;  // Definitely not in manifold
    
    // Might be in manifold, do full lookup
    return true;
}
```

## Deployment

### Build Process

```bash
# Install dependencies
sudo apt-get install clang llvm libbpf-dev

# Compile eBPF program
clang -O2 -g -target bpf -c ddm_dns_filter.c -o ddm_dns_filter.o

# Compile user-space loader
gcc -o ddm_loader ddm_loader.c -lbpf

# Load and attach
sudo ./ddm_loader
```

### Systemd Service

```ini
[Unit]
Description=Axiom Hive DDM DNS Filter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ddm_loader
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### Common Issues

**1. Verifier Rejection**

```
Error: invalid argument (22)
Verifier log: R1 pointer arithmetic on map_value pointer prohibited
```

**Solution:** Avoid pointer arithmetic on map values. Use helper functions.

**2. Instruction Limit**

```
Error: program too large (1000001 insns)
```

**Solution:** Split into multiple programs or reduce loop unrolling.

**3. Map Size Limits**

```
Error: cannot create map: out of memory
```

**Solution:** Reduce `max_entries` or use per-CPU maps.

## Conclusion

The eBPF implementation provides a robust, performant, and safe foundation for the DDM on Linux. Key advantages:

- **No kernel modules**: Simplified deployment
- **Verified safety**: Kernel protects itself
- **High performance**: JIT compilation, zero-copy
- **Rich attribution**: Process, container, cgroup context

## Next Steps

- **[Windows WFP Implementation](windows-wfp.md)**: Windows equivalent
- **[Entropy Filtering](entropy-filtering.md)**: Detailed algorithms
- **[Deployment Guide](../operations/deployment.md)**: Production rollout

## References

1. [BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
2. [libbpf Documentation](https://libbpf.readthedocs.io/)
3. [BPF CO-RE (Compile Once – Run Everywhere)](https://nakryiko.com/posts/bpf-portability-and-co-re/)
