// Minimal compatibility shims so clangd can parse this file without Linux headers.
// This is only used when <linux/bpf.h> is not available (e.g., on Windows).
#ifndef DDM_BPF_COMPAT_SHIM_H
#define DDM_BPF_COMPAT_SHIM_H

#ifndef __has_include
#define __has_include(x) 0
#endif

#if !__has_include(<linux/bpf.h>)
#include <stdint.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif

#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

#ifndef __uint
#define __uint(name, val) unsigned int name __attribute__((unused))
#endif

#ifndef __type
#define __type(name, val) __typeof__(val) name __attribute__((unused))
#endif

enum {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_PERCPU_ARRAY = 28,
};

#define LIBBPF_PIN_BY_NAME 1

// Minimal skb definition for helpers that only read data/data_end.
struct __sk_buff {
    __u32 len;
    __u32 data;
    __u32 data_end;
};

// Helper stubs to satisfy clangd; no runtime behavior.
static __always_inline void *bpf_map_lookup_elem(void *map, const void *key) { return 0; }
static __always_inline int bpf_ringbuf_submit(void *data, __u64 flags) { return 0; }
static __always_inline void *bpf_ringbuf_reserve(void *rb, __u64 size, __u64 flags) { return 0; }
static __always_inline __u64 bpf_ktime_get_ns(void) { return 0; }
static __always_inline __u64 bpf_get_current_pid_tgid(void) { return 0; }
static __always_inline __u64 bpf_get_current_uid_gid(void) { return 0; }
static __always_inline __u32 bpf_get_netns_device_id(void) { return 0; }

static __always_inline __u16 bpf_ntohs(__u16 v) { return (v >> 8) | (v << 8); }

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// Minimal networking structs/constants for IntelliSense.
#define ETH_ALEN 6
#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6

struct ethhdr {
    __u8 h_dest[ETH_ALEN];
    __u8 h_source[ETH_ALEN];
    __u16 h_proto;
};

struct vlanhdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
};

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl:4, version:4;
#else
    __u8 version:4, ihl:4;
#endif
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

struct udphdr {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
};

struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#else
    __u16 doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#endif
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
};
#endif  // !__has_include(<linux/bpf.h>)

#endif  // DDM_BPF_COMPAT_SHIM_H
