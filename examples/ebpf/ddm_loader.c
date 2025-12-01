// SPDX-License-Identifier: MIT
/*
 * Axiom Hive DDM - User-Space Loader
 * 
 * This program loads the eBPF DNS filter, attaches it to the network interface,
 * manages the manifold database, and monitors violation events.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_QNAME_LEN 253
#define SCALE 65536

/* Structures matching eBPF program */
struct manifold_entry {
    __u8 type;
    __u32 entropy_max_scaled;
    __u64 valid_until;
    __u8 flags;
};

struct violation_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char domain[MAX_QNAME_LEN];
    char reason[32];
    __u32 entropy_scaled;
};

struct stats {
    __u64 packets_total;
    __u64 packets_allowed;
    __u64 packets_dropped;
    __u64 not_in_manifold;
    __u64 entropy_exceeded;
    __u64 expired;
};

/* Global state */
static struct bpf_object *obj = NULL;
static struct ring_buffer *rb = NULL;
static volatile sig_atomic_t stop = 0;

/* Signal handler */
static void sig_handler(int sig) {
    stop = 1;
}

/* Event handler callback */
static int handle_event(void *ctx, void *data, size_t len) {
    struct violation_event *event = data;
    
    time_t t = event->timestamp / 1000000000;
    struct tm *tm_info = localtime(&t);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    float entropy = (float)event->entropy_scaled / SCALE;
    
    printf("[%s] VIOLATION: domain=%s reason=%s pid=%u uid=%u entropy=%.2f\n",
           timestamp,
           event->domain,
           event->reason,
           event->pid,
           event->uid,
           entropy);
    
    return 0;
}

/* Load manifold from configuration file */
static int load_manifold(struct bpf_object *obj, const char *config_file) {
    FILE *fp;
    char line[512];
    int exact_fd, wildcard_fd;
    int count = 0;
    
    exact_fd = bpf_object__find_map_fd_by_name(obj, "manifold_exact");
    wildcard_fd = bpf_object__find_map_fd_by_name(obj, "manifold_wildcards");
    
    if (exact_fd < 0 || wildcard_fd < 0) {
        fprintf(stderr, "Failed to find manifold maps\n");
        return -1;
    }
    
    fp = fopen(config_file, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open config file: %s\n", config_file);
        return -1;
    }
    
    printf("Loading manifold from %s...\n", config_file);
    
    while (fgets(line, sizeof(line), fp)) {
        char domain[MAX_QNAME_LEN];
        char type[16];
        float entropy_max;
        int ttl;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n')
            continue;
        
        // Parse line: domain,type,entropy_max,ttl
        if (sscanf(line, "%253[^,],%15[^,],%f,%d", 
                   domain, type, &entropy_max, &ttl) != 4) {
            fprintf(stderr, "Invalid line: %s", line);
            continue;
        }
        
        struct manifold_entry entry = {0};
        
        if (strcmp(type, "exact") == 0) {
            entry.type = 0;
        } else if (strcmp(type, "wildcard") == 0) {
            entry.type = 1;
        } else {
            fprintf(stderr, "Unknown type: %s\n", type);
            continue;
        }
        
        entry.entropy_max_scaled = (entropy_max > 0) ? (__u32)(entropy_max * SCALE) : 0;
        entry.valid_until = (ttl > 0) ? (time(NULL) + ttl) : 0;
        
        // Add to appropriate map
        int map_fd = (entry.type == 0) ? exact_fd : wildcard_fd;
        
        if (bpf_map_update_elem(map_fd, domain, &entry, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to add domain: %s (error: %s)\n", 
                    domain, strerror(errno));
            continue;
        }
        
        count++;
        printf("  Added: %s (type=%s, entropy_max=%.2f)\n", 
               domain, type, entropy_max);
    }
    
    fclose(fp);
    printf("Loaded %d manifold entries\n", count);
    
    return count;
}

/* Print statistics */
static void print_stats(struct bpf_object *obj) {
    int stats_fd;
    __u32 key = 0;
    struct stats s = {0};
    
    stats_fd = bpf_object__find_map_fd_by_name(obj, "statistics");
    if (stats_fd < 0)
        return;
    
    if (bpf_map_lookup_elem(stats_fd, &key, &s) != 0)
        return;
    
    printf("\n=== Statistics ===\n");
    printf("Total packets:      %llu\n", s.packets_total);
    printf("Allowed:            %llu\n", s.packets_allowed);
    printf("Dropped:            %llu\n", s.packets_dropped);
    printf("  Not in manifold:  %llu\n", s.not_in_manifold);
    printf("  Entropy exceeded: %llu\n", s.entropy_exceeded);
    printf("  Expired:          %llu\n", s.expired);
    printf("==================\n\n");
}

int main(int argc, char **argv) {
    struct bpf_program *prog;
    int prog_fd, events_fd;
    int err;
    const char *ifname = "eth0";
    const char *config_file = "manifold.conf";
    
    if (argc > 1)
        ifname = argv[1];
    if (argc > 2)
        config_file = argv[2];
    
    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Set up libbpf logging */
    libbpf_set_print(NULL);
    
    printf("Axiom Hive DDM - DNS Defense Module\n");
    printf("===================================\n\n");
    
    /* Open BPF object */
    obj = bpf_object__open_file("ddm_dns_filter.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    /* Load BPF object into kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    printf("BPF object loaded successfully\n");
    
    /* Find the program */
    prog = bpf_object__find_program_by_name(obj, "ddm_dns_filter");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        goto cleanup;
    }
    
    prog_fd = bpf_program__fd(prog);
    
    /* Attach to TC egress */
    printf("Attaching to interface: %s\n", ifname);
    
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = if_nametoindex(ifname),
        .attach_point = BPF_TC_EGRESS
    );
    
    /* Create TC hook */
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }
    
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = prog_fd
    );
    
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC program: %d\n", err);
        goto cleanup;
    }
    
    printf("BPF program attached successfully\n\n");
    
    /* Load manifold configuration */
    if (load_manifold(obj, config_file) < 0) {
        fprintf(stderr, "Warning: Failed to load manifold, continuing anyway\n");
    }
    
    printf("\n");
    
    /* Set up ring buffer for events */
    events_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (events_fd < 0) {
        fprintf(stderr, "Failed to find events map\n");
        goto cleanup;
    }
    
    rb = ring_buffer__new(events_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    printf("Monitoring DNS violations (Ctrl+C to stop)...\n\n");
    
    /* Main event loop */
    while (!stop) {
        err = ring_buffer__poll(rb, 1000);  // Poll every 1 second
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        
        /* Print stats every 10 seconds */
        static time_t last_stats = 0;
        time_t now = time(NULL);
        if (now - last_stats >= 10) {
            print_stats(obj);
            last_stats = now;
        }
    }
    
    printf("\nShutting down...\n");
    print_stats(obj);
    
    /* Detach TC program */
    opts.flags = opts.prog_fd = opts.prog_id = 0;
    err = bpf_tc_detach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to detach TC program: %d\n", err);
    }
    
    /* Destroy TC hook */
    bpf_tc_hook_destroy(&hook);
    
cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (obj)
        bpf_object__close(obj);
    
    printf("Cleanup complete\n");
    return 0;
}
