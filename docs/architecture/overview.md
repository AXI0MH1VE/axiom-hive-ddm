# Architecture Overview

## Introduction

The Axiom Hive DNS Defense Module (DDM) implements a deterministic approach to DNS security that fundamentally differs from conventional probabilistic defenses. This document provides a comprehensive overview of the system architecture, design principles, and component interactions.

## Design Philosophy

### From Probabilistic to Deterministic

Traditional cybersecurity tools—Intrusion Detection Systems (IDS), Endpoint Detection and Response (EDR), Next-Generation Firewalls (NGFW)—operate as **probabilistic filters**. They infer maliciousness from:

- Signature databases
- Statistical anomalies
- Behavioral heuristics
- Machine learning models

This approach inherently accepts error:
- **False Positives**: Legitimate traffic blocked, disrupting operations
- **False Negatives**: Malicious traffic permitted, enabling compromise

The DDM replaces this model with **strict enforcement** based on:
- Pre-declared allowed states
- Mathematical verification
- Cryptographic proofs
- Zero-entropy constraints

### The Closed Manifold Concept

A **Closed Manifold** in DDM terminology represents:

> A finite, well-defined set of authorized DNS domains and resolution patterns that constitute the complete allowed state space for network behavior.

**Key Properties:**

1. **Completeness**: All legitimate DNS queries must exist within the manifold
2. **Boundedness**: The manifold has explicit, enforceable boundaries
3. **Verifiability**: Membership can be cryptographically proven
4. **Determinism**: No probabilistic inference—only binary membership tests

**Analogy to Physics:**

The manifold acts as a **potential well** in the Inverted Lagrangian framework:
- Authorized states sit at the bottom of the well (minimum energy)
- Unauthorized queries represent high kinetic energy
- The system enforces return to the potential minimum

## System Architecture

### High-Level Components

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Layer                       │
│              (Browsers, Apps, Services)                      │
└──────────────────────┬──────────────────────────────────────┘
                       │ DNS Queries
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Kernel-Space DDM Shim                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  1. Packet/Socket Interception                       │   │
│  │  2. Entropy Computation (Fixed-Point)                │   │
│  │  3. Manifold Membership Check                        │   │
│  │  4. Merkle Proof Verification                        │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │ Authorized Queries Only
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Hermetic Resolver                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  - Merkle-Backed Zone Data                          │   │
│  │  - Transparency Log Client                          │   │
│  │  - Inclusion Proof Generation                       │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │ DNS Response + Proof
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Public DNS / Upstream                       │
│              (Only for Hermetic Resolver)                    │
└─────────────────────────────────────────────────────────────┘
```

### Component Details

#### 1. Kernel-Space DNS Shim

**Purpose**: Intercept all DNS traffic at the lowest possible layer to prevent evasion.

**Platform Implementations:**

| Platform | Technology | Hook Points |
|----------|-----------|-------------|
| **Linux** | eBPF (Extended Berkeley Packet Filter) | XDP, TC, Socket hooks, Kprobes |
| **Windows** | WFP (Windows Filtering Platform) | ALE layers, FWPM callouts |

**Responsibilities:**
- Intercept DNS queries before transmission
- Extract QNAME (query name) and metadata
- Compute entropy in real-time
- Check manifold membership
- Verify Merkle proofs (Phase 3)
- Drop unauthorized packets
- Log violations with full attribution

**Key Design Requirement**: Must operate in kernel space to be immune to user-mode tampering, process termination, or privilege escalation attacks.

#### 2. Entropy Filter

**Purpose**: Detect high-entropy DNS queries that indicate tunneling or Domain Generation Algorithms (DGA).

**Traditional Approach (Rejected):**
```
if entropy(domain) > threshold:
    flag_as_suspicious()
```

**Problems:**
- CDNs use high-entropy labels legitimately
- No way to distinguish authorized randomness from malicious randomness
- Threshold tuning creates false positive/negative tradeoff

**DDM Approach:**
```
if domain not in manifold:
    if entropy(domain) > baseline:
        drop_packet()
        log_violation()
```

**Key Innovation**: Entropy is evaluated **only for domains outside the manifold**. Authorized high-entropy domains (CDNs, cloud services) are explicitly included in the manifold with cryptographic proofs.

**Implementation**: Fixed-point integer arithmetic suitable for kernel environments without floating-point support.

#### 3. Manifold Database

**Purpose**: Store and efficiently query the set of authorized DNS domains.

**Structure:**

```
Manifold Entry:
{
    domain: "api.example.com",
    type: "exact" | "wildcard",
    pattern: "*.cdn.example.com",
    merkle_root: "0x1a2b3c...",
    ttl: 3600,
    metadata: {
        added_by: "admin@example.com",
        justification: "Production API endpoint",
        risk_level: "low"
    }
}
```

**Storage Options:**
- **Kernel Space**: Hash table or radix tree for fast lookup
- **User Space**: SQLite or embedded database for management
- **Synchronization**: Atomic updates via shared memory or eBPF maps

**Wildcard Support**: Enables patterns like `*.cloudfront.net` to cover dynamic CDN subdomains while maintaining deterministic boundaries.

#### 4. Proof-of-Resolution Layer

**Purpose**: Cryptographically verify that DNS responses are authentic and authorized.

**Mechanism**: Merkle Tree-based authenticated dictionaries

**Workflow:**

1. **Hermetic Resolver** maintains a Merkle tree over all authorized DNS records
2. For each query, resolver returns:
   - DNS answer (IP address, CNAME, etc.)
   - Merkle inclusion proof (sibling hashes)
3. **DDM Shim** recomputes the Merkle root from the proof
4. If computed root matches pinned root → **ALLOW**
5. If mismatch or missing proof → **DROP**

**Properties:**
- **Integrity**: Any tampering changes the root hash
- **Transparency**: Root hashes can be published to public logs
- **Efficiency**: Logarithmic proof size and verification time
- **Post-Quantum Ready**: Hash-based, resistant to quantum attacks

#### 5. Hermetic Resolver

**Purpose**: Provide DNS resolution with cryptographic integrity guarantees.

**Architecture:**

```
┌─────────────────────────────────────────────────────────┐
│              Hermetic Resolver                          │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Zone Database (Merkle-Backed)                  │   │
│  │  - Internal zones (full authority)              │   │
│  │  - External zones (cached with proofs)          │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Transparency Log Client                        │   │
│  │  - Monitors public DNS transparency logs        │   │
│  │  - Verifies log consistency                     │   │
│  │  - Updates pinned roots                         │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Proof Generator                                │   │
│  │  - Computes Merkle inclusion proofs             │   │
│  │  - Attaches proofs to DNS responses             │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

**Deployment Modes:**

1. **Fully Hermetic** (High-Assurance Environments):
   - No recursion to public DNS
   - All zones preloaded with signed data
   - Zero external query leakage
   - Ideal for: OT, IoT, classified networks

2. **Hybrid** (Enterprise Environments):
   - Internal zones fully hermetic
   - External zones cached with transparency log verification
   - Controlled recursion to trusted upstreams
   - Ideal for: Corporate networks, cloud infrastructure

## Data Flow

### Query Processing Pipeline

```
1. Application initiates DNS query
   └─> "api.example.com" A record

2. Kernel Shim intercepts at socket/packet layer
   ├─> Extract QNAME: "api.example.com"
   ├─> Extract metadata: PID, UID, container ID
   └─> Compute entropy: H(QNAME)

3. Manifold Membership Check
   ├─> Exact match? → Proceed to step 4
   ├─> Wildcard match? → Proceed to step 4
   └─> No match? → Check entropy
       ├─> High entropy? → DROP + LOG
       └─> Low entropy? → DROP + LOG (unauthorized)

4. Forward to Hermetic Resolver
   └─> Query with endpoint identity

5. Resolver processes query
   ├─> Lookup in Merkle-backed zone database
   ├─> Generate inclusion proof
   └─> Return: Answer + Proof

6. Kernel Shim verifies proof
   ├─> Recompute Merkle root from proof
   ├─> Compare to pinned root
   ├─> Match? → ALLOW packet
   └─> Mismatch? → DROP + LOG

7. Application receives DNS response
   └─> Proceeds with connection
```

### Violation Handling

```
Unauthorized Query Detected
   │
   ├─> Log Event
   │   ├─> Timestamp
   │   ├─> QNAME
   │   ├─> Entropy value
   │   ├─> Process identity (PID, UID, binary path)
   │   ├─> Container/cgroup context
   │   └─> Network namespace
   │
   ├─> Drop Packet
   │   └─> No response to application
   │
   ├─> Alert (Optional)
   │   ├─> SIEM integration
   │   ├─> Webhook notification
   │   └─> Real-time dashboard
   │
   └─> Quarantine (Optional, Phase 4)
       ├─> Isolate process
       ├─> Network segmentation
       └─> Forensic snapshot
```

## Security Properties

### Threat Model

**In Scope:**
- DNS tunneling and exfiltration
- Domain Generation Algorithm (DGA) malware
- DNS cache poisoning
- Rogue resolver attacks
- Man-in-the-middle DNS hijacking
- Unauthorized network egress

**Out of Scope (Complementary Controls Required):**
- Direct IP connections bypassing DNS
- Pre-resolved IP hardcoded in malware
- Kernel-level rootkits (requires secure boot, measured boot)
- Physical attacks on hardware

### Guarantees

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Integrity** | DNS responses cannot be forged | Merkle proof verification |
| **Authenticity** | Responses come from authorized resolver | Cryptographic binding |
| **Completeness** | All DNS traffic is inspected | Kernel-level interception |
| **Determinism** | No false positives within manifold | Explicit allowlist, no inference |
| **Transparency** | All policy changes are auditable | Manifold versioning, logs |
| **Attribution** | Violations traced to process/user | Kernel metadata extraction |

### Defense in Depth

DDM is designed to layer with existing security controls:

```
┌────────────────────────────────────────────────────────┐
│  Application Security (Code review, SAST, DAST)        │
└────────────────────────────────────────────────────────┘
                        │
┌────────────────────────────────────────────────────────┐
│  Endpoint Security (EDR, AV)                           │
└────────────────────────────────────────────────────────┘
                        │
┌────────────────────────────────────────────────────────┐
│  DNS Defense Module (DDM) ← This Layer                 │
└────────────────────────────────────────────────────────┘
                        │
┌────────────────────────────────────────────────────────┐
│  Network Security (NGFW, IDS/IPS)                      │
└────────────────────────────────────────────────────────┘
                        │
┌────────────────────────────────────────────────────────┐
│  Zero Trust Architecture (ZTDNS, Network Segmentation) │
└────────────────────────────────────────────────────────┘
```

**Integration with Microsoft ZTDNS:**
- ZTDNS enforces resolver-of-record at OS level
- DDM provides local sovereignty and cryptographic verification
- Together: Resolver integrity + response verification

## Performance Considerations

### Latency Budget

| Operation | Target Latency | Implementation |
|-----------|---------------|----------------|
| Manifold lookup | < 10 µs | Hash table in kernel memory |
| Entropy computation | < 50 µs | Fixed-point arithmetic, bounded input |
| Merkle proof verification | < 100 µs | SHA-256 in kernel, ~10 hashes for 1M entries |
| **Total overhead** | **< 200 µs** | Negligible vs. network RTT (10-100 ms) |

### Throughput

**Target**: Handle 100,000+ DNS queries per second per endpoint without packet loss.

**Optimizations:**
- Zero-copy packet processing (XDP)
- JIT-compiled eBPF programs
- Lock-free data structures
- Per-CPU hash tables

### Memory Footprint

**Manifold Database:**
- Average domain entry: ~100 bytes
- 10,000 domains: ~1 MB
- 100,000 domains: ~10 MB

**Kernel Shim:**
- eBPF program: ~50 KB
- Per-CPU maps: ~1 MB
- Total: < 5 MB per endpoint

## Operational Model

### Deployment Phases

**Phase 1: Observability (Weeks 1-4)**
- Deploy in monitor-only mode
- Log all DNS queries without blocking
- Build baseline manifolds
- Identify high-entropy legitimate domains

**Phase 2: Enforcement (Weeks 5-8)**
- Enable blocking for high-confidence violations
- Gradual rollout by workload type (servers first)
- Continuous manifold refinement

**Phase 3: Cryptographic Verification (Weeks 9-12)**
- Deploy Hermetic Resolvers
- Enable Merkle proof requirements
- Full deterministic enforcement

### Manifold Management

**Lifecycle:**

1. **Discovery**: Automated learning from observability phase
2. **Review**: Security team validates business justification
3. **Approval**: Cryptographically signed manifold update
4. **Distribution**: Atomic push to all endpoints
5. **Enforcement**: Immediate effect, versioned rollback capability
6. **Audit**: All changes logged to immutable audit trail

**Update Frequency:**
- **Static Infrastructure**: Weekly or monthly
- **Dynamic Environments**: Daily with automated approval for known patterns
- **Emergency**: Real-time for security incidents

## Scalability

### Enterprise Deployment

**Architecture:**

```
┌─────────────────────────────────────────────────────────┐
│           Centralized Management Plane                  │
│  - Manifold Repository (Git-backed)                     │
│  - Policy Engine                                        │
│  - Analytics Dashboard                                  │
│  - Transparency Log Monitor                             │
└─────────────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
┌───────▼──────┐ ┌─────▼──────┐ ┌─────▼──────┐
│ Hermetic     │ │ Hermetic   │ │ Hermetic   │
│ Resolver 1   │ │ Resolver 2 │ │ Resolver N │
└───────┬──────┘ └─────┬──────┘ └─────┬──────┘
        │               │               │
┌───────▼────────────────▼───────────────▼─────┐
│          Endpoint Fleet (DDM Shims)          │
│  - Workstations                              │
│  - Servers                                   │
│  - Containers                                │
│  - IoT/OT Devices                            │
└──────────────────────────────────────────────┘
```

**Scaling Factors:**
- Hermetic Resolvers: Horizontally scalable, anycast deployment
- Manifold Distribution: CDN-like content distribution
- Log Aggregation: Distributed streaming (Kafka, Kinesis)

## Conclusion

The DDM architecture represents a paradigm shift from probabilistic threat detection to deterministic enforcement. By combining kernel-level interception, entropy filtering, cryptographic verification, and hermetic resolution, the system eliminates entire classes of DNS-based attacks while providing zero false positives within the defined manifold.

The architecture is designed for:
- **Security**: Cryptographic guarantees, not heuristics
- **Performance**: Microsecond-scale overhead
- **Scalability**: Enterprise-grade deployment
- **Operability**: Phased rollout, continuous refinement
- **Transparency**: Auditable, verifiable, deterministic

## Next Steps

- **[Linux Implementation](../implementation/linux-ebpf.md)**: eBPF-specific architecture
- **[Windows Implementation](../implementation/windows-wfp.md)**: WFP driver details
- **[Entropy Filtering](../implementation/entropy-filtering.md)**: Fixed-point algorithms
- **[Merkle Proofs](../implementation/merkle-proofs.md)**: Cryptographic verification
- **[Deployment Guide](../operations/deployment.md)**: Production rollout strategies
