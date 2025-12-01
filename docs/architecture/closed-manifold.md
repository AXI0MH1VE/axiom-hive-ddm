# The Closed Manifold: Deterministic State Space for DNS

## Introduction

The **Closed Manifold** is the foundational concept of the Axiom Hive DNS Defense Module. It represents a radical departure from probabilistic security models by defining a finite, verifiable set of authorized network states.

## Conceptual Foundation

### Definition

> A **Closed Manifold** is a mathematically bounded set of authorized DNS domains and resolution patterns that completely defines the allowed state space for network behavior. Any DNS query outside this manifold is structurally unauthorized, regardless of its apparent legitimacy.

### Mathematical Formulation

Let **M** be the Closed Manifold, defined as:

```
M = { (d, r) | d ∈ D_authorized, r ∈ R_valid(d) }
```

Where:
- **d**: A DNS domain name (QNAME)
- **D_authorized**: The set of all authorized domain names
- **r**: A DNS resolution result (IP address, CNAME, etc.)
- **R_valid(d)**: The set of valid resolutions for domain d

**Closure Property:**

For any DNS query **q**:
```
q ∈ M  →  ALLOW
q ∉ M  →  DROP
```

No probabilistic inference. No confidence scores. Only binary membership.

### Contrast with Probabilistic Models

| Aspect | Probabilistic Model | Closed Manifold |
|--------|-------------------|-----------------|
| **Decision Basis** | Statistical inference, signatures, ML | Explicit authorization |
| **Uncertainty** | Confidence scores (0-1) | Binary (0 or 1) |
| **False Positives** | Inevitable tradeoff | Eliminated by design* |
| **False Negatives** | Inevitable tradeoff | Impossible within manifold |
| **Operational Mode** | Reactive detection | Proactive enforcement |
| **Threat Model** | Known bad patterns | Everything not known good |

\* *Within the manifold. Undeclared legitimate domains are not misclassifications but policy gaps.*

## Components of the Manifold

### 1. Exact Domain Entries

**Definition**: Specific, fully-qualified domain names.

**Examples:**
```
api.example.com
www.example.com
mail.example.com
```

**Use Cases:**
- Internal services with fixed endpoints
- Critical external APIs
- Known infrastructure domains

**Storage:**
```json
{
  "type": "exact",
  "domain": "api.example.com",
  "records": [
    {
      "type": "A",
      "value": "203.0.113.10",
      "ttl": 3600
    }
  ],
  "merkle_proof": "0x1a2b3c4d...",
  "metadata": {
    "owner": "platform-team",
    "criticality": "high",
    "added": "2025-01-15T10:30:00Z"
  }
}
```

### 2. Wildcard Patterns

**Definition**: Pattern-based authorization for dynamic subdomains.

**Syntax:**
```
*.cdn.example.com        # Any subdomain of cdn.example.com
*.s3.amazonaws.com       # AWS S3 buckets
content-*.cloudfront.net # CloudFront distributions
```

**Matching Rules:**
- `*` matches one or more labels
- Patterns are anchored (not substring matches)
- Most specific pattern takes precedence

**Use Cases:**
- Content Delivery Networks (CDNs)
- Cloud storage services
- Dynamic microservice deployments
- SaaS platforms with customer subdomains

**Implementation:**
```python
def matches_wildcard(domain, pattern):
    """
    Check if domain matches wildcard pattern.
    
    Examples:
      matches_wildcard("abc.cdn.example.com", "*.cdn.example.com") → True
      matches_wildcard("cdn.example.com", "*.cdn.example.com") → False
      matches_wildcard("a.b.cdn.example.com", "*.cdn.example.com") → True
    """
    pattern_parts = pattern.split('.')
    domain_parts = domain.split('.')
    
    if len(domain_parts) < len(pattern_parts):
        return False
    
    # Match from right to left
    for i in range(1, len(pattern_parts) + 1):
        if pattern_parts[-i] == '*':
            continue
        if pattern_parts[-i] != domain_parts[-i]:
            return False
    
    return True
```

### 3. Temporal Constraints

**Definition**: Time-bounded authorizations that automatically expire.

**Use Cases:**
- Short-lived development endpoints
- Temporary partner integrations
- Time-limited campaigns or events
- Incident response temporary access

**Schema:**
```json
{
  "type": "exact",
  "domain": "temp-api.partner.com",
  "valid_from": "2025-12-01T00:00:00Z",
  "valid_until": "2025-12-31T23:59:59Z",
  "auto_revoke": true
}
```

**Enforcement:**
- Kernel shim checks timestamp on each query
- Expired entries treated as non-existent
- Automatic cleanup reduces manifold bloat

### 4. Entropy Bounds

**Definition**: Maximum allowed entropy for domains within wildcard patterns.

**Purpose**: Prevent abuse of wildcard authorizations for DNS tunneling.

**Example:**
```json
{
  "type": "wildcard",
  "pattern": "*.cdn.example.com",
  "entropy_max": 3.5,
  "rationale": "CDN uses predictable hash prefixes, not random strings"
}
```

**Enforcement:**
```
Query: "abc123.cdn.example.com"
  ├─> Matches wildcard pattern ✓
  ├─> Compute entropy: H("abc123") = 2.8
  ├─> Compare: 2.8 < 3.5 ✓
  └─> ALLOW

Query: "xK9pQmZw.cdn.example.com"
  ├─> Matches wildcard pattern ✓
  ├─> Compute entropy: H("xK9pQmZw") = 4.2
  ├─> Compare: 4.2 > 3.5 ✗
  └─> DROP (high entropy in authorized pattern)
```

## Manifold Construction

### Discovery Phase

**Objective**: Build initial manifold from observed traffic.

**Process:**

1. **Passive Observation** (2-4 weeks)
   ```
   Deploy DDM in monitor-only mode
   Log all DNS queries with metadata:
     - Domain name
     - Query type (A, AAAA, CNAME, etc.)
     - Source process/container
     - Timestamp
     - Entropy
   ```

2. **Clustering and Analysis**
   ```
   Group domains by:
     - Base domain (e.g., all *.example.com)
     - Entropy profile
     - Query frequency
     - Business unit/application
   ```

3. **Pattern Extraction**
   ```
   Identify candidates for:
     - Exact entries (low-frequency, critical)
     - Wildcard patterns (high-frequency, variable subdomains)
     - Temporal entries (rare, time-bound)
   ```

4. **Validation**
   ```
   Cross-reference with:
     - Asset inventory (CMDB)
     - Network diagrams
     - Application documentation
     - Security policies
   ```

### Manual Curation

**Roles:**

- **Application Owners**: Declare required external dependencies
- **Security Team**: Validate business justification and risk
- **Network Team**: Verify infrastructure requirements
- **Compliance**: Ensure regulatory alignment

**Approval Workflow:**

```
Request: Add "api.newvendor.com" to manifold
  │
  ├─> Application Owner: Business justification
  │   "Required for payment processing integration"
  │
  ├─> Security Team: Risk assessment
  │   - Vendor reputation check
  │   - Data flow analysis
  │   - Encryption requirements
  │
  ├─> Network Team: Technical validation
  │   - DNS resolution test
  │   - IP range documentation
  │   - Firewall rule coordination
  │
  ├─> Compliance: Regulatory review
  │   - Data residency requirements
  │   - Privacy impact assessment
  │
  └─> Approval: Cryptographically signed manifold update
      - Git commit with GPG signature
      - Audit log entry
      - Automated distribution to endpoints
```

### Automated Expansion

**Scenario**: Application deploys new microservice with dynamic DNS.

**Solution**: Controlled automation with guardrails.

```yaml
# Automation Policy
automation:
  enabled: true
  
  rules:
    - name: "Internal Kubernetes Services"
      condition:
        pattern: "*.svc.cluster.local"
        namespace: "production"
      action:
        add_to_manifold: true
        type: "wildcard"
        approval: "automatic"
        ttl: 86400  # 24 hours
      
    - name: "AWS S3 Buckets"
      condition:
        pattern: "*.s3.amazonaws.com"
        tag: "managed-by-terraform"
      action:
        add_to_manifold: true
        type: "wildcard"
        approval: "security-team"
        entropy_max: 4.0
      
    - name: "Unknown External Domains"
      condition:
        pattern: "*"
        internal: false
      action:
        add_to_manifold: false
        alert: "security-team"
        block: true
```

## Manifold Maintenance

### Update Mechanisms

**1. Git-Based Version Control**

```bash
# Manifold repository structure
manifold-repo/
├── manifolds/
│   ├── production.json
│   ├── staging.json
│   └── development.json
├── policies/
│   ├── wildcard-rules.yaml
│   └── entropy-thresholds.yaml
├── audit/
│   └── changes.log
└── scripts/
    ├── validate.py
    ├── deploy.sh
    └── rollback.sh
```

**Workflow:**
```bash
# 1. Make changes
git checkout -b add-new-api
vim manifolds/production.json

# 2. Validate
./scripts/validate.py manifolds/production.json

# 3. Commit with signature
git commit -S -m "Add api.newvendor.com for payment integration"

# 4. Review and merge
git push origin add-new-api
# Pull request with security team approval

# 5. Automated deployment
# CI/CD pipeline distributes to all endpoints
./scripts/deploy.sh production
```

**2. Atomic Updates**

**Challenge**: Ensure all endpoints have consistent manifold state.

**Solution**: Versioned manifolds with atomic swaps.

```c
// Kernel-space implementation (eBPF)
struct manifold_version {
    u64 version_id;
    u64 timestamp;
    u32 entry_count;
    u8 merkle_root[32];
};

// Atomic pointer swap
BPF_PERCPU_ARRAY(current_manifold, struct manifold_version, 1);

int update_manifold(struct manifold_version *new_version) {
    u32 key = 0;
    struct manifold_version *old = 
        bpf_map_lookup_elem(&current_manifold, &key);
    
    if (!old)
        return -1;
    
    // Atomic update
    bpf_map_update_elem(&current_manifold, &key, new_version, BPF_ANY);
    
    return 0;
}
```

**3. Rollback Capability**

```bash
# Detect issue with new manifold
./scripts/monitor.sh --check-violations

# Immediate rollback
./scripts/rollback.sh --to-version 1234

# Verify
./scripts/validate.sh --version 1234
```

### Drift Detection

**Problem**: Manifold may become stale as infrastructure evolves.

**Solution**: Continuous monitoring and alerting.

```python
# Drift detection algorithm
def detect_drift(observed_queries, manifold):
    """
    Identify domains frequently queried but not in manifold.
    """
    drift_candidates = []
    
    for domain, count in observed_queries.items():
        if domain not in manifold:
            if count > THRESHOLD:
                drift_candidates.append({
                    'domain': domain,
                    'query_count': count,
                    'first_seen': get_first_seen(domain),
                    'processes': get_querying_processes(domain)
                })
    
    return drift_candidates

# Alert on drift
drift = detect_drift(last_24h_queries, current_manifold)
if drift:
    alert_security_team(
        title="Manifold Drift Detected",
        domains=drift,
        action_required="Review and update manifold"
    )
```

## Operational Challenges

### Challenge 1: CDN and Cloud Services

**Problem**: Modern services use thousands of dynamic subdomains.

**Example:**
```
# Netflix CDN
ipv4-c001-prg001-ix.1.oca.nflxvideo.net
ipv4-c002-prg001-ix.1.oca.nflxvideo.net
ipv4-c003-prg001-ix.1.oca.nflxvideo.net
... (thousands more)
```

**Solution**: Hierarchical wildcard patterns with entropy bounds.

```json
{
  "type": "wildcard",
  "pattern": "*.oca.nflxvideo.net",
  "entropy_max": 4.0,
  "subpattern": "ipv4-c*-*-*.1.oca.nflxvideo.net",
  "justification": "Netflix CDN infrastructure"
}
```

### Challenge 2: Third-Party Integrations

**Problem**: SaaS vendors change infrastructure without notice.

**Example:** Vendor migrates from `api.vendor.com` to `api-v2.vendor.com`.

**Solutions:**

1. **Proactive Monitoring**
   ```
   Subscribe to vendor status pages
   Monitor vendor DNS changes via transparency logs
   Automated alerts for vendor infrastructure changes
   ```

2. **Graceful Degradation**
   ```
   On first violation:
     - Log and alert
     - Allow with warning (grace period)
     - Notify administrators
   
   After grace period:
     - Enforce blocking
     - Require explicit manifold update
   ```

3. **Vendor Coordination**
   ```
   Establish communication channels with critical vendors
   Request advance notice of infrastructure changes
   Negotiate stable DNS patterns
   ```

### Challenge 3: Development vs. Production

**Problem**: Development environments need flexibility; production needs security.

**Solution**: Environment-specific manifolds with different policies.

```yaml
# Development Manifold
environment: development
policy:
  default_action: "allow_and_log"
  entropy_threshold: 5.0  # More permissive
  wildcard_expansion: "automatic"
  temporal_entries: "enabled"

# Production Manifold
environment: production
policy:
  default_action: "deny"
  entropy_threshold: 3.5  # Stricter
  wildcard_expansion: "manual_approval"
  temporal_entries: "disabled"
```

## Integration with Zero Trust

### Zero Trust Principles

1. **Never Trust, Always Verify**: Manifold enforces explicit verification
2. **Least Privilege**: Only authorized domains accessible
3. **Assume Breach**: Limits lateral movement via DNS
4. **Verify Explicitly**: Cryptographic proof-of-resolution

### Complementary Controls

```
┌─────────────────────────────────────────────────────────┐
│  Identity & Access Management (IAM)                     │
│  - User authentication                                  │
│  - Role-based access control                            │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Device Trust (EDR, Posture Checking)                   │
│  - Device compliance                                    │
│  - Patch status                                         │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  DNS Defense Module (Closed Manifold) ← This Layer     │
│  - Authorized destinations only                         │
│  - Cryptographic verification                           │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Network Segmentation (Micro-segmentation)              │
│  - Workload isolation                                   │
│  - East-west traffic control                            │
└─────────────────────────────────────────────────────────┘
```

## Performance Optimization

### Lookup Efficiency

**Data Structure**: Radix tree (trie) for domain lookups.

```
Example Manifold:
  api.example.com
  www.example.com
  *.cdn.example.com

Radix Tree:
        (root)
          │
         com
          │
       example
       /     \
     api     www
             /
           cdn
           │
          (*)  ← wildcard marker
```

**Complexity:**
- Exact lookup: O(k) where k = domain length
- Wildcard match: O(k × w) where w = number of wildcards
- Memory: O(n × k) where n = number of domains

**Optimization**: Bloom filter for fast negative lookups.

```c
// Fast path: Bloom filter
if (!bloom_filter_contains(domain)) {
    // Definitely not in manifold
    return DROP;
}

// Slow path: Precise lookup
if (radix_tree_lookup(domain)) {
    return ALLOW;
} else {
    return DROP;
}
```

### Cache Locality

**Strategy**: Keep hot domains in CPU cache.

```c
// LRU cache for frequent domains
#define CACHE_SIZE 256

struct lru_cache {
    char domain[256];
    bool authorized;
    u64 last_access;
};

BPF_PERCPU_ARRAY(domain_cache, struct lru_cache, CACHE_SIZE);
```

## Conclusion

The Closed Manifold is the cornerstone of deterministic DNS security. By explicitly defining authorized network behavior and enforcing it cryptographically, the DDM eliminates the uncertainty inherent in probabilistic models.

**Key Takeaways:**

1. **Determinism**: Binary decisions, no confidence scores
2. **Completeness**: All authorized domains explicitly declared
3. **Verifiability**: Cryptographic proofs for every resolution
4. **Maintainability**: Git-based versioning, automated workflows
5. **Scalability**: Efficient data structures, sub-millisecond lookups
6. **Flexibility**: Wildcards, temporal entries, entropy bounds

The manifold transforms DNS from an open, trust-based protocol into a closed, verified system where every connection is authorized by design, not permitted by default.

## Further Reading

- **[Architecture Overview](overview.md)**: Complete system architecture
- **[Inverted Lagrangian](inverted-lagrangian.md)**: Theoretical foundation
- **[Entropy Filtering](../implementation/entropy-filtering.md)**: Technical implementation
- **[Deployment Guide](../operations/deployment.md)**: Operational procedures
