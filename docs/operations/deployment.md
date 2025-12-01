# Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Axiom Hive DNS Defense Module in production environments. The deployment follows a phased approach to minimize disruption while maximizing security benefits.

## Prerequisites

### System Requirements

**Linux Endpoints:**
- Operating System: Ubuntu 20.04+, RHEL 8+, or compatible distribution
- Kernel Version: 5.8 or later with eBPF support
- Memory: Minimum 512 MB available
- Disk Space: 100 MB for DDM components
- Network: Outbound DNS (UDP/53 or DoH/DoT)

**Windows Endpoints:**
- Operating System: Windows 10 (1809+) or Windows Server 2019+
- Memory: Minimum 512 MB available
- Disk Space: 100 MB for DDM components
- Driver Signing: Code signing certificate or test signing mode

**Hermetic Resolver:**
- CPU: 4+ cores recommended
- Memory: 8 GB minimum, 16 GB recommended
- Disk: 50 GB for zone data and logs
- Network: High-bandwidth, low-latency connection to endpoints

### Software Dependencies

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential \
    pkg-config

# RHEL/CentOS
sudo yum install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    gcc \
    make
```

**Windows:**
- Visual Studio 2019 or later with Windows Driver Kit (WDK)
- Windows SDK
- Code signing certificate (for production deployment)

## Deployment Phases

### Phase 1: Observability (Weeks 1-4)

The first phase deploys DDM in monitor-only mode to establish baselines without impacting operations.

#### Objectives

The observability phase serves to understand current DNS behavior patterns across the organization. During this period, the system collects comprehensive data on all DNS queries, including domain names, query frequencies, process attribution, and entropy profiles. This data forms the foundation for building an accurate Closed Manifold that reflects legitimate business requirements while maintaining security.

#### Deployment Steps

**1. Install DDM Components**

```bash
# Clone repository
git clone https://github.com/axiom-hive/ddm.git
cd ddm

# Build components
./scripts/build.sh linux

# Install system-wide
sudo make install
```

**2. Configure Monitor Mode**

Create configuration file at `/etc/ddm/config.yaml`:

```yaml
mode: observe
log_level: info
log_destination: /var/log/ddm/queries.log

# Monitoring settings
monitor:
  capture_all_queries: true
  include_process_info: true
  include_container_info: true
  compute_entropy: true
  
# Storage
storage:
  retention_days: 30
  max_log_size_mb: 1000
  
# Export
export:
  enabled: true
  format: json
  destination: /var/log/ddm/export/
  interval_seconds: 3600
```

**3. Deploy to Pilot Group**

Start with a small, representative group of endpoints:

```bash
# Start DDM in monitor mode
sudo systemctl start ddm-monitor
sudo systemctl enable ddm-monitor

# Verify operation
sudo systemctl status ddm-monitor
sudo tail -f /var/log/ddm/queries.log
```

**4. Collect and Analyze Data**

After running for at least two weeks, analyze the collected data:

```bash
# Generate baseline report
ddm-analyze --input /var/log/ddm/queries.log \
            --output /tmp/baseline-report.json \
            --generate-manifold

# Review high-entropy domains
ddm-analyze --show-high-entropy --threshold 4.0

# Identify patterns for wildcards
ddm-analyze --suggest-wildcards --min-frequency 100
```

**5. Build Initial Manifold**

Review the automatically generated manifold and refine it:

```bash
# Export suggested manifold
ddm-analyze --export-manifold > /tmp/suggested-manifold.conf

# Review and edit
vim /tmp/suggested-manifold.conf

# Validate manifold
ddm-validate --manifold /tmp/suggested-manifold.conf

# Deploy to test environment
ddm-deploy --manifold /tmp/suggested-manifold.conf --environment test
```

#### Success Criteria

The observability phase is considered successful when the following conditions are met. First, data collection must be complete across all pilot endpoints with no gaps or failures. Second, the baseline manifold should cover at least ninety-five percent of observed legitimate traffic. Third, high-entropy domains must be properly categorized as either legitimate CDN traffic requiring wildcard patterns or potential threats requiring investigation. Fourth, stakeholders from application teams, security, and network operations must review and approve the initial manifold.

### Phase 2: Enforcement (Weeks 5-8)

The second phase enables active enforcement, blocking unauthorized DNS queries while continuously refining the manifold.

#### Objectives

This phase transitions from passive monitoring to active security enforcement. The system begins dropping packets that violate the Closed Manifold policy, effectively preventing DNS tunneling, DGA malware, and unauthorized network egress. The focus remains on minimizing false positives through careful manifold management and rapid response to legitimate business needs.

#### Deployment Steps

**1. Update Configuration for Enforcement**

Modify `/etc/ddm/config.yaml`:

```yaml
mode: enforce
enforcement:
  default_action: drop
  grace_period_seconds: 300  # 5 minutes for new violations
  alert_on_drop: true
  
manifold:
  source: /etc/ddm/manifold.conf
  auto_reload: true
  reload_interval_seconds: 60
  
alerts:
  enabled: true
  destinations:
    - type: syslog
      facility: local0
    - type: webhook
      url: https://siem.example.com/api/alerts
    - type: email
      recipients:
        - security-team@example.com
```

**2. Gradual Rollout**

Deploy enforcement in stages to minimize disruption:

**Stage 1: Non-Production Servers (Week 5)**

Begin with development and staging servers where impact is limited:

```bash
# Deploy to dev/staging
ansible-playbook -i inventory/staging deploy-ddm.yml \
  --extra-vars "mode=enforce"

# Monitor for 48 hours
ddm-monitor --environment staging --duration 48h
```

**Stage 2: Production Servers (Week 6)**

Proceed to production servers with stable DNS patterns:

```bash
# Deploy to production servers
ansible-playbook -i inventory/production-servers deploy-ddm.yml \
  --extra-vars "mode=enforce"

# Monitor closely for 72 hours
ddm-monitor --environment production --alert-threshold high
```

**Stage 3: Workstations (Week 7-8)**

Finally, deploy to user workstations with enhanced support:

```bash
# Deploy to workstations in batches
for batch in batch1 batch2 batch3; do
  ansible-playbook -i inventory/$batch deploy-ddm.yml \
    --extra-vars "mode=enforce"
  
  # Wait 48 hours between batches
  sleep $((48 * 3600))
done
```

**3. Violation Response Workflow**

Establish a clear process for handling violations:

```
Violation Detected
  │
  ├─> Automated Analysis
  │   ├─> Known CDN/Cloud? → Add to manifold
  │   ├─> Internal service? → Investigate and add
  │   └─> Unknown external? → Security review
  │
  ├─> Temporary Allowlist (if urgent)
  │   └─> Time-limited entry (24 hours)
  │
  ├─> Permanent Addition (if approved)
  │   ├─> Document justification
  │   ├─> Add to manifold with appropriate constraints
  │   └─> Deploy update
  │
  └─> Incident Investigation (if malicious)
      ├─> Isolate affected endpoint
      ├─> Forensic analysis
      └─> Remediation
```

**4. Manifold Management**

Implement version control and change management:

```bash
# Initialize manifold repository
cd /etc/ddm
git init
git add manifold.conf
git commit -m "Initial manifold baseline"

# Create update workflow
cat > /usr/local/bin/update-manifold << 'EOF'
#!/bin/bash
set -e

# Validate new manifold
ddm-validate --manifold manifold.conf.new

# Commit change
git add manifold.conf.new
git commit -m "Update: $1"

# Deploy to endpoints
ddm-deploy --manifold manifold.conf.new --all-endpoints

# Rename to active
mv manifold.conf manifold.conf.backup
mv manifold.conf.new manifold.conf
EOF

chmod +x /usr/local/bin/update-manifold
```

#### Success Criteria

Enforcement is successful when violations are reduced by at least ninety percent compared to the observability phase, false positive rate remains below one percent of total queries, mean time to resolution for legitimate violations is under four hours, and no business-critical services are disrupted by DDM enforcement.

### Phase 3: Cryptographic Verification (Weeks 9-12)

The final phase adds Merkle-based proof-of-resolution for cryptographic integrity guarantees.

#### Objectives

This phase elevates DNS security from policy enforcement to cryptographic verification. Every DNS response must include a valid Merkle inclusion proof that can be independently verified by the endpoint. This eliminates trust in the resolver and provides mathematical certainty that DNS responses are authentic and authorized.

#### Deployment Steps

**1. Deploy Hermetic Resolvers**

Set up dedicated resolvers with Merkle tree support:

```bash
# Install hermetic resolver
sudo apt-get install ddm-hermetic-resolver

# Configure resolver
cat > /etc/ddm-resolver/config.yaml << EOF
resolver:
  listen_addresses:
    - 10.0.1.10:53
    - 10.0.2.10:53
  
  zones:
    internal:
      source: /etc/ddm-resolver/zones/internal.zone
      merkle_tree: true
    
    external:
      upstream:
        - 8.8.8.8
        - 1.1.1.1
      cache_ttl: 3600
      merkle_tree: true
  
  transparency:
    enabled: true
    log_url: https://transparency.example.com/dns
    verification_interval: 300
  
  proof_generation:
    enabled: true
    algorithm: sha256
    include_in_response: true
EOF

# Start resolver
sudo systemctl start ddm-resolver
sudo systemctl enable ddm-resolver
```

**2. Generate Merkle Trees for Zones**

Build Merkle trees for all authorized domains:

```bash
# Generate tree from manifold
ddm-merkle-gen --manifold /etc/ddm/manifold.conf \
               --output /etc/ddm-resolver/merkle-tree.db

# Verify tree integrity
ddm-merkle-verify --tree /etc/ddm-resolver/merkle-tree.db

# Export root hash
ddm-merkle-root --tree /etc/ddm-resolver/merkle-tree.db \
                > /etc/ddm/merkle-root.txt
```

**3. Update Endpoints for Proof Verification**

Enable proof verification on endpoints:

```yaml
# /etc/ddm/config.yaml
mode: enforce

verification:
  enabled: true
  require_merkle_proof: true
  pinned_roots:
    - hash: "0x1a2b3c4d..."
      valid_from: "2025-01-01T00:00:00Z"
      valid_until: "2025-12-31T23:59:59Z"
  
  resolver:
    primary: 10.0.1.10
    secondary: 10.0.2.10
    require_tls: true
```

**4. Test Proof Verification**

Validate end-to-end proof verification:

```bash
# Test query with proof
dig @10.0.1.10 api.example.com +dnssec

# Verify proof manually
ddm-verify-proof --domain api.example.com \
                 --response response.bin \
                 --root /etc/ddm/merkle-root.txt

# Monitor verification failures
journalctl -u ddm -f | grep "proof_verification_failed"
```

**5. Establish Root Rotation Process**

Implement secure root hash updates:

```bash
# Generate new tree with updated manifold
ddm-merkle-gen --manifold /etc/ddm/manifold.conf.new \
               --output /tmp/merkle-tree-new.db

# Compute new root
NEW_ROOT=$(ddm-merkle-root --tree /tmp/merkle-tree-new.db)

# Sign root with organizational key
echo "$NEW_ROOT" | gpg --sign --armor > /tmp/merkle-root-signed.txt

# Distribute to endpoints
ddm-deploy --merkle-root /tmp/merkle-root-signed.txt \
           --all-endpoints \
           --verify-signature
```

#### Success Criteria

Cryptographic verification is successful when all DNS responses include valid Merkle proofs, proof verification completes in under one hundred microseconds per query, zero DNS spoofing or cache poisoning incidents occur, and transparency logs are continuously monitored with no consistency violations detected.

## Architecture Patterns

### High-Availability Deployment

For enterprise environments requiring high availability:

```
┌─────────────────────────────────────────────────────┐
│          Load Balancer (Anycast DNS)                │
│              10.0.0.53 (VIP)                        │
└──────────────┬──────────────┬──────────────┬────────┘
               │              │              │
    ┌──────────▼─────┐ ┌─────▼──────┐ ┌────▼───────┐
    │ Resolver 1     │ │ Resolver 2 │ │ Resolver 3 │
    │ DC-East        │ │ DC-West    │ │ DC-Central │
    │ Active         │ │ Active     │ │ Active     │
    └────────────────┘ └────────────┘ └────────────┘
```

Configuration:

```yaml
# Load balancer health checks
health_check:
  interval: 5s
  timeout: 2s
  unhealthy_threshold: 3
  healthy_threshold: 2
  check_type: dns_query
  test_domain: health.internal

# Resolver synchronization
sync:
  method: raft
  cluster_members:
    - 10.0.1.10
    - 10.0.2.10
    - 10.0.3.10
  election_timeout: 1000ms
  heartbeat_interval: 500ms
```

### Kubernetes Deployment

Deploy DDM as a DaemonSet in Kubernetes:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ddm-agent
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: ddm-agent
  template:
    metadata:
      labels:
        app: ddm-agent
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: ddm
        image: axiomhive/ddm:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: bpf
          mountPath: /sys/fs/bpf
        - name: config
          mountPath: /etc/ddm
        env:
        - name: DDM_MODE
          value: "enforce"
        - name: DDM_RESOLVER
          value: "ddm-resolver.kube-system.svc.cluster.local"
      volumes:
      - name: bpf
        hostPath:
          path: /sys/fs/bpf
      - name: config
        configMap:
          name: ddm-config
```

## Monitoring and Alerting

### Key Metrics

Monitor these critical metrics for operational health:

**Performance Metrics:**
- DNS query latency (p50, p95, p99)
- Manifold lookup time
- Entropy computation time
- Proof verification time
- Packet drop rate

**Security Metrics:**
- Violations per hour
- Unique violating domains
- High-entropy query rate
- Proof verification failures
- Manifold coverage percentage

**Operational Metrics:**
- Manifold size (entries)
- Manifold update frequency
- Resolver availability
- Log storage utilization
- Endpoint compliance rate

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ddm-endpoints'
    static_configs:
      - targets: ['endpoint1:9090', 'endpoint2:9090']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'ddm-resolvers'
    static_configs:
      - targets: ['resolver1:9091', 'resolver2:9091']
    metrics_path: '/metrics'
    scrape_interval: 10s
```

### Grafana Dashboards

Import the provided dashboard for visualization:

```bash
# Import DDM dashboard
curl -X POST http://grafana:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d @dashboards/ddm-overview.json
```

## Troubleshooting

### Common Issues

**Issue: High False Positive Rate**

Symptoms: Legitimate services blocked, user complaints, manifold gaps identified.

Resolution: Review violation logs to identify missing manifold entries, add legitimate domains with appropriate wildcard patterns, consider temporary grace periods for new services, and engage with application teams to document dependencies.

**Issue: Performance Degradation**

Symptoms: Increased DNS latency, high CPU usage, packet loss.

Resolution: Optimize manifold data structures using bloom filters for fast negatives, reduce entropy computation overhead with caching, scale resolver infrastructure horizontally, and review eBPF program efficiency with bpftool.

**Issue: Proof Verification Failures**

Symptoms: Valid queries blocked, merkle root mismatches, resolver synchronization issues.

Resolution: Verify root hash distribution across endpoints, check resolver Merkle tree consistency, ensure transparency log synchronization, and validate network connectivity between endpoints and resolvers.

## Rollback Procedures

If issues arise, follow these rollback steps:

```bash
# Emergency: Disable enforcement immediately
sudo ddm-control --mode observe --all-endpoints

# Targeted: Rollback specific endpoint group
ansible-playbook -i inventory/affected-group rollback-ddm.yml

# Manifold: Revert to previous version
cd /etc/ddm
git revert HEAD
ddm-deploy --manifold manifold.conf --all-endpoints

# Complete: Remove DDM entirely
sudo systemctl stop ddm
sudo systemctl disable ddm
sudo ddm-uninstall --purge
```

## Security Considerations

Deployment must address these security concerns. First, protect the manifold repository with access controls, cryptographic signatures, and audit logging. Second, secure resolver infrastructure through network segmentation, TLS encryption, and DDoS protection. Third, implement endpoint hardening with secure boot, measured boot, and tamper detection. Fourth, establish incident response procedures for handling violations, investigating anomalies, and coordinating remediation.

## Conclusion

Successful DDM deployment requires careful planning, phased rollout, and continuous refinement. By following this guide and adapting to organizational needs, you can achieve deterministic DNS security with minimal operational disruption.

## Next Steps

- Review [Architecture Overview](../architecture/overview.md) for system design details
- Consult [Linux eBPF Implementation](../implementation/linux-ebpf.md) for technical specifics
- Explore [Hermetic Resolver Setup](hermetic-resolver.md) for resolver deployment
- Join the community at https://github.com/axiom-hive/ddm/discussions
