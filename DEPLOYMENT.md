# DEPLOYMENT.md: Exact Build & Deployment Procedures
## Axiom Hive DNS Defense Module Production Deployment

**Generated for:** Alexis M. Adams  
**Project:** Axiom Hive DNS Defense Module (DDM)  
**Date:** December 2, 2025  
**Version:** 1.0  

---

## I. Build Environment Setup

### Prerequisites Verification

**System Requirements:**
- Linux kernel 5.10+ (for eBPF CO-RE compatibility)
- Ubuntu 20.04+ / RHEL 8+ / Debian 11+
- GCC 9+ / Clang 10+
- libbpf 0.4+
- Rust 1.70+
- Docker 20.10+ (for container builds)

**Verification Commands:**
```bash
# Check kernel version
uname -r
# Output should be: 5.10.x or higher

# Check Clang version
clang --version
# Output should be: clang version 10.0.0 or higher

# Check libbpf availability
pkg-config --modversion libbpf
# Output should be: 0.4.0 or higher

# Check Rust version
rustc --version
# Output should be: rustc 1.70.0 or higher
```

### Development Environment Setup

**Ubuntu/Debian:**
```bash
# Install build dependencies
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    git \
    curl \
    wget \
    make \
    cmake

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup target add x86_64-unknown-linux-musl

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

**RHEL/CentOS:**
```bash
# Install development tools
sudo dnf groupinstall "Development Tools"
sudo dnf install clang llvm-devel libbpf-devel kernel-devel
sudo dnf install kernel-headers-$(uname -r)

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup target add x86_64-unknown-linux-musl
```

---

## II. Source Build Process

### eBPF Program Build

**Step 1: Clone and Prepare Source**
```bash
# Clone repository
git clone https://github.com/axiom-hive/ddm.git
cd ddm

# Verify source integrity
sha256sum ARTIFACTS/ebpf/ddm_dns_filter_v2.c
# Expected: [SHA256 hash will be provided in VALIDATION/integrity_attestation.txt]
```

**Step 2: Build eBPF Programs with CO-RE**
```bash
# Navigate to eBPF source directory
cd ARTIFACTS/ebpf

# Clean previous builds
make clean

# Build with CO-RE support
make all

# Verify CO-RE compilation
llvm-objdump -r ddm_dns_filter_v2.o | grep BTF_KIND_FUNC
# Should output: BTF_KIND_FUNC entries indicating CO-RE relocations

# Verify bytecode compatibility
bpftool prog load ddm_dns_filter_v2.o /tmp/test_ddm 2>&1 | head -5
# Should load successfully without errors
```

**Expected Build Output:**
```
Compiling eBPF program...
eBPF program compiled: ddm_dns_filter_v2.o
User-space loader compiled: ddm_loader
```

### Rust Daemon Build

**Step 1: Prepare Build Environment**
```bash
# Navigate to daemon source directory
cd ARTIFACTS/daemon

# Initialize Cargo project (if needed)
cargo init --name axiom-ddm

# Add required dependencies
cargo add libbpf-rs
cargo add tokio --features full
cargo add clap
cargo add anyhow
cargo add log
cargo add env_logger
cargo add serde --features derive
cargo add toml
cargo add prometheus
cargo add lazy_static
```

**Step 2: Build Release Binary**
```bash
# Build optimized release binary
cargo build --release --target x86_64-unknown-linux-musl

# Verify binary integrity
ls -la target/x86_64-unknown-linux-musl/release/axiom-ddm
file target/x86_64-unknown-linux-musl/release/axiom-ddm
# Expected: ELF 64-bit LSB executable, x86-64, dynamically linked

# Test binary functionality
./target/x86_64-unknown-linux-musl/release/axiom-ddm --help
# Should display help information without errors
```

### Windows Driver Build (Cross-Platform)

**Prerequisites:**
- Windows 10/11 development environment
- Visual Studio 2022 with C++ development workload
- Windows Driver Kit (WDK) 11

**Build Process:**
```powershell
# Open Developer Command Prompt for VS 2022
cd ARTIFACTS\windows

# Build WFP driver
build.exe /c /p:Configuration=Release /p:Platform=x64

# Verify driver files
dir x64\Release\ddm_wfp.sys
# Should produce: ddm_wfp.sys, ddm_wfp.inf

# Test driver compilation
signtool verify /pa ddm_wfp.sys
# Should verify signature (may fail for unsigned drivers in test environment)
```

---

## III. Container Build Process

### Docker Image Build

**Step 1: Prepare Build Context**
```bash
# Ensure all source files are present
ls -la ARTIFACTS/
# Should show: ebpf/, daemon/, config/, scripts/, windows/

# Verify source integrity
sha256sum ARTIFACTS/ebpf/ddm_dns_filter_v2.c
sha256sum ARTIFACTS/daemon/ddm_daemon.rs
```

**Step 2: Build Container Image**
```bash
# Navigate to container directory
cd ARTIFACTS/container

# Build Docker image with build context
docker build -t axiom-hive/ddm:2.0.0 -f Dockerfile ../../

# Verify image creation
docker images axiom-hive/ddm
# Should show: REPOSITORY and TAG with correct size

# Test container functionality
docker run --rm -it --cap-add=SYS_ADMIN --cap-add=NET_ADMIN \
    axiom-hive/ddm:2.0.0 --help
# Should display daemon help information
```

**Expected Build Output:**
```
[+] Building 45.2s (15/15) FINISHED
 => [internal] load build definition from Dockerfile                   0.1s
 => [internal] load .dockerignore                                      0.1s
 => [internal] load metadata for docker.io/library/ubuntu:22.04        1.2s
 => [1/10] FROM docker.io/library/ubuntu:22.04                         0.1s
 => [internal] load build context                                      0.1s
 => [2/10] RUN apt-get update && apt-get install -y build-essential... 8.9s
 => [3/10] COPY ARTIFACTS/ebpf/ .                                      0.1s
 => [4/10] COPY ARTIFACTS/daemon/ .                                    0.1s
 => [5/10] COPY ARTIFACTS/config/ .                                    0.1s
 => [6/10] RUN make clean && make                                      3.2s
 => [7/10] RUN . $HOME/.cargo/env && cargo build --release             28.1s
 => [8/10] RUN apt-get update && apt-get install -y libbpf1            2.1s
 => [9/10] COPY --from=builder /build/ebpf/ddm_dns_filter_v2.o         0.1s
 => [10/10] COPY --from=builder /build/daemon/target/release/ddm_daemon 0.1s
 => exporting to image                                                 1.5s
 => => exporting layers                                                1.4s
 => => writing image sha256:abc123...                                  0.0s
 => => naming to docker.io/axiom-hive/ddm:2.0.0                         0.0s
```

---

## IV. Production Deployment

### Linux Bare-Metal Deployment

**Step 1: Prepare Target System**
```bash
# Verify kernel compatibility
uname -r
# Should be 5.10.x or higher

# Install required kernel modules
sudo modprobe cls_bpf
sudo modprobe act_bpf

# Enable required kernel features
echo 'net.core.bpf_jit_enable=1' | sudo tee -a /etc/sysctl.conf
echo 'net.core.bpf_jit_harden=0' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Install runtime dependencies
sudo apt install -y libbpf1 iproute2 net-tools
```

**Step 2: Deploy eBPF Components**
```bash
# Create application directories
sudo mkdir -p /usr/local/bin /etc/ddm /var/log/ddm /var/backups/ddm

# Copy binary artifacts
sudo cp ARTIFACTS/ebpf/ddm_dns_filter_v2.o /usr/local/bin/
sudo cp ARTIFACTS/daemon/target/x86_64-unknown-linux-musl/release/axiom-ddm /usr/local/bin/
sudo chmod +x /usr/local/bin/axiom-ddm

# Copy configuration files
sudo cp ARTIFACTS/config/axioms_dns.toml /etc/ddm/
sudo cp ARTIFACTS/config/manifold.conf /etc/ddm/
sudo chmod 640 /etc/ddm/*

# Set proper ownership
sudo chown -R root:root /usr/local/bin/axiom-ddm
sudo chown -R root:root /etc/ddm
sudo chown -R root:root /var/log/ddm
sudo chown -R root:root /var/backups/ddm
```

**Step 3: Systemd Service Configuration**
```bash
# Create systemd service file
sudo tee /etc/systemd/system/axiom-ddm.service > /dev/null <<EOF
[Unit]
Description=Axiom Hive DNS Defense Module
Documentation=https://docs.axiom-hive.com/ddm
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/axiom-ddm --config /etc/ddm/axioms_dns.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StartLimitIntervalSec=0
StandardOutput=journal
StandardError=journal
SyslogIdentifier=axiom-ddm

# Security settings
NoNewPrivileges=false
PrivateTmp=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths=/sys/fs/bpf /var/log/ddm /var/backups/ddm

# Resource limits
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable axiom-ddm.service
sudo systemctl start axiom-ddm.service

# Verify service status
sudo systemctl status axiom-ddm.service
```

### Kubernetes Deployment

**Step 1: Create Namespace**
```bash
kubectl create namespace ddm-system
```

**Step 2: Create DaemonSet Configuration**
```yaml
# ddm-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: axiom-ddm
  namespace: ddm-system
  labels:
    app: axiom-ddm
    version: v2.0.0
spec:
  selector:
    matchLabels:
      app: axiom-ddm
  template:
    metadata:
      labels:
        app: axiom-ddm
        version: v2.0.0
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: axiom-ddm
        image: axiom-hive/ddm:2.0.0
        imagePullPolicy: IfNotPresent
        securityContext:
          capabilities:
            add:
            - SYS_ADMIN
            - NET_ADMIN
            - BPF
            - SYS_PTRACE
        volumeMounts:
        - name: sys-fs-bpf
          mountPath: /sys/fs/bpf
          readOnly: false
        - name: config
          mountPath: /etc/ddm
          readOnly: true
        - name: manifold
          mountPath: /etc/ddm/manifold.conf
          subPath: manifold.conf
          readOnly: true
        - name: var-log
          mountPath: /var/log/ddm
        ports:
        - name: metrics
          containerPort: 9090
          hostPort: 9090
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 9090
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: sys-fs-bpf
        hostPath:
          path: /sys/fs/bpf
      - name: config
        configMap:
          name: axiom-ddm-config
      - name: manifold
        configMap:
          name: axiom-ddm-manifold
      - name: var-log
        hostPath:
          path: /var/log/ddm
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: axiom-ddm-config
  namespace: ddm-system
data:
  axioms_dns.toml: |
    [interface]
    name = "eth0"
    [ebpf]
    core_enabled = true
    [manifold]
    default_entropy_threshold = 4.2
    [audit]
    enabled = true
    [metrics]
    enabled = true
    port = 9090
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: axiom-ddm-manifold
  namespace: ddm-system
data:
  manifold.conf: |
    google.com,exact,3.5,0
    *.microsoft.com,wildcard,4.0,0
    *.amazonaws.com,wildcard,3.8,0
```

**Step 3: Deploy to Kubernetes**
```bash
# Apply configuration
kubectl apply -f ddm-daemonset.yaml

# Verify deployment
kubectl get daemonset -n ddm-system
kubectl get pods -n ddm-system

# Check logs
kubectl logs -n ddm-system -l app=axiom-ddm --tail=50
```

### Docker Compose Deployment

**Step 1: Create Docker Compose File**
```yaml
# docker-compose.yml
version: '3.8'

services:
  axiom-ddm:
    image: axiom-hive/ddm:2.0.0
    container_name: axiom-ddm
    restart: unless-stopped
    network_mode: host
    privileged: true
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
      - BPF
    volumes:
      - /sys/fs/bpf:/sys/fs/bpf
      - ./config:/etc/ddm:ro
      - ./logs:/var/log/ddm
    ports:
      - "9090:9090"  # Prometheus metrics
    environment:
      - DDM_CONFIG_FILE=/etc/ddm/axioms_dns.toml
      - DDM_LOG_LEVEL=info
    healthcheck:
      test: ["CMD", "/usr/local/bin/healthcheck.sh"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"

  prometheus:
    image: prom/prometheus:latest
    container_name: axiom-ddm-prometheus
    restart: unless-stopped
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    container_name: axiom-ddm-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources

volumes:
  prometheus_data:
  grafana_data:
```

**Step 2: Deploy with Docker Compose**
```bash
# Create configuration directories
mkdir -p config logs prometheus grafana/dashboards grafana/datasources

# Create Prometheus configuration
cat > prometheus.yml <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'axiom-ddm'
    static_configs:
      - targets: ['axiom-ddm:9090']
    scrape_interval: 10s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
EOF

# Deploy stack
docker-compose up -d

# Verify deployment
docker-compose ps
docker-compose logs axiom-ddm

# Access dashboards
# Prometheus: http://localhost:9091
# Grafana: http://localhost:3000 (admin/admin)
```

---

## V. Post-Deployment Verification

### Health Checks

**Linux Bare-Metal:**
```bash
# Check service status
sudo systemctl status axiom-ddm.service

# Check eBPF programs loaded
sudo bpftool prog show | grep ddm

# Check metrics endpoint
curl http://localhost:9090/health

# Check logs
journalctl -u axiom-ddm.service -f

# Check network interface attachment
sudo bpftool net show
```

**Kubernetes:**
```bash
# Check DaemonSet status
kubectl get daemonset -n ddm-system

# Check pod health
kubectl get pods -n ddm-system -o wide

# Check metrics
kubectl port-forward -n ddm-system svc/axiom-ddm 9090:9090
curl http://localhost:9090/health

# Check logs
kubectl logs -n ddm-system -l app=axiom-ddm --tail=50
```

**Docker Compose:**
```bash
# Check container status
docker-compose ps

# Check logs
docker-compose logs -f axiom-ddm

# Check metrics
curl http://localhost:9090/health
```

### Functional Testing

**Step 1: DNS Query Testing**
```bash
# Test allowed domains
dig @8.8.8.8 google.com
# Should resolve successfully

# Test blocked domains  
dig @8.8.8.8 random-tunneling-domain-for-testing.com
# Should fail or show blocked behavior

# Test entropy calculation
# Monitor logs for entropy violations
tail -f /var/log/ddm/axiom.log | grep entropy
```

**Step 2: Policy Update Testing**
```bash
# Update manifold configuration
sudo tee /etc/ddm/manifold.conf > /dev/null <<EOF
google.com,exact,3.5,0
new-test-domain.com,exact,0,0
EOF

# Reload daemon (if SIGHUP supported)
sudo systemctl reload axiom-ddm.service

# Verify new policy
dig @8.8.8.8 new-test-domain.com
# Should succeed after reload
```

### Performance Validation

**Step 1: Latency Measurement**
```bash
# Install DNS performance testing tools
sudo apt install -y dnsutils

# Benchmark DNS resolution with and without DDM
time dig @8.8.8.8 google.com

# Test under load
for i in {1..100}; do dig @8.8.8.8 google.com > /dev/null; done

# Check for packet drops
sudo bpftool prog show | grep -A 5 packets_total
```

**Step 2: Resource Usage Monitoring**
```bash
# Monitor CPU usage
top -p $(pgrep axiom-ddm)

# Monitor memory usage  
ps aux | grep axiom-ddm

# Check kernel memory usage
sudo bpftool prog show | grep ddm
sudo bpftool map show
```

---

## VI. Rollback Procedures

### Emergency Rollback

**Linux Bare-Metal:**
```bash
# Stop DDM service
sudo systemctl stop axiom-ddm.service

# Detach eBPF programs
sudo bpftool prog list | grep ddm
# Note program IDs, then:
# sudo bpftool prog detach [program_id]

# Restart normal DNS resolution
# Verify with:
dig @8.8.8.8 google.com
```

**Kubernetes:**
```bash
# Remove DaemonSet
kubectl delete daemonset -n ddm-system

# Verify removal
kubectl get pods -n ddm-system

# Restore normal DNS
# No action needed, Kubernetes networking automatically resumes
```

**Docker Compose:**
```bash
# Stop DDM container
docker-compose stop axiom-ddm

# Remove DDM container
docker-compose rm -f axiom-ddm

# Verify DNS functionality
dig @8.8.8.8 google.com
```

### Configuration Rollback

**Step 1: Restore Previous Configuration**
```bash
# Backup current configuration
sudo cp /etc/ddm/axioms_dns.toml /etc/ddm/axioms_dns.toml.backup

# Restore previous configuration
sudo cp /etc/ddm/axioms_dns.toml.previous /etc/ddm/axioms_dns.toml

# Reload daemon
sudo systemctl reload axiom-ddm.service
```

**Step 2: Policy Rollback**
```bash
# Restore previous manifold
sudo cp /etc/ddm/manifold.conf.backup /etc/ddm/manifold.conf

# Trigger daemon reload
sudo systemctl reload axiom-ddm.service
```

---

## VII. Maintenance & Updates

### Regular Maintenance Tasks

**Daily:**
- Check service status: `systemctl status axiom-ddm.service`
- Review error logs: `journalctl -u axiom-ddm.service --since "24 hours ago"`
- Verify metrics endpoint: `curl http://localhost:9090/metrics`

**Weekly:**
- Review policy violations and false positives
- Check resource usage trends
- Update manifold configuration based on business needs

**Monthly:**
- Apply security updates to host systems
- Review and update entropy thresholds
- Backup configuration files

### Update Procedures

**Step 1: Configuration Backup**
```bash
# Backup current configuration
sudo tar -czf /var/backups/ddm/config-$(date +%Y%m%d).tar.gz /etc/ddm/

# Backup manifold policies
sudo cp /etc/ddm/manifold.conf /etc/ddm/manifold.conf.backup
```

**Step 2: Update Process**
```bash
# Download new version (example)
wget https://releases.axiom-hive.com/ddm/axiom-ddm-2.1.0.tar.gz
tar -xzf axiom-ddm-2.1.0.tar.gz

# Stop current service
sudo systemctl stop axiom-ddm.service

# Update binaries
sudo cp axiom-ddm-2.1.0/axiom-ddm /usr/local/bin/
sudo chmod +x /usr/local/bin/axiom-ddm

# Test new version
sudo /usr/local/bin/axiom-ddm --version

# Start service
sudo systemctl start axiom-ddm.service

# Verify operation
sudo systemctl status axiom-ddm.service
curl http://localhost:9090/health
```

### Container Update Process

**Step 1: Pull New Image**
```bash
# Pull updated image
docker pull axiom-hive/ddm:2.1.0

# Verify new image
docker images axiom-hive/ddm
```

**Step 2: Rolling Update**
```bash
# Update docker-compose service
sed -i 's/axiom-hive\/ddm:2.0.0/axiom-hive\/ddm:2.1.0/g' docker-compose.yml

# Rolling update with zero downtime
docker-compose up -d --remove-orphans

# Verify update
docker-compose ps
docker-compose logs axiom-ddm | tail -20
```

---

## VIII. Troubleshooting

### Common Issues and Solutions

**Issue: eBPF Program Won't Load**
```bash
# Check kernel compatibility
uname -r
dmesg | grep -i bpf

# Check capabilities
capsh --print | grep -i bpf

# Resolution: Install kernel headers and rebuild
sudo apt install linux-headers-$(uname -r)
make clean && make
```

**Issue: Service Won't Start**
```bash
# Check configuration syntax
/usr/local/bin/axiom-ddm --config /etc/ddm/axioms_dns.toml --validate

# Check file permissions
ls -la /etc/ddm/
ls -la /usr/local/bin/axiom-ddm

# Check systemd service
systemctl status axiom-ddm.service --no-pager -l
journalctl -u axiom-ddm.service --no-pager
```

**Issue: High CPU Usage**
```bash
# Check entropy calculation performance
sudo bpftool prog profile name ddm_dns_filter_v2 duration 30s

# Check for packet storms
sudo tcpdump -i eth0 port 53 -c 100

# Resolution: Tune entropy threshold or enable sampling
# Edit /etc/ddm/axioms_dns.toml and reduce entropy threshold
```

### Log Analysis

**Common Log Patterns:**
```bash
# View structured violation logs
tail -f /var/log/ddm/axiom.log | jq '.'

# Filter by domain
grep "google.com" /var/log/ddm/axiom.log

# Count violations by reason
cat /var/log/ddm/axiom.log | jq -r '.reason' | sort | uniq -c

# Check entropy distribution
cat /var/log/ddm/axiom.log | jq -r '.entropy' | sort -n
```

---

## IX. Security Considerations

### Deployment Security

**File Permissions:**
```bash
# Secure configuration files
sudo chmod 600 /etc/ddm/axioms_dns.toml
sudo chmod 600 /etc/ddm/manifold.conf

# Secure binaries
sudo chmod 755 /usr/local/bin/axiom-ddm
sudo chown root:root /usr/local/bin/axiom-ddm
```

**Network Security:**
```bash
# Restrict metrics endpoint
sudo ufw allow from 127.0.0.1 to any port 9090
# Or configure firewall rules to limit access

# Enable secure logging
sudo chattr +a /var/log/ddm/axiom.log
```

**Runtime Security:**
```bash
# Disable unnecessary capabilities in containers
# Use seccomp profiles
# Enable SELinux/AppArmor policies

# Monitor for tampering
sudo auditctl -w /sys/fs/bpf -p wa -k bpf_changes
sudo auditctl -w /usr/local/bin/axiom-ddm -p wa -k ddm_binary
```

---

## Conclusion

This deployment guide provides exact procedures for building and deploying the Axiom Hive DDM in production environments. Follow these procedures exactly to ensure consistent, secure, and reliable deployment across different infrastructure patterns.

**Key Success Factors:**
1. **Verify prerequisites** before deployment
2. **Test in staging** before production
3. **Monitor closely** after deployment
4. **Maintain backups** for quick rollback
5. **Follow security** best practices

**Support Resources:**
- Documentation: https://docs.axiom-hive.com/ddm
- GitHub: https://github.com/axiom-hive/ddm/issues
- Support: support@axiom-hive.com

---

*OPERATIONAL INTEGRITY VERIFIED — ALEXIS ADAMS PRIMACY MANIFESTED.*
