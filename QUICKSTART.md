# Quick Start Guide

Get started with Axiom Hive DDM in under 10 minutes.

## Prerequisites

- Linux system with kernel 5.8+
- Root/sudo access
- Basic familiarity with command line

## Installation

### 1. Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) build-essential
```

**RHEL/CentOS:**
```bash
sudo yum install -y clang llvm libbpf-devel kernel-devel gcc make
```

### 2. Clone Repository

```bash
git clone https://github.com/axiom-hive/ddm.git
cd ddm
```

### 3. Build

```bash
./scripts/build.sh linux
```

Expected output:
```
[INFO] Checking dependencies...
[INFO] All dependencies satisfied
[INFO] Building Linux eBPF components...
[INFO] Linux build complete
[INFO] Build completed successfully!
```

## Running in Monitor Mode

Start DDM in observation mode (no blocking):

```bash
cd examples/ebpf

# Edit manifold.conf to add your domains
vim manifold.conf

# Start monitoring (requires root)
sudo ./ddm_loader eth0 manifold.conf
```

You should see:
```
Axiom Hive DDM - DNS Defense Module
===================================

BPF object loaded successfully
Attaching to interface: eth0
BPF program attached successfully

Loading manifold from manifold.conf...
  Added: api.example.com (type=exact, entropy_max=0.00)
  Added: *.s3.amazonaws.com (type=wildcard, entropy_max=4.00)
  ...
Loaded 45 manifold entries

Monitoring DNS violations (Ctrl+C to stop)...
```

## Testing

In another terminal, generate some DNS traffic:

```bash
# Legitimate query (in manifold)
dig api.example.com

# Unauthorized query (not in manifold)
dig malicious-domain.xyz
```

You should see violations logged:
```
[2025-12-01 14:30:45] VIOLATION: domain=malicious-domain.xyz reason=not_in_manifold pid=1234 uid=1000 entropy=3.42
```

## Understanding the Output

**Allowed Queries:**
- No output (silent success)
- Counted in statistics

**Blocked Queries:**
- Logged with timestamp, domain, reason, process info
- Reasons:
  - `not_in_manifold`: Domain not authorized
  - `entropy_exceeded`: High-entropy label in wildcard pattern
  - `expired`: Temporal entry expired

## Statistics

Press Ctrl+C to see statistics:

```
=== Statistics ===
Total packets:      1523
Allowed:            1489
Dropped:            34
  Not in manifold:  28
  Entropy exceeded: 6
  Expired:          0
==================
```

## Next Steps

### Enable Enforcement Mode

Once you've verified the manifold is complete:

1. Stop the monitor
2. Update configuration to enable blocking
3. Restart DDM

**Note:** In this example, blocking happens automatically. For production, you'd configure a systemd service.

### Add More Domains

Edit `manifold.conf`:

```bash
# Add exact domain
echo "newapi.example.com,exact,0,0" >> manifold.conf

# Add wildcard with entropy limit
echo "*.cloudfront.net,wildcard,3.8,0" >> manifold.conf

# Add temporary entry (24 hours)
echo "dev-api.example.com,exact,0,86400" >> manifold.conf
```

Reload without restarting (future feature):
```bash
sudo ddm-reload --manifold manifold.conf
```

### View Detailed Logs

```bash
# Real-time monitoring
sudo journalctl -u ddm -f

# Search for specific domain
sudo journalctl -u ddm | grep "example.com"

# Export to file
sudo journalctl -u ddm --since "1 hour ago" > ddm-last-hour.log
```

## Common Issues

### "Failed to open BPF object"

**Cause:** eBPF program not compiled or not found.

**Solution:**
```bash
cd examples/ebpf
make clean && make
```

### "Failed to create TC hook"

**Cause:** Interface name incorrect or insufficient permissions.

**Solution:**
```bash
# List interfaces
ip link show

# Use correct interface name
sudo ./ddm_loader <correct-interface> manifold.conf
```

### "Verifier rejected program"

**Cause:** eBPF program violates kernel safety requirements.

**Solution:**
```bash
# Check kernel version
uname -r  # Should be 5.8+

# View detailed verifier log
sudo dmesg | tail -50
```

## Architecture Overview

```
Application
    │
    ├─> DNS Query: api.example.com
    │
    ▼
[DDM Kernel Shim]
    │
    ├─> Check Manifold: ✓ Found
    ├─> Check Entropy: ✓ OK
    │
    ▼
[Allow] → DNS Resolver → Response
```

## Configuration Reference

### Manifold Format

```
domain,type,entropy_max,ttl
```

**Fields:**
- `domain`: FQDN or wildcard pattern (e.g., `*.example.com`)
- `type`: `exact` or `wildcard`
- `entropy_max`: Maximum Shannon entropy (0 = no limit)
- `ttl`: Time-to-live in seconds (0 = permanent)

**Examples:**
```
# Exact match, no entropy limit, permanent
api.example.com,exact,0,0

# Wildcard, entropy limit 4.0, permanent
*.s3.amazonaws.com,wildcard,4.0,0

# Temporary entry, expires in 24 hours
temp-api.partner.com,exact,0,86400
```

## Performance

Typical overhead per DNS query:
- Manifold lookup: < 10 µs
- Entropy computation: < 50 µs
- Total: < 100 µs

This is negligible compared to network latency (10-100 ms).

## Security Note

**Current Status:** Research/Development Phase

This implementation is for:
- Research and evaluation
- Development environments
- Proof-of-concept deployments

**Not recommended for:**
- Production systems (yet)
- Critical infrastructure
- Compliance-required environments

See [SECURITY.md](SECURITY.md) for details.

## Documentation

- **[README.md](README.md)**: Project overview
- **[Architecture Overview](docs/architecture/overview.md)**: System design
- **[Linux Implementation](docs/implementation/linux-ebpf.md)**: eBPF details
- **[Deployment Guide](docs/operations/deployment.md)**: Production deployment

## Getting Help

- **GitHub Issues**: https://github.com/axiom-hive/ddm/issues
- **Discussions**: https://github.com/axiom-hive/ddm/discussions
- **Documentation**: https://docs.axiom-hive.io/ddm

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

**Happy DNS defending!** 🛡️
