# Lab Environment Setup for Axiom Hive DDM Pilot

This document outlines the setup of the lab environment for the Axiom Hive DDM pilot, including hardware simulation, CI matrix, and EV code signing configuration.

## Hardware Setup

### Lab Server Simulation

The lab environment simulates a high-performance server with 25G NIC capabilities and PTP support for precise timing.

#### Requirements

- Host machine with virtualization support (Intel VT-x/AMD-V)
- Minimum 32GB RAM, 500GB SSD storage
- Linux host (Ubuntu 22.04+ recommended) or Windows 11 with Hyper-V

#### Simulated Components

- **25G NIC**: Simulated using virtual NICs with high throughput configuration
- **PTP Switch**: Software PTP implementation using ptp4l and chrony
- **VM Pool**: Kernel matrix VMs for testing across Linux 5.10-6.x

### VM Pool Setup

Create a pool of VMs for kernel matrix testing:

```bash
# Linux setup script (run on Linux host)
./scripts/setup-vm-pool.sh
```

```powershell
# Windows setup script (run on Windows host)
.\scripts\Setup-VmPool.ps1
```

#### Kernel Versions

- Ubuntu 20.04 (Kernel 5.10)
- Ubuntu 21.10 (Kernel 5.15)
- Ubuntu 22.04 (Kernel 6.1)
- Ubuntu 24.04 (Kernel 6.6)

### PTP Configuration

For software PTP simulation:

```bash
# Install PTP tools
sudo apt update
sudo apt install linuxptp chrony

# Configure PTP
sudo ptp4l -i eth0 -m
sudo phc2sys -s eth0 -c CLOCK_REALTIME -O 0
```

## CI Matrix

### CO-RE eBPF Implementation

eBPF programs use Compile Once - Run Everywhere (CO-RE) for compatibility across kernel versions 5.10-6.x.

#### Build Configuration

- Compiler: clang -target bpf
- Relocatable bytecode generation
- Automated testing via GitHub Actions

### GitHub Actions Workflow

See `.github/workflows/ci.yml` for the complete CI configuration.

### Key features

- Matrix testing across kernels 5.10, 5.15, 6.1, 6.6
- CO-RE compilation verification
- Automated deployment to test VMs

## EV Code Signing

### Certificate Acquisition

1. Choose a CA: DigiCert, Sectigo, or SSL.com
2. Apply for Extended Validation (EV) code signing certificate
3. Provide organization details for validation
4. Receive token-based certificate

### Windows WFP Driver Signing

#### Prerequisites

- Windows 10/11 development environment
- Windows Driver Kit (WDK)
- EV token and certificate

#### Configuration Steps

1. Install certificate on development machine
2. Configure driver project for signing
3. Submit to Microsoft Hardware Dev Center for attestation

#### Submission Process

```powershell
# Sign driver with EV certificate
signtool sign /v /fd sha256 /t http://timestamp.digicert.com /f "path\to\cert.pfx" /p "password" driver.sys

# Submit for attestation (requires Microsoft account)
# Access: https://partner.microsoft.com/en-us/dashboard/hardware
```

### Audit Mode Deployment

All components are configured for AUDIT mode by default:

- eBPF programs load in monitor-only mode
- WFP drivers log violations without blocking
- PTP operates in slave mode for synchronization

Enable enforcement mode after validation:

```bash
# Linux: Enable enforcement
sudo bpftool prog load ddm_filter.o /sys/fs/bpf/ddm_filter --pin-maps

# Windows: Enable blocking
# Modify WFP policy to FWP_ACTION_BLOCK
```

## Hybrid Scope Alignment

- **Linux**: eBPF CO-RE programs for kernel-space filtering
- **Windows**: WFP callout drivers with EV signing
- **Cross-platform**: Shared manifold configuration and entropy algorithms

## AUDIT Mode Configuration

All DDM components are deployed in AUDIT mode by default for the pilot phase:

### Linux eBPF Programs

```bash
# Load eBPF programs in audit mode (no blocking)
sudo bpftool prog load ddm_dns_filter.o /sys/fs/bpf/ddm_filter --pin-maps
sudo bpftool map update pinned /sys/fs/bpf/ddm_config audit_mode 1

# Monitor logs
sudo bpftool prog trace log | grep ddm
```

### Windows WFP Driver

```powershell
# Install driver in audit mode
pnputil /add-driver ddm_wfp.inf /install

# Configure audit-only filtering
# Set WFP policy to FWP_ACTION_PERMIT with logging
```

### Hybrid Operation

- **Linux**: eBPF programs log DNS queries without blocking
- **Windows**: WFP driver monitors traffic and logs violations
- **Cross-platform**: Shared manifold configuration ensures consistent audit behavior

## Quick Setup

1. Clone repository
2. Run hardware setup script for your platform
3. Configure CI workflow in GitHub
4. Acquire EV certificate for Windows components
5. Deploy in AUDIT mode for testing

6. Monitor logs and validate behavior before enabling enforcement