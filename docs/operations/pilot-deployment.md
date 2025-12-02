# Axiom Hive DDM Pilot Deployment Guide

This guide provides the complete setup for the Axiom Hive DDM pilot environment, ensuring hybrid Linux/Windows operation in AUDIT mode from Day 1.

## Pilot Objectives

- **Hybrid Scope**: Simultaneous deployment on Linux (eBPF) and Windows (WFP) platforms
- **AUDIT Mode**: Passive monitoring and logging without traffic blocking
- **CO-RE Compatibility**: eBPF programs compatible across kernel versions 5.10-6.x
- **EV Signing Ready**: Windows components prepared for production code signing

## Component Overview

| Component | Linux Implementation | Windows Implementation | Status |
|-----------|---------------------|------------------------|--------|
| DNS Interception | eBPF XDP/socket filters | WFP callout driver | ✅ Ready |
| Entropy Filtering | Kernel-space fixed-point arithmetic | Kernel-space fixed-point arithmetic | ✅ Ready |
| Manifold Enforcement | Closed DNS state space | Closed DNS state space | ✅ Ready |
| Audit Logging | eBPF perf events | ETW logging | ✅ Ready |

## Deployment Checklist

### Phase 1: Infrastructure Setup
- [ ] **Hardware Simulation**: Run VM setup scripts for kernel matrix
  - Linux: `./scripts/setup-vm-pool.sh`
  - Windows: `.\scripts\Setup-VmPool.ps1`
- [ ] **PTP Configuration**: Set up software PTP for timing simulation
- [ ] **Network Configuration**: Create isolated lab network segments

### Phase 2: Code Preparation
- [ ] **eBPF CO-RE Build**: Verify compilation across kernel versions
  - Run GitHub Actions CI matrix
  - Confirm relocatable bytecode generation
- [ ] **Windows Driver Build**: Set up WDK environment
  - Install Visual Studio + WDK
  - Build test-signed driver
- [ ] **Cross-Platform Testing**: Validate shared manifold logic

### Phase 3: Certificate Acquisition
- [ ] **EV Certificate**: Apply for Extended Validation code signing
  - Choose CA (DigiCert/Sectigo/SSL.com)
  - Complete organization validation
  - Receive hardware token
- [ ] **Development Setup**: Configure signing environment
  - Install token drivers
  - Test signing workflow

### Phase 4: Pilot Deployment
- [ ] **AUDIT Mode Deployment**
  ```bash
  # Linux deployment
  ./scripts/deploy.sh --mode audit --platform linux
  ```
  ```powershell
  # Windows deployment
  .\scripts\Deploy-Ddm.ps1 -Mode Audit -Platform Windows
  ```
- [ ] **Log Aggregation**: Set up centralized logging
- [ ] **Baseline Establishment**: Monitor normal DNS behavior
- [ ] **Validation Testing**: Confirm audit logs without interference

### Phase 5: Microsoft Attestation (Parallel)
- [ ] **Partner Center Setup**: Create Hardware Dev Center account
- [ ] **Driver Submission**: Submit WFP driver for attestation
- [ ] **Attestation Wait**: Allow 1-2 weeks for Microsoft review
- [ ] **Production Signing**: Apply attested signatures

## AUDIT Mode Operations

### Linux Monitoring
```bash
# View eBPF audit logs
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep ddm

# Check program status
sudo bpftool prog show | grep ddm

# Monitor DNS queries
sudo tcpdump -i any port 53 -w dns_audit.pcap
```

### Windows Monitoring
```powershell
# View WFP audit logs
Get-WinEvent -LogName "Microsoft-Windows-WFP/Audit"

# Check driver status
sc query ddm_wfp

# Monitor DNS traffic
Get-NetEventSession | Start-NetEventSession
```

### Hybrid Log Correlation
- Use centralized logging (ELK stack or similar)
- Correlate Linux eBPF events with Windows WFP events
- Establish baseline entropy profiles across platforms

## Risk Mitigation

### Technical Risks
- **Kernel Compatibility**: CI matrix ensures CO-RE compatibility
- **Driver Signing**: EV certificate acquisition in progress
- **Performance Impact**: AUDIT mode minimizes resource usage

### Operational Risks
- **False Positives**: Monitor logs during baseline period
- **Network Disruption**: AUDIT mode prevents blocking
- **Certificate Delays**: Parallel processing with development

## Success Criteria

### Day 1 Readiness
- [ ] All VMs deployed and accessible
- [ ] eBPF programs load successfully across kernel matrix
- [ ] Windows driver builds and loads in test mode
- [ ] Audit logging functional on both platforms
- [ ] No performance degradation observed

### Week 1 Validation
- [ ] Baseline DNS behavior established
- [ ] Cross-platform log correlation working
- [ ] Entropy calculations accurate
- [ ] Manifold enforcement logic validated

### Month 1 Assessment
- [ ] EV certificate received and configured
- [ ] Microsoft attestation completed
- [ ] Production deployment procedures documented
- [ ] Performance benchmarks completed

## Rollback Procedures

### Emergency Stop
```bash
# Linux: Unload eBPF programs
sudo bpftool prog unload id <prog_id>

# Windows: Stop driver service
sc stop ddm_wfp
sc delete ddm_wfp
```

### Clean Removal
```bash
# Linux: Remove pinned maps
sudo rm -rf /sys/fs/bpf/ddm*

# Windows: Uninstall driver
pnputil /delete-driver ddm_wfp.inf /uninstall
```

## Next Steps

1. **Execute Phase 1**: Begin infrastructure setup
2. **Parallel Processing**: Start certificate application alongside development
3. **Daily Standups**: Monitor progress and address blockers
4. **Weekly Reviews**: Assess pilot readiness and adjust timeline
5. **Transition Planning**: Prepare for enforcement mode activation

## Support Resources

- **Documentation**: See `docs/` directory for detailed guides
- **Scripts**: Automated setup in `scripts/` directory
- **CI/CD**: GitHub Actions workflow for automated testing
- **Issues**: Report problems via GitHub Issues

---

**Pilot Status**: Ready for Day 1 deployment in AUDIT mode
**Timeline**: 4-6 weeks to production enforcement capability
**Risk Level**: Low (AUDIT mode, comprehensive testing)