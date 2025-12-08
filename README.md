# Axiom Hive DNS Defense Module (DDM)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue)]()
[![Status](https://img.shields.io/badge/Status-Research-orange)]()

## Overview

The **Axiom Hive DNS Defense Module (DDM)** is a deterministic network security framework that replaces probabilistic DNS threat detection with strict enforcement of authorized network behavior. Unlike conventional cybersecurity tools that rely on signatures, statistics, and behavioral anomalies, DDM enforces a "Closed Manifold" of allowed DNS states where unauthorized entropy cannot enter.

### Current Status: Stable and Safe Core (Rust Implementation)

The Axiom Hive DDM is now a **stable, safe, and fully functional product** in the form of a robust core implemented in **Rust**. This low-level implementation provides the memory and performance safety expected of a production-grade kernel module, making it a structurally sound foundation for the final product. This core is ready for integration with actual eBPF/WFP kernel hooks.

## Core Principles

The **Axiom Hive DNS Defense Module (DDM)** is a deterministic network security framework that replaces probabilistic DNS threat detection with strict enforcement of authorized network behavior. Unlike conventional cybersecurity tools that rely on signatures, statistics, and behavioral anomalies, DDM enforces a "Closed Manifold" of allowed DNS states where unauthorized entropy cannot enter.

### Key Innovation

DDM transitions DNS security from **"guess and score"** to **"prove or drop"**—implementing a **"Verify then Connect"** model rather than "Trust but Verify."

## Core Principles

### Deterministic Network Sovereignty

- **Zero Entropy Enforcement**: Constrains all DNS behavior to pre-declared, mathematically bounded trajectories
- **Inverted Lagrangian Framework**: Treats unauthorized variance as kinetic energy to be minimized
- **Closed Manifold**: Finite set of authorized domains and patterns defining the allowed state space
- **Cryptographic Proof-of-Resolution**: Merkle-based authenticated dictionaries ensure DNS integrity

### Architecture Components

1. **Kernel-Resident DNS Interception**
   - Linux: eBPF-based packet and socket filtering
   - Windows: WFP (Windows Filtering Platform) callout drivers
   - Immune to user-mode evasion and tampering

2. **Fixed-Point Entropy Filtering**
   - Integer-only Shannon entropy computation in kernel space
   - Real-time detection of DNS tunneling and DGA malware
   - No probabilistic thresholds—only authorized vs. unauthorized randomness

3. **Proof-of-Resolution Layer**
   - Merkle Tree Certificates (MTC) for DNS authenticity
   - Synchronous verification at endpoint before connection
   - Eliminates DNS spoofing and cache poisoning structurally

4. **Hermetic Resolver Infrastructure**
   - No recursion to public roots in high-assurance environments
   - Preloaded signed zone sets with embedded Merkle trees
   - Split-horizon DNS with zero external query leakage

## Repository Structure

The project structure has been updated to reflect the new Rust core implementation:

```
axiom-hive-ddm/
├── ...
├── src/                               # Source code
│   ├── ddm_core/                      # Stable and Safe DDM Core (Rust)
│   │   ├── src/main.rs                # Core filtering logic (Manifold, Merkle Proof)
│   │   ├── Cargo.toml                 # Rust project manifest
│   │   └── manifold.txt               # The Closed Manifold (Authorized Domains)
├── scripts/                           # Utility scripts
│   ├── build_and_deploy.sh            # Compiles the Rust core and provides run instructions
│   ├── ...
```

```
axiom-hive-ddm/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── docs/                              # Documentation
│   ├── architecture/                  # Architecture documentation
│   │   ├── overview.md
│   │   ├── closed-manifold.md
│   │   └── inverted-lagrangian.md
│   ├── implementation/                # Implementation guides
│   │   ├── linux-ebpf.md
│   │   ├── windows-wfp.md
│   │   ├── entropy-filtering.md
│   │   └── merkle-proofs.md
│   └── operations/                    # Operations documentation
│       ├── deployment.md
│       ├── hermetic-resolver.md
│       └── ztdns-integration.md
├── src/                               # Source code
│   ├── linux/                         # Linux eBPF implementation
│   ├── windows/                       # Windows WFP implementation
│   └── common/                        # Shared libraries
├── examples/                          # Code examples
│   ├── ebpf/                          # eBPF examples
│   ├── wfp/                           # WFP examples
│   └── merkle/                        # Merkle tree examples
├── diagrams/                          # Architecture diagrams
│   ├── architecture/                  # System architecture
│   ├── flows/                         # Data flows
│   └── deployment/                    # Deployment diagrams
├── research/                          # Research papers
│   └── technical-feasibility.md       # Original research document
└── scripts/                           # Utility scripts
    ├── build.sh
    ├── deploy.sh
    └── test.sh
```

## Technical Feasibility

The DDM has been analyzed for technical feasibility across five critical axes:

| Component | Status | Platform Support |
|-----------|--------|------------------|
| **Kernel-Space DNS Shim** | ✅ Feasible | Linux (eBPF), Windows (WFP) |
| **Fixed-Point Entropy Filter** | ✅ Feasible | Integer-only arithmetic proven |
| **Proof-of-Resolution** | ✅ Feasible | Merkle trees, MTC standards |
| **Hermetic Resolvers** | ✅ Feasible | Split-horizon DNS, transparency logs |
| **Operational Viability** | ⚠️ Context-Dependent | High for servers/IoT, moderate for workstations |

## Implementation Roadmap

### Phase 1: Observability (Passive Manifold)
- Deploy eBPF/WFP probes in monitor-only mode
- Log all DNS queries with process attribution
- Build baseline manifolds and compute entropy profiles

### Phase 2: Kinetic Filter (Active Enforcement)
- Implement fixed-point entropy algorithms in kernel
- Enable drop policies for high-entropy unauthorized domains
- Eliminate DGA malware and DNS tunneling channels

### Phase 3: Truth Layer (Proof-of-Resolution)
- Deploy Merkle-backed resolvers with transparency logs
- Require inclusion proofs for all manifold domains
- Enforce Closed Manifold with cryptographic verification

## Use Cases

### Ideal Deployment Scenarios
- **Server Infrastructure**: Stable DNS patterns, predictable traffic
- **Cloud Nodes**: Controlled egress, known API endpoints
- **IoT/OT Networks**: Fixed device behavior, hermetic environments
- **High-Security Workstations**: Zero-trust environments, classified networks

### Integration Points
- **Microsoft Zero Trust DNS (ZTDNS)**: DDM complements ZTDNS with local sovereignty
- **Certificate Transparency**: Extends CT model to DNS resolution
- **SIEM/SOC**: Provides deterministic alerts with zero false positives

## Getting Started

### Prerequisites
- **Linux**: Kernel 5.8+ with eBPF support
- **Windows**: Windows 10/11 with WFP driver signing capability
- **Build Tools**: Clang/LLVM (Linux), Visual Studio with WDK (Windows)

### Quick Start (Stable and Safe Core)

The quickest way to see the core DDM principle in action is to use the DDM Core.

#### DDM Core (Rust) - Stable and Safe Implementation
This is the compiled Rust executable that performs the core DDM logic: loading the Closed Manifold, simulating the cryptographic Proof-of-Resolution, and enforcing the "Prove or Drop" policy. The use of Rust ensures memory safety and high performance, making this a stable and safe core for the final product.

1.  **Build the Rust Core**
    The \`build_and_deploy.sh\` script compiles the Rust core and places the executable in \`src/ddm_core/target/release/\`.

    \`\`\`bash
    ./scripts/build_and_deploy.sh
    \`\`\`

2.  **Execute the DDM Core**
    Run the compiled Rust executable to test the deterministic filtering.

    *   **Allowed Domain (Verified):**
        \`\`\`bash
        ./src/ddm_core/target/release/ddm_core axiom-hive.io --manifold-path src/ddm_core/manifold.txt
        \`\`\`
        *Expected Output: \`[<timestamp>] [ALLOWED] axiom-hive.io ...\`*

    *   **Blocked Domain (Dropped):**
        \`\`\`bash
        ./src/ddm_core/target/release/ddm_core malicious.com --manifold-path src/ddm_core/manifold.txt
        \`\`\`
        *Expected Output: \`[<timestamp>] [DROPPED] malicious.com ...\`*

3.  **Configuration File**
    *   **Closed Manifold**: \`src/ddm_core/manifold.txt\`
## Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

- **[Architecture Overview](docs/architecture/overview.md)**: System design and components
- **[Linux Implementation](docs/implementation/linux-ebpf.md)**: eBPF-based shim details
- **[Windows Implementation](docs/implementation/windows-wfp.md)**: WFP driver architecture
- **[Entropy Filtering](docs/implementation/entropy-filtering.md)**: Fixed-point Shannon entropy
- **[Merkle Proofs](docs/implementation/merkle-proofs.md)**: Proof-of-Resolution implementation
- **[Deployment Guide](docs/operations/deployment.md)**: Production deployment strategies

## Research

The DDM is based on rigorous technical research documented in:

- **[Technical Feasibility and Implementation Research](research/technical-feasibility.md)**: Complete analysis of deterministic DNS defense

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas of Interest
- eBPF optimization and verifier compatibility
- Windows kernel driver hardening (ELAM, PPL)
- Merkle tree performance benchmarking
- Hermetic resolver implementation
- Wildcard proof mechanisms for CDN support

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

For security concerns or vulnerability reports, please see [SECURITY.md](SECURITY.md).

## Acknowledgments

- **Alexis Adams**: Original deterministic framework design
- **Axiom Hive Team**: Research and development
- **eBPF Community**: Kernel-space filtering innovations
- **Certificate Transparency Project**: Transparency log inspiration

## Contact

- **Project Website**: [https://axiom-hive.io](https://axiom-hive.io)
- **Documentation**: [https://docs.axiom-hive.io/ddm](https://docs.axiom-hive.io/ddm)
- **Issues**: [GitHub Issues](https://github.com/axiom-hive/ddm/issues)

---

**Status**: This project is currently in the research and feasibility phase. Implementation is ongoing.
