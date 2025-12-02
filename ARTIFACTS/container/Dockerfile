# Axiom Hive DDM - Production Docker Container
# Multi-stage build for optimal image size and security

# Stage 1: Build Dependencies
FROM ubuntu:22.04 as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust for daemon building
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . $HOME/.cargo/env && \
    rustup target add x86_64-unknown-linux-musl

# Copy and build eBPF programs
WORKDIR /build/ebpf
COPY ARTIFACTS/ebpf/ddm_dns_filter_v2.c .
COPY ARTIFACTS/ebpf/Makefile .
RUN make clean && make

# Build Rust daemon
WORKDIR /build/daemon
COPY ARTIFACTS/daemon/ddm_daemon.rs .
COPY ARTIFACTS/daemon/Cargo.toml .
COPY ARTIFACTS/daemon/Cargo.lock .
RUN . $HOME/.cargo/env && \
    cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Runtime Environment
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libbpf1 \
    iproute2 \
    netcat \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -r -s /bin/false ddm

# Create necessary directories
RUN mkdir -p /etc/ddm /var/log/ddm /var/backups/ddm /usr/local/bin

# Copy built artifacts from builder stage
COPY --from=builder /build/ebpf/ddm_dns_filter_v2.o /usr/local/bin/
COPY --from=builder /build/daemon/target/x86_64-unknown-linux-musl/release/ddm_daemon /usr/local/bin/axiom-ddm

# Copy configuration files
COPY ARTIFACTS/config/axioms_dns.toml /etc/ddm/
COPY ARTIFACTS/config/manifold.conf /etc/ddm/

# Copy monitoring and setup scripts
COPY ARTIFACTS/scripts/* /usr/local/bin/

# Set proper permissions
RUN chmod +x /usr/local/bin/axiom-ddm && \
    chmod 640 /etc/ddm/* && \
    chown -R ddm:ddm /etc/ddm /var/log/ddm /var/backups/ddm

# Configure capabilities for eBPF operations
# CAP_BPF is required for eBPF operations
# CAP_NET_ADMIN is required for network interface operations
# CAP_SYS_ADMIN is required for certain kernel operations

# Install Prometheus monitoring
RUN curl -L https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz | \
    tar xz && \
    cp node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/ && \
    chmod +x /usr/local/bin/node_exporter

# Health check script
COPY --chmod=755 ARTIFACTS/scripts/healthcheck.sh /usr/local/bin/

# Set up log rotation
RUN mkdir -p /etc/logrotate.d && \
    echo '/var/log/ddm/*.log {' > /etc/logrotate.d/ddm && \
    echo '    daily' >> /etc/logrotate.d/ddm && \
    echo '    missingok' >> /etc/logrotate.d/ddm && \
    echo '    rotate 5' >> /etc/logrotate.d/ddm && \
    echo '    compress' >> /etc/logrotate.d/ddm && \
    echo '    delaycompress' >> /etc/logrotate.d/ddm && \
    echo '    notifempty' >> /etc/logrotate.d/ddm && \
    echo '    copytruncate' >> /etc/logrotate.d/ddm && \
    echo '}' >> /etc/logrotate.d/ddm

# Expose ports
EXPOSE 9090 9100 53/udp

# Set working directory
WORKDIR /app

# Switch to non-root user
USER ddm

# Environment variables
ENV DDM_CONFIG_FILE=/etc/ddm/axioms_dns.toml
ENV DDM_MANIFOLD_FILE=/etc/ddm/manifold.conf
ENV DDM_LOG_LEVEL=info

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh || exit 1

# Default command
CMD ["axiom-ddm", "--config", "/etc/ddm/axioms_dns.toml"]

# Labels for metadata
LABEL org.opencontainers.image.title="Axiom Hive DDM"
LABEL org.opencontainers.image.description="Deterministic DNS Defense Module"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.vendor="Axiom Hive"
LABEL org.opencontainers.image.licenses="GPL-2.0"
LABEL org.opencontainers.image.source="https://github.com/axiom-hive/ddm"