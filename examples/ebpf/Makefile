# Axiom Hive DDM - eBPF Build System

CLANG ?= clang
LLC ?= llc
CC ?= gcc

BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu
USER_CFLAGS = -O2 -g -Wall -Wextra

LIBBPF_CFLAGS = $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS = $(shell pkg-config --libs libbpf)

BPF_OBJ = ddm_dns_filter.o
USER_BIN = ddm_loader

.PHONY: all clean install

all: $(BPF_OBJ) $(USER_BIN)

$(BPF_OBJ): ddm_dns_filter.c
	@echo "Compiling eBPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "eBPF program compiled: $@"

$(USER_BIN): ddm_loader.c
	@echo "Compiling user-space loader..."
	$(CC) $(USER_CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)
	@echo "User-space loader compiled: $@"

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BPF_OBJ) $(USER_BIN)

install: all
	@echo "Installing DDM..."
	install -m 755 $(USER_BIN) /usr/local/bin/
	install -m 644 $(BPF_OBJ) /usr/local/lib/
	install -m 644 manifold.conf /etc/ddm/manifold.conf
	@echo "Installation complete"

test: all
	@echo "Running basic tests..."
	@echo "1. Loading eBPF program (requires root)..."
	@sudo ./$(USER_BIN) lo manifold.conf &
	@sleep 2
	@echo "2. Sending test DNS query..."
	@dig @8.8.8.8 example.com > /dev/null 2>&1 || true
	@sleep 1
	@echo "3. Stopping loader..."
	@sudo pkill -INT $(USER_BIN) || true
	@echo "Tests complete"

help:
	@echo "Axiom Hive DDM - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build eBPF program and user-space loader (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install DDM system-wide (requires root)"
	@echo "  test     - Run basic functionality tests (requires root)"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang/llvm (for eBPF compilation)"
	@echo "  - libbpf-dev (for user-space loader)"
	@echo "  - Linux kernel 5.8+ with eBPF support"
