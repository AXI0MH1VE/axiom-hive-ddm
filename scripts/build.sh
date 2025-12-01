#!/bin/bash
# Axiom Hive DDM - Build Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Check for clang
    if ! command -v clang &> /dev/null; then
        missing_deps+=("clang")
    fi
    
    # Check for gcc
    if ! command -v gcc &> /dev/null; then
        missing_deps+=("gcc")
    fi
    
    # Check for libbpf
    if ! pkg-config --exists libbpf; then
        missing_deps+=("libbpf-dev")
    fi
    
    # Check for kernel headers
    if [ ! -d "/usr/src/linux-headers-$(uname -r)" ]; then
        missing_deps+=("linux-headers-$(uname -r)")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install with: sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi
    
    log_info "All dependencies satisfied"
}

build_linux() {
    log_info "Building Linux eBPF components..."
    
    cd "$PROJECT_ROOT/examples/ebpf"
    
    if [ -f Makefile ]; then
        make clean
        make
        log_info "Linux build complete"
    else
        log_error "Makefile not found in examples/ebpf"
        exit 1
    fi
}

build_windows() {
    log_warn "Windows WFP driver build not yet implemented"
    log_info "Windows build requires:"
    log_info "  - Visual Studio with Windows Driver Kit (WDK)"
    log_info "  - Windows SDK"
    log_info "  - Code signing certificate"
    log_info "Please refer to docs/implementation/windows-wfp.md"
}

build_docs() {
    log_info "Building documentation..."
    
    # Check if we have diagram files to render
    if command -v manus-render-diagram &> /dev/null; then
        log_info "Rendering diagrams..."
        
        for mmd_file in "$PROJECT_ROOT"/diagrams/**/*.mmd; do
            if [ -f "$mmd_file" ]; then
                png_file="${mmd_file%.mmd}.png"
                log_info "Rendering $(basename "$mmd_file")..."
                manus-render-diagram "$mmd_file" "$png_file" || log_warn "Failed to render $mmd_file"
            fi
        done
    else
        log_warn "manus-render-diagram not found, skipping diagram rendering"
    fi
    
    log_info "Documentation build complete"
}

show_usage() {
    cat << EOF
Axiom Hive DDM - Build Script

Usage: $0 [OPTION]

Options:
    linux       Build Linux eBPF components
    windows     Build Windows WFP components (not yet implemented)
    docs        Build documentation and diagrams
    all         Build all components (default)
    clean       Clean build artifacts
    help        Show this help message

Examples:
    $0              # Build all components
    $0 linux        # Build only Linux components
    $0 clean        # Clean all build artifacts

EOF
}

clean_build() {
    log_info "Cleaning build artifacts..."
    
    if [ -d "$PROJECT_ROOT/examples/ebpf" ]; then
        cd "$PROJECT_ROOT/examples/ebpf"
        make clean 2>/dev/null || true
    fi
    
    log_info "Clean complete"
}

# Main
main() {
    local target="${1:-all}"
    
    case "$target" in
        linux)
            check_dependencies
            build_linux
            ;;
        windows)
            build_windows
            ;;
        docs)
            build_docs
            ;;
        all)
            check_dependencies
            build_linux
            build_docs
            ;;
        clean)
            clean_build
            ;;
        help|--help|-h)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown target: $target"
            show_usage
            exit 1
            ;;
    esac
    
    log_info "Build completed successfully!"
}

main "$@"
