#!/bin/bash

# DDM Build and Deployment Script
# This script simulates the full build and deployment process for the Axiom Hive DDM.

set -e

PROJECT_ROOT=$(dirname "$0")/..
MTC_FILE="$PROJECT_ROOT/src/ddm_core/mtc_certificate.json"
MANIFOLD_FILE="$PROJECT_ROOT/src/ddm_core/manifold.txt"
SERVER_SCRIPT="$PROJECT_ROOT/src/ddm_core/ddm_server.py"
MTC_GENERATOR="$PROJECT_ROOT/src/ddm_core/mtc_generator.py"

echo "--- Axiom Hive DDM Full Product Build and Deployment ---"

# 1. Validation and Setup
echo "1. Validating environment..."
if ! command -v python3 &> /dev/null
then
    echo "Error: python3 is required but not installed."
    exit 1
fi
echo "Environment validated. Python3 found."

# 2. Commit Phase: Generate Merkle Tree Certificate (MTC)
echo "2. Generating Merkle Tree Certificate (MTC) for the Closed Manifold..."
"$MTC_GENERATOR" "$MANIFOLD_FILE" "$MTC_FILE"

if [ ! -f "$MTC_FILE" ]; then
    echo "Error: MTC file generation failed."
    exit 1
fi

MERKLE_ROOT=$(grep "merkle_root" "$MTC_FILE" | awk -F'"' '{print $4}')
echo "Commit successful. Merkle Root: $MERKLE_ROOT"

# 3. Build Phase (Simulated)
echo "3. Simulating Kernel Module Build (eBPF/WFP)..."
# In a real scenario, this would compile the C/Rust code for the kernel modules.
# For this simulation, we ensure the Python server is executable.
chmod +x "$SERVER_SCRIPT"
echo "Build simulation complete. User-space server is executable."

# 4. Deployment Phase
echo "4. Deploying DDM Server (TITAN-0 Simulation)..."
echo "To run the DDM server, execute the following command (requires sudo to bind to port 53):"
echo "sudo $SERVER_SCRIPT"
echo ""
echo "To test the DDM, you can use 'dig' or 'nslookup' against 127.0.0.1:"
echo "  Allowed: dig @127.0.0.1 axiom-hive.io"
echo "  Dropped: dig @127.0.0.1 malicious.com"
echo ""
echo "--- Deployment Complete ---"
echo "The DDM is ready to be run. Please execute the server command manually."
