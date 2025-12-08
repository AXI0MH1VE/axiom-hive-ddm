#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from typing import List, Dict

# --- Merkle Tree Implementation (Simplified) ---

def sha256(data: str) -> str:
    """Computes the SHA256 hash of a string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def build_merkle_tree(leaves: List[str]) -> List[str]:
    """Recursively builds the Merkle tree from a list of leaf hashes."""
    if not leaves:
        return []
    if len(leaves) == 1:
        return leaves
    
    new_level = []
    for i in range(0, len(leaves), 2):
        left = leaves[i]
        right = leaves[i+1] if i + 1 < len(leaves) else left # Handle odd number of leaves
        new_level.append(sha256(left + right))
        
    return build_merkle_tree(new_level)

def generate_mtc(manifold_file: str) -> Dict:
    """Generates the Merkle Tree Certificate (MTC) for the Closed Manifold."""
    try:
        with open(manifold_file, 'r') as f:
            domains = sorted([line.strip().lower() for line in f if line.strip() and not line.startswith('#')])
    except FileNotFoundError:
        print(f"Error: Manifold file not found at {manifold_file}", file=sys.stderr)
        return {}

    if not domains:
        print("Manifold is empty. Cannot generate MTC.", file=sys.stderr)
        return {}

    # 1. Hash the domains (leaves)
    leaf_hashes = [sha256(d) for d in domains]
    
    # 2. Build the tree and get the root
    merkle_root = build_merkle_tree(leaf_hashes)[0]
    
    # 3. Create a simple proof structure (for simulation)
    # In a real system, this would be a complex path of sibling hashes.
    # Here, we just map the domain to its hash and the root.
    proofs = {d: {"hash": sha256(d), "root": merkle_root} for d in domains}
    
    return {
        "merkle_root": merkle_root,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "domain_count": len(domains),
        "proofs": proofs
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: ./mtc_generator.py <manifold_file_path> [output_file_path]", file=sys.stderr)
        sys.exit(1)

    manifold_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "mtc_certificate.json"
    
    mtc = generate_mtc(manifold_file)
    
    if mtc:
        with open(output_file, 'w') as f:
            json.dump(mtc, f, indent=4)
        print(f"Successfully generated Merkle Tree Certificate (MTC) to {output_file}")
        print(f"Merkle Root: {mtc['merkle_root']}")

if __name__ == "__main__":
    import time
    
    # Ensure the script is executable
    if not os.access(sys.argv[0], os.X_OK):
        os.chmod(sys.argv[0], 0o755)
        
    main()
