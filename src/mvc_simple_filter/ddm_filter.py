#!/usr/bin/env python3
import sys
import os

def load_manifold(file_path):
    """Loads the authorized domains from the manifold file."""
    try:
        with open(file_path, 'r') as f:
            # Filter out comments and empty lines
            domains = {line.strip() for line in f if line.strip() and not line.startswith('#')}
        return domains
    except FileNotFoundError:
        print(f"Error: Manifold file not found at {file_path}", file=sys.stderr)
        sys.exit(1)

def check_domain(domain, manifold):
    """Simulates the DDM's 'Prove or Drop' logic."""
    if domain in manifold:
        print(f"[{domain}] -> ALLOWED (Proof-of-Resolution: Verified)")
        return 0
    else:
        print(f"[{domain}] -> DROPPED (Zero Entropy Violation: Unauthorized Domain)")
        return 1

def main():
    if len(sys.argv) < 2:
        print("Usage: ./ddm_filter.py <domain_name>", file=sys.stderr)
        sys.exit(1)

    # Determine the path to the manifold.txt relative to the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    manifold_path = os.path.join(script_dir, 'manifold.txt')

    domain_to_check = sys.argv[1].lower()
    manifold = load_manifold(manifold_path)

    sys.exit(check_domain(domain_to_check, manifold))

if __name__ == "__main__":
    main()
