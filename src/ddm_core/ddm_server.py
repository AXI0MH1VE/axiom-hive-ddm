#!/usr/bin/env python3
import socket
import struct
import time
import sys
import os
from typing import Dict, Set, Tuple

# --- Configuration ---
DNS_PORT = 53
MANIFOLD_FILE = os.path.join(os.path.dirname(__file__), 'manifold.txt')
MERKLE_ROOT = "0xDEADBEEFCAFEBABEC0FFEE" # Simulated Merkle Root Hash

# --- Core DDM Logic ---

def load_manifold(file_path: str) -> Set[str]:
    """Loads the authorized domains from the manifold file."""
    try:
        with open(file_path, 'r') as f:
            return {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
    except FileNotFoundError:
        print(f"Error: Manifold file not found at {file_path}", file=sys.stderr)
        return set()

def simulate_merkle_proof(domain: str) -> Tuple[bool, str]:
    """
    Simulates the Proof-of-Resolution layer.
    In a real DDM, this would involve cryptographic verification of a Merkle Proof.
    Here, we simulate success for authorized domains and failure otherwise.
    """
    if domain in MANIFOLD:
        # Simulate a valid proof being generated/verified
        return True, f"Proof-of-Resolution: Verified (Root: {MERKLE_ROOT[:8]}...)"
    else:
        # Simulate proof failure or non-existence
        return False, "Zero Entropy Violation: Unauthorized Domain"

def parse_dns_query(data: bytes) -> Tuple[str, int]:
    """Parses a simple DNS query to extract the domain name."""
    # Transaction ID (2 bytes)
    # Flags (2 bytes)
    # Questions (2 bytes)
    # Answer RRs (2 bytes)
    # Authority RRs (2 bytes)
    # Additional RRs (2 bytes)
    
    # We only care about the question section
    transaction_id = data[:2]
    
    # Extract the question section (starts at byte 12)
    q_data = data[12:]
    
    domain_parts = []
    i = 0
    while i < len(q_data):
        length = q_data[i]
        if length == 0:
            break
        
        part = q_data[i+1:i+1+length].decode('utf-8', errors='ignore')
        domain_parts.append(part)
        i += length + 1
        
    domain = ".".join(domain_parts).lower()
    return domain, transaction_id

def build_dns_response(transaction_id: int, domain: str, is_allowed: bool) -> bytes:
    """Builds a simulated DNS response packet."""
    
    # Header: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    # Flags: 0x8180 (Standard query response, no error)
    # QDCOUNT: 1 (one question)
    # ANCOUNT: 1 (one answer) or 0 (if dropped)
    
    if is_allowed:
        flags = 0x8180
        ancount = 1
        # Simulated IP for allowed domains (e.g., a known safe resolver)
        simulated_ip = b'\x08\x08\x08\x08' # 8.8.8.8
    else:
        # Flags: 0x8183 (Name Error - NXDOMAIN)
        flags = 0x8183
        ancount = 0
        simulated_ip = b''

    header = struct.pack('>HHHHHH', transaction_id, flags, 1, ancount, 0, 0)
    
    # Question section (copy from original query)
    # This is complex to reconstruct perfectly, so we'll use a simplified structure
    # For a full implementation, we'd need the original query's question section
    # For this simulation, we'll skip full response generation for simplicity
    
    # A real implementation would use a library like dnspython.
    # For a complete product simulation, we'll just log the decision and return a minimal response.
    
    # Minimal response for simulation: just the header and the original question
    # This is a simplification and not a valid DNS response, but serves the purpose of logging/filtering.
    return header + b'\x00' # Minimal valid-looking packet (not truly valid)


def run_ddm_server():
    """The main DDM server loop."""
    
    if not MANIFOLD:
        print("DDM Server failed to start: Manifold is empty.", file=sys.stderr)
        return

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_socket.bind(('', DNS_PORT))
        print(f"DDM Server (TITAN-0 Simulation) running on port {DNS_PORT}...")
        print(f"Loaded {len(MANIFOLD)} authorized domains from {MANIFOLD_FILE}")
        print("-" * 50)
        
        while True:
            try:
                data, addr = udp_socket.recvfrom(512)
                domain, transaction_id = parse_dns_query(data)
                
                if not domain:
                    continue
                
                # --- DDM Pipeline: Validate (Merkle Proof) & Execute (Filter) ---
                is_allowed, proof_status = simulate_merkle_proof(domain)
                
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                
                if is_allowed:
                    log_message = f"[{timestamp}] [ALLOWED] {domain:<30} | {proof_status}"
                    print(log_message)
                    # In a real DDM, we would forward the query to the upstream resolver
                    # or return the pre-signed answer.
                    # For simulation, we do nothing further.
                else:
                    log_message = f"[{timestamp}] [DROPPED] {domain:<30} | {proof_status}"
                    print(log_message)
                    # In a real DDM, the packet is dropped or an NXDOMAIN response is sent.
                    # For simulation, we do nothing further.
                    
                # Minimal response to prevent client timeout (not a real DNS answer)
                # response = build_dns_response(transaction_id, domain, is_allowed)
                # udp_socket.sendto(response, addr)
                
            except KeyboardInterrupt:
                print("\nDDM Server shutting down...")
                break
            except Exception as e:
                print(f"An error occurred: {e}", file=sys.stderr)
                
    except PermissionError:
        print(f"Error: Permission denied. Cannot bind to port {DNS_PORT}. Try running with sudo.", file=sys.stderr)
    except Exception as e:
        print(f"Failed to start DDM Server: {e}", file=sys.stderr)
    finally:
        udp_socket.close()

if __name__ == "__main__":
    MANIFOLD = load_manifold(MANIFOLD_FILE)
    run_ddm_server()
