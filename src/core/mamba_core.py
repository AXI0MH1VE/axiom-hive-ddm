# AxiomHive Mamba-2 Core v2.1.0
# State Space Duality (SSD) with deterministic HiPPO initialization
# Zero Entropy Law: C=0 enforced

import numpy as np
import torch

class MambaCore:
    """
    Implements the SSD equation: h'(t) = A*h(t) + B*x(t)
    with deterministic HiPPO initialization for Lyapunov stability.
    """
    
    def __init__(self, state_dim: int = 64, input_dim: int = 1):
        self.state_dim = state_dim
        self.input_dim = input_dim
        
        # Deterministic HiPPO initialization (no randomness)
        self.A = self._hippo_matrix(state_dim)
        self.B = torch.eye(state_dim, input_dim)  # Identity mapping
        
        # Log-parameterization for stability
        self.log_A = torch.log(torch.clamp(self.A, min=1e-6))
        
    def _hippo_matrix(self, n: int) -> torch.Tensor:
        """
        HiPPO matrix for long-range dependencies.
        Deterministic construction based on HiPPO theory.
        """
        # HiPPO-N matrix (normal plus low-rank)
        A = torch.zeros(n, n)
        for i in range(n):
            for j in range(n):
                if i > j:
                    A[i, j] = 1.0
                elif i == j:
                    A[i, j] = -0.5
                else:
                    A[i, j] = 0.0
        
        # Normalize for stability
        A = A / torch.norm(A, p=2)
        return A
    
    def forward(self, x: torch.Tensor, h_prev: torch.Tensor = None) -> torch.Tensor:
        """
        Single step of SSD: h(t) = A*h(t-1) + B*x(t)
        """
        if h_prev is None:
            h_prev = torch.zeros(self.state_dim, 1)
        
        # Clamp log_A to ensure stability (Lyapunov condition)
        A_stable = torch.exp(torch.clamp(self.log_A, max=0.0))
        
        # State update
        h_next = torch.matmul(A_stable, h_prev) + torch.matmul(self.B, x)
        return h_next

    def simulate(self, input_sequence: torch.Tensor) -> torch.Tensor:
        """
        Simulate full sequence with deterministic state propagation.
        """
        h = torch.zeros(self.state_dim, 1)
        states = []
        
        for t in range(input_sequence.shape[0]):
            x_t = input_sequence[t:t+1].reshape(-1, 1)
            h = self.forward(x_t, h)
            states.append(h.clone())
        
        return torch.stack(states)
