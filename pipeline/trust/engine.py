"""
pipeline/trust/engine.py
========================
Trust Engine Layer: Wraps the existing TrustDriftEngine.

This layer does NOT rewrite the original trust_engine.py logic.
It imports and wraps it for pipeline integration.

Trust evolution follows:
  Decay:    T(t+Δt) = T(t) × exp(−λ × s)     when s ≥ threshold
  Recovery: T(t+Δt) = T(t) + μ × Δt          when s < threshold
"""

from __future__ import annotations

import sys
from pathlib import Path

# Import the existing TrustDriftEngine
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from trust_engine import TrustDriftEngine, Zone, classify_zone

from pipeline.utils.models import TrustOutput, get_timestamp


class TrustLayer:
    """
    Wrapper around TrustDriftEngine for pipeline integration.
    
    Accepts severity scores and maintains per-entity trust evolution.
    Returns trust state snapshots for enforcement layer.
    """
    
    # Trust profiles: λ (decay) and μ (recovery)
    PROFILES = {
        "High": {
            "lambda_": 3.0,
            "mu": 0.01,
            "anomaly_threshold": 0.5,
            "initial_trust": 1.0,
        },
        "Balanced": {
            "lambda_": 1.5,
            "mu": 0.05,
            "anomaly_threshold": 0.5,
            "initial_trust": 1.0,
        },
        "Low": {
            "lambda_": 0.5,
            "mu": 0.10,
            "anomaly_threshold": 0.5,
            "initial_trust": 1.0,
        },
    }
    
    def __init__(self, profile: str = "Balanced"):
        """
        Initialize Trust Layer with profile.
        
        Parameters
        ----------
        profile : str
            Trust profile: "High" (paranoid), "Balanced" (default), "Low" (lenient)
        """
        if profile not in self.PROFILES:
            raise ValueError(f"Unknown profile: {profile}. Choose from {list(self.PROFILES.keys())}")
        
        config = self.PROFILES[profile]
        
        print(f"[TrustLayer] Initializing with profile: {profile}")
        print(f"  lambda (decay):    {config['lambda_']}")
        print(f"  mu (recovery):     {config['mu']}")
        print(f"  threshold:         {config['anomaly_threshold']}")
        
        self.profile = profile
        self.engine = TrustDriftEngine(
            lambda_=config["lambda_"],
            mu=config["mu"],
            anomaly_threshold=config["anomaly_threshold"],
            initial_trust=config["initial_trust"],
        )
    
    def update(self, severity: float, delta_t: float = 1.0) -> TrustOutput:
        """
        Update trust with new severity score.
        
        Parameters
        ----------
        severity : float ∈ [0, 1]
            Severity score from Severity Layer
        delta_t : float
            Time elapsed since last update (seconds)
        
        Returns
        -------
        TrustOutput
            Updated trust state snapshot
        """
        # Use the engine's update_full method to get full state
        state = self.engine.update_full(severity, delta_t)
        
        return TrustOutput(
            trust=state.trust,
            zone=Zone(state.zone.value),
            decayed=state.decayed,
            severity=severity,
            metadata={
                "updated_at": get_timestamp(),
                "profile": self.profile,
                "lambda": self.PROFILES[self.profile]["lambda_"],
                "mu": self.PROFILES[self.profile]["mu"],
                "threshold": self.PROFILES[self.profile]["anomaly_threshold"],
                "zone_name": state.zone.value,
                "action": state.action,
            }
        )
    
    def reset(self) -> None:
        """Reset trust to initial value."""
        self.engine.reset()
        print(f"[TrustLayer] Reset to initial trust: {self.engine.initial_trust}")
    
    def get_trust(self) -> float:
        """Get current trust value."""
        return self.engine.trust
    
    def get_zone(self) -> Zone:
        """Get current enforcement zone."""
        zone_str = self.engine.zone.value
        return Zone(zone_str)
