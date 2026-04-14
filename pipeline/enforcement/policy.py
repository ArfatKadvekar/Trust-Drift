"""
pipeline/enforcement/policy.py
==============================
Enforcement Layer: Maps trust level → enforcement action.

Trust → Zone → Action mapping:
  Zone A (T > 0.8):       Allow (full access)
  Zone B (0.4 < T ≤ 0.8): Throttle + MFA
  Zone C (T ≤ 0.4):       Block + Quarantine
"""

from __future__ import annotations

from pipeline.utils.models import (
    Zone,
    EnforcementOutput,
    get_timestamp,
)


class EnforcementLayer:
    """
    Enforcement Layer: Trust → Action mapping.
    
    Takes trust level and generates enforcement policies for downstream
    firewall and access control systems.
    """
    
    def __init__(self):
        print("[EnforcementLayer] Initialized")
    
    def enforce(
        self,
        trust: float,
        zone: Zone,
        entity_id: str,
    ) -> EnforcementOutput:
        """
        Generate enforcement action based on trust level.
        
        Parameters
        ----------
        trust : float ∈ [0, 1]
            Current trust value
        zone : Zone
            Enforcement zone (A/B/C)
        entity_id : str
            Entity identifier (IP, user, session)
        
        Returns
        -------
        EnforcementOutput
            Enforcement policy with action and configuration
        """
        
        if zone == Zone.A:
            # Full access
            return EnforcementOutput(
                action="Full network access granted",
                zone=zone,
                rate_limit_rps=None,
                mfa_required=False,
                quarantine=False,
                metadata={
                    "enforced_at": get_timestamp(),
                    "entity": entity_id,
                    "trust": round(trust, 4),
                    "rationale": "Zone A - trust > 0.8",
                }
            )
        
        elif zone == Zone.B:
            # Throttle + MFA
            return EnforcementOutput(
                action="Step-up MFA + session throttling",
                zone=zone,
                rate_limit_rps=10,
                mfa_required=True,
                quarantine=False,
                metadata={
                    "enforced_at": get_timestamp(),
                    "entity": entity_id,
                    "trust": round(trust, 4),
                    "rationale": "Zone B - 0.4 < trust ≤ 0.8",
                    "rate_limit_rps": 10,
                }
            )
        
        elif zone == Zone.C:
            # Block + Quarantine
            return EnforcementOutput(
                action="Quarantine — session terminated",
                zone=zone,
                rate_limit_rps=0,
                mfa_required=True,
                quarantine=True,
                metadata={
                    "enforced_at": get_timestamp(),
                    "entity": entity_id,
                    "trust": round(trust, 4),
                    "rationale": "Zone C - trust ≤ 0.4",
                    "action": "BLOCK",
                }
            )
        
        else:
            # Fallback (should not reach here)
            raise ValueError(f"Unknown zone: {zone}")
