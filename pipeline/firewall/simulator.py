"""
pipeline/firewall/simulator.py
==============================
Firewall Simulation Layer 🔥

Simulates real enterprise firewall behavior:
  ALLOW     → Pass requests immediately
  THROTTLE  → Add latency (50-200ms), apply rate limit
  BLOCK     → Reject immediately
  QUARANTINE → Isolate entity, prevent access

Maintains per-entity state to demonstrate realistic Zero Trust enforcement.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Optional

from pipeline.utils.models import (
    FirewallAction,
    RequestStatus,
    FirewallOutput,
    get_timestamp,
)
from pipeline.firewall.state import EntityState, EntityStatus


class FirewallSimulator:
    """
    Stateful firewall simulator for Zero Trust enforcement.
    
    Maintains per-entity state and applies enforcement actions based on
    trust scores. Simulates realistic enterprise firewall behavior.
    """
    
    def __init__(
        self,
        enable_latency_simulation: bool = True,
        throttle_latency_min_ms: int = 50,
        throttle_latency_max_ms: int = 200,
    ):
        """
        Initialize Firewall Simulator.
        
        Parameters
        ----------
        enable_latency_simulation : bool
            If True, simulate network latency for throttled requests
        throttle_latency_min_ms : int
            Min artificial delay for THROTTLE action
        throttle_latency_max_ms : int
            Max artificial delay for THROTTLE action
        """
        self.enable_latency_simulation = enable_latency_simulation
        self.throttle_latency_min_ms = throttle_latency_min_ms
        self.throttle_latency_max_ms = throttle_latency_max_ms
        
        # Per-entity state tracking
        self.entity_states: dict[str, EntityState] = {}
        
        # Decision log
        self.decisions: list[dict] = []
        
        print("[FirewallSimulator] Initialized")
        print(f"  Latency simulation: {enable_latency_simulation}")
        print(f"  Throttle latency: {throttle_latency_min_ms}-{throttle_latency_max_ms} ms")
    
    def _get_or_create_entity(self, entity_id: str) -> EntityState:
        """Get existing entity state or create new one."""
        if entity_id not in self.entity_states:
            self.entity_states[entity_id] = EntityState(entity_id=entity_id)
        return self.entity_states[entity_id]
    
    def evaluate(
        self,
        entity_id: str,
        enforcement_action: str,
        trust_score: float,
        severity_score: float,
        zone: str,
    ) -> FirewallOutput:
        """
        Evaluate firewall action for entity.
        
        Maps enforcement action to firewall response:
          "Full network access granted" → ALLOW
          "Step-up MFA + session throttling" → THROTTLE
          "Quarantine — session terminated" → BLOCK + QUARANTINE
        
        Parameters
        ----------
        entity_id : str
            Entity identifier (IP, user, session)
        enforcement_action : str
            Action from enforcement layer
        trust_score : float
            Current trust value
        severity_score : float
            Current severity value
        zone : str
            Enforcement zone (A/B/C)
        
        Returns
        -------
        FirewallOutput
            Firewall decision with latency simulation
        """
        
        entity = self._get_or_create_entity(entity_id)
        previous_state = entity.status.value
        
        # Map enforcement action to firewall action
        if "Full network access" in enforcement_action:
            firewall_action = FirewallAction.ALLOW
            status = RequestStatus.SUCCESS
            latency_ms = 1.0
            reason = "Zone A - full access granted"
            entity.update_status(EntityStatus.ALLOWED, trust_score, reason)
        
        elif "Step-up MFA" in enforcement_action or "throttling" in enforcement_action:
            firewall_action = FirewallAction.THROTTLE
            status = RequestStatus.DELAYED
            # Simulate latency
            if self.enable_latency_simulation:
                latency_ms = float(random.randint(
                    self.throttle_latency_min_ms,
                    self.throttle_latency_max_ms
                ))
            else:
                latency_ms = 10.0
            reason = f"Zone B - throttle + MFA (latency: {latency_ms:.0f}ms)"
            entity.update_status(EntityStatus.THROTTLED, trust_score, reason)
            entity.throttle_rate_limit_rps = 10
        
        elif "Quarantine" in enforcement_action:
            firewall_action = FirewallAction.BLOCK
            status = RequestStatus.DENIED
            latency_ms = 0.0
            reason = "Zone C - quarantine initiated"
            entity.update_status(EntityStatus.QUARANTINED, trust_score, reason)
        
        else:
            # Fallback: block
            firewall_action = FirewallAction.BLOCK
            status = RequestStatus.DENIED
            latency_ms = 0.0
            reason = "Unknown enforcement action - blocking as precaution"
            entity.update_status(EntityStatus.BLOCKED, trust_score, reason)
        
        # Build response
        response = FirewallOutput(
            firewall_action=firewall_action,
            status=status,
            latency_ms=latency_ms,
            reason=reason,
            entity_id=entity_id,
            trust_score=round(trust_score, 4),
            severity_score=round(severity_score, 4),
            request_allowed=(firewall_action == FirewallAction.ALLOW),
            previous_state=previous_state,
            new_state=entity.status.value,
            timestamp=get_timestamp(),
            metadata={
                "zone": zone,
                "session_count_allowed": entity.allowed_count,
                "session_count_throttled": entity.throttled_count,
                "session_count_blocked": entity.blocked_count,
                "session_count_quarantined": entity.quarantined_count,
            }
        )
        
        # Log decision
        self.decisions.append({
            "timestamp": response.timestamp,
            "entity_id": entity_id,
            "action": firewall_action.value,
            "status": status.value,
            "latency_ms": latency_ms,
            "trust_score": round(trust_score, 4),
            "severity_score": round(severity_score, 4),
            "zone": zone,
        })
        
        return response
    
    def get_entity_state(self, entity_id: str) -> Optional[EntityState]:
        """Get current state of entity."""
        return self.entity_states.get(entity_id)
    
    def get_all_entities(self) -> list[EntityState]:
        """Get all tracked entities."""
        return list(self.entity_states.values())
    
    def get_decisions(self, limit: int = 100) -> list[dict]:
        """Get recent firewall decisions."""
        return self.decisions[-limit:]
    
    def get_blocked_entities(self) -> list[str]:
        """Get list of currently blocked entities."""
        return [
            entity_id
            for entity_id, state in self.entity_states.items()
            if state.is_blocked() or state.is_quarantined()
        ]
    
    def get_throttled_entities(self) -> list[str]:
        """Get list of currently throttled entities."""
        return [
            entity_id
            for entity_id, state in self.entity_states.items()
            if state.is_throttled()
        ]
    
    def reset_entity(self, entity_id: str) -> None:
        """Reset trust for entity (recovery scenario)."""
        if entity_id in self.entity_states:
            self.entity_states[entity_id].update_status(
                EntityStatus.ALLOWED, 1.0, "Trust reset by admin"
            )
            print(f"[Firewall] Reset entity: {entity_id}")
    
    def clear_quarantine(self) -> None:
        """Clear all quarantined entities."""
        for entity in self.entity_states.values():
            if entity.is_quarantined():
                entity.update_status(EntityStatus.ALLOWED, 0.5, "Quarantine cleared")
        print("[Firewall] Cleared all quarantines")
    
    def get_stats(self) -> dict:
        """Get firewall statistics."""
        all_entities = self.get_all_entities()
        
        return {
            "total_entities": len(all_entities),
            "allowed": sum(1 for e in all_entities if e.status == EntityStatus.ALLOWED),
            "throttled": sum(1 for e in all_entities if e.status == EntityStatus.THROTTLED),
            "blocked": sum(1 for e in all_entities if e.status == EntityStatus.BLOCKED),
            "quarantined": sum(1 for e in all_entities if e.status == EntityStatus.QUARANTINED),
            "total_decisions": len(self.decisions),
            "avg_trust": round(
                sum(e.trust for e in all_entities) / len(all_entities) if all_entities else 0,
                4
            ),
        }
