"""
pipeline/firewall/state.py
==========================
Entity state management for firewall simulator.

Tracks per-entity (IP/session) state:
- Allowed count
- Throttled count
- Blocked count
- Quarantine status
- Recent actions
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class EntityStatus(str, Enum):
    ALLOWED = "allowed"
    THROTTLED = "throttled"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"


@dataclass
class EntityState:
    """Per-entity (IP/session) firewall state."""
    
    entity_id: str
    status: EntityStatus = EntityStatus.ALLOWED
    trust: float = 1.0
    
    # Counters
    allowed_count: int = 0
    throttled_count: int = 0
    blocked_count: int = 0
    quarantined_count: int = 0
    
    # Quarantine info
    quarantine_reason: Optional[str] = None
    quarantine_timestamp: Optional[str] = None
    quarantine_expiry: Optional[str] = None
    
    # Recent actions
    last_action: Optional[str] = None
    last_action_timestamp: Optional[str] = None
    action_history: list[dict] = field(default_factory=list)
    
    # Throttling
    throttle_until: Optional[str] = None
    throttle_rate_limit_rps: int = 0
    
    def update_status(
        self,
        new_status: EntityStatus,
        trust: float,
        reason: Optional[str] = None,
    ) -> None:
        """Update entity status and track change."""
        self.status = new_status
        self.trust = trust
        self.last_action = new_status.value
        self.last_action_timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Update counters
        if new_status == EntityStatus.ALLOWED:
            self.allowed_count += 1
        elif new_status == EntityStatus.THROTTLED:
            self.throttled_count += 1
        elif new_status == EntityStatus.BLOCKED:
            self.blocked_count += 1
        elif new_status == EntityStatus.QUARANTINED:
            self.quarantined_count += 1
            self.quarantine_reason = reason
            self.quarantine_timestamp = self.last_action_timestamp
        
        # Add to history
        self.action_history.append({
            "timestamp": self.last_action_timestamp,
            "status": new_status.value,
            "trust": round(trust, 4),
            "reason": reason,
        })
        
        # Keep history to last 100 actions
        if len(self.action_history) > 100:
            self.action_history = self.action_history[-100:]
    
    def is_quarantined(self) -> bool:
        """Check if entity is currently quarantined."""
        return self.status == EntityStatus.QUARANTINED
    
    def is_blocked(self) -> bool:
        """Check if entity is blocked."""
        return self.status == EntityStatus.BLOCKED
    
    def is_throttled(self) -> bool:
        """Check if entity is throttled."""
        return self.status == EntityStatus.THROTTLED
    
    def can_accept_request(self) -> bool:
        """Check if entity can accept new requests."""
        return self.status not in [EntityStatus.BLOCKED, EntityStatus.QUARANTINED]
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "entity_id": self.entity_id,
            "status": self.status.value,
            "trust": round(self.trust, 4),
            "allowed_count": self.allowed_count,
            "throttled_count": self.throttled_count,
            "blocked_count": self.blocked_count,
            "quarantined_count": self.quarantined_count,
            "quarantine_reason": self.quarantine_reason,
            "quarantine_timestamp": self.quarantine_timestamp,
            "last_action": self.last_action,
            "last_action_timestamp": self.last_action_timestamp,
            "action_history_count": len(self.action_history),
        }
