"""
pipeline/utils/models.py
=======================
Shared data structures and Pydantic schemas for pipeline layers.

All layers communicate using these models for strong typing and validation.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any, Optional
from datetime import datetime
from enum import Enum


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FirewallAction(str, Enum):
    ALLOW = "ALLOW"
    THROTTLE = "THROTTLE"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"


class Zone(str, Enum):
    A = "A"  # T > 0.8 — full access
    B = "B"  # 0.4 < T ≤ 0.8 — throttle + MFA
    C = "C"  # T ≤ 0.4 — block


class RequestStatus(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    DELAYED = "delayed"
    QUARANTINED = "quarantined"


# ─────────────────────────────────────────────────────────────────────────────
# Layer Output Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InputLayerOutput:
    """Output from Layer 1: Input Layer"""
    rows: int
    columns: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FeatureLayerOutput:
    """Output from Layer 2: Feature Processing"""
    X_scaled: Any  # np.ndarray, kept as Any to avoid numpy import
    feature_names: list[str]
    n_features: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SeverityOutput:
    """Output from Layer 3: Severity Sensor"""
    severity_score: float
    ae_score: float
    if_score: float
    weight_ae: float
    weight_if: float
    top_features: list[str]
    feature_errors: list[float]
    explain_driver: str  # "AE" or "IF"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExplainabilityOutput:
    """Output from Layer 4: Explainability"""
    risk_level: RiskLevel
    severity_score: float
    attack_pattern: str
    explanation: str
    top_features: list[dict[str, Any]]  # [{name, error, interpretation}, ...]
    verdict: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustOutput:
    """Output from Layer 5: Trust Engine"""
    trust: float
    zone: Zone
    decayed: bool
    severity: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnforcementOutput:
    """Output from Layer 6: Enforcement"""
    action: str  # "Full access", "Throttle + MFA", "Quarantine"
    zone: Zone
    rate_limit_rps: Optional[int] = None
    mfa_required: bool = False
    quarantine: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FirewallOutput:
    """Output from Layer 7: Firewall Simulation 🔥"""
    firewall_action: FirewallAction
    status: RequestStatus
    latency_ms: float
    reason: str
    entity_id: str
    trust_score: float
    severity_score: float
    request_allowed: bool
    previous_state: str
    new_state: str
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# API Request/Response Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PipelineRequest:
    """Full pipeline request"""
    request_id: str
    entity_id: str
    feature_vector: list[float]
    profile: str = "Balanced"
    debug: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineSummary:
    """Executive summary of pipeline result"""
    severity: float
    trust: float
    zone: Zone
    action: str
    risk_level: RiskLevel
    allow: bool


@dataclass
class PipelineResponse:
    """Complete pipeline response for API"""
    request_id: str
    timestamp: str
    status: str
    
    # Layer outputs
    input: Optional[InputLayerOutput] = None
    features: Optional[FeatureLayerOutput] = None
    severity: Optional[SeverityOutput] = None
    explainability: Optional[ExplainabilityOutput] = None
    trust: Optional[TrustOutput] = None
    enforcement: Optional[EnforcementOutput] = None
    firewall: Optional[FirewallOutput] = None
    
    # Summary
    summary: Optional[PipelineSummary] = None
    
    # Debug trace
    debug_trace: Optional[dict[str, Any]] = None


# ─────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

def dataclass_to_dict(obj: Any) -> dict[str, Any]:
    """Convert dataclass to dict, handling nested dataclasses and enums."""
    if hasattr(obj, '__dataclass_fields__'):
        result = {}
        for key, value in asdict(obj).items():
            if isinstance(value, Enum):
                result[key] = value.value
            elif isinstance(value, (list, tuple)):
                result[key] = [
                    dataclass_to_dict(v) if hasattr(v, '__dataclass_fields__')
                    else v.value if isinstance(v, Enum)
                    else v
                    for v in value
                ]
            elif isinstance(value, dict):
                result[key] = {
                    k: dataclass_to_dict(v) if hasattr(v, '__dataclass_fields__')
                    else v.value if isinstance(v, Enum)
                    else v
                    for k, v in value.items()
                }
            elif isinstance(value, Enum):
                result[key] = value.value
            else:
                result[key] = value
        return result
    elif isinstance(obj, Enum):
        return obj.value
    else:
        return obj


def get_timestamp() -> str:
    """Get current timestamp in ISO 8601 format."""
    return datetime.utcnow().isoformat() + "Z"
