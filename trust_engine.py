"""
trust_engine.py
===============
Trust-Drift Core Engine — pure math, zero ML dependencies.

This module is completely independent of the model layer.
It consumes a single float (severity_score) and maintains trust state.

Usage
-----
    from trust_engine import TrustDriftEngine

    engine = TrustDriftEngine(lambda_=1.5, mu=0.05, anomaly_threshold=0.5)

    severity = 0.82                          # comes from SeverityScorer
    trust    = engine.update(severity)       # returns updated trust float
    zone     = engine.zone                   # Zone.A / B / C
    action   = engine.action                 # enforcement string

Interface contract
------------------
    Input  : severity_score  float ∈ [0, 1]   — from SeverityScorer
    Output : trust           float ∈ [0, 1]   — current trust level
    Output : zone            Zone enum         — enforcement tier
    Output : action          str               — recommended action

No shared state with the model layer. No imports from the model layer.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple


# ─────────────────────────────────────────────────────────────────────────────
# Parameter guardrails
# ─────────────────────────────────────────────────────────────────────────────

_LAMBDA_MIN, _LAMBDA_MAX = 0.1,  5.0
_MU_MIN,     _MU_MAX     = 0.001, 0.2


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


# ─────────────────────────────────────────────────────────────────────────────
# Enforcement zones
# ─────────────────────────────────────────────────────────────────────────────

class Zone(Enum):
    A = "A"   # T > 0.8  — full access
    B = "B"   # 0.4 < T ≤ 0.8 — step-up MFA / throttle
    C = "C"   # T ≤ 0.4  — quarantine / block


ZONE_ACTIONS: dict[Zone, str] = {
    Zone.A: "Full network access granted",
    Zone.B: "Step-up MFA + session throttling",
    Zone.C: "Quarantine — session terminated",
}


def classify_zone(trust: float) -> Zone:
    """Map a trust value to its enforcement zone."""
    if trust > 0.8:
        return Zone.A
    if trust > 0.4:
        return Zone.B
    return Zone.C


# ─────────────────────────────────────────────────────────────────────────────
# TrustState snapshot  (returned by update_full for easy downstream access)
# ─────────────────────────────────────────────────────────────────────────────

class TrustState(NamedTuple):
    """
    Immutable snapshot of trust engine state after one update.

    Fields
    ------
    trust    : float  — updated trust value ∈ [0, 1]
    zone     : Zone   — enforcement tier (A / B / C)
    action   : str    — recommended enforcement action
    decayed  : bool   — True if decay fired, False if recovery fired
    severity : float  — severity score that triggered this update
    """
    trust:    float
    zone:     Zone
    action:   str
    decayed:  bool
    severity: float


# ─────────────────────────────────────────────────────────────────────────────
# TrustDriftEngine
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TrustDriftEngine:
    """
    Continuous trust evolution engine.

    Math
    ----
    Decay   : T = T × exp(−λ × s)          when s ≥ anomaly_threshold
    Recovery: T = min(1.0,  T + μ × Δt)    when s <  anomaly_threshold

    λ controls how aggressively trust drops per unit severity.
    μ controls how quickly trust recovers during clean behaviour.
    Both are guardrailed to prevent degenerate states.

    Parameters
    ----------
    lambda_           : decay constant  λ   guardrailed to [0.1, 5.0]
    mu                : recovery rate   μ   guardrailed to [0.001, 0.2]
    anomaly_threshold : severity above which decay fires (default 0.5)
    initial_trust     : starting trust value (default 1.0)

    Public API
    ----------
    update(severity, delta_t=1.0) → float
        Minimal call — returns updated trust float only.
        Use this for tight loops where you only need the trust value.

    update_full(severity, delta_t=1.0) → TrustState
        Returns a full TrustState snapshot including zone and action.
        Use this when the downstream layer needs enforcement decisions.

    reset()
        Restore trust to initial_trust.
    """

    lambda_:           float = 1.5
    mu:                float = 0.05
    anomaly_threshold: float = 0.5
    initial_trust:     float = 1.0

    # Internal mutable state — not an __init__ parameter
    trust: float = field(init=False)

    def __post_init__(self) -> None:
        self.lambda_ = _clamp(self.lambda_, _LAMBDA_MIN, _LAMBDA_MAX)
        self.mu      = _clamp(self.mu,      _MU_MIN,     _MU_MAX)
        self.trust   = float(_clamp(self.initial_trust, 0.0, 1.0))

    # ── Public API ────────────────────────────────────────────────────────────

    def update(self, severity: float, delta_t: float = 1.0) -> float:
        """
        Advance trust by one time step. Returns updated trust ∈ [0, 1].

        Parameters
        ----------
        severity : float ∈ [0, 1]
            Anomaly severity from SeverityScorer.score_row() or score_dataset().
        delta_t  : float
            Elapsed time since last update (seconds). Used only in recovery.
            Default 1.0 is correct for per-flow scoring.
        """
        if not (0.0 <= severity <= 1.0):
            severity = _clamp(severity, 0.0, 1.0)

        if severity >= self.anomaly_threshold:
            self.trust = self._decay(severity)
        else:
            self.trust = self._recover(delta_t)

        return self.trust

    def update_full(self, severity: float, delta_t: float = 1.0) -> TrustState:
        """
        Advance trust and return a full TrustState snapshot.

        Returns TrustState(trust, zone, action, decayed, severity).
        Use when the enforcement layer needs zone and action alongside trust.
        """
        if not (0.0 <= severity <= 1.0):
            severity = _clamp(severity, 0.0, 1.0)

        decayed = severity >= self.anomaly_threshold
        self.update(severity, delta_t)

        return TrustState(
            trust    = self.trust,
            zone     = self.zone,
            action   = self.action,
            decayed  = decayed,
            severity = severity,
        )

    def reset(self) -> None:
        """Restore trust to initial_trust."""
        self.trust = float(_clamp(self.initial_trust, 0.0, 1.0))

    # ── Convenience properties ────────────────────────────────────────────────

    @property
    def zone(self) -> Zone:
        """Current enforcement zone based on trust value."""
        return classify_zone(self.trust)

    @property
    def action(self) -> str:
        """Recommended enforcement action for current zone."""
        return ZONE_ACTIONS[self.zone]

    def __repr__(self) -> str:
        return (
            f"TrustDriftEngine("
            f"trust={self.trust:.4f}, "
            f"zone={self.zone.value}, "
            f"λ={self.lambda_}, μ={self.mu}, "
            f"threshold={self.anomaly_threshold})"
        )

    # ── Math (private) ────────────────────────────────────────────────────────

    def _decay(self, s: float) -> float:
        """T(t+Δt) = T(t) × exp(−λ × s)"""
        return self.trust * math.exp(-self.lambda_ * s)

    def _recover(self, delta_t: float) -> float:
        """T(t+Δt) = min(1.0,  T(t) + μ × Δt)"""
        return min(1.0, self.trust + self.mu * delta_t)


# ─────────────────────────────────────────────────────────────────────────────
# Self-contained demo
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    engine = TrustDriftEngine(lambda_=1.5, mu=0.05, anomaly_threshold=0.5)

    events = [
        (0.90, 1.0, "high-severity attack"),
        (0.70, 1.0, "medium attack"),
        (0.20, 1.0, "normal → recover"),
        (0.20, 1.0, "normal → recover"),
        (0.20, 1.0, "normal → recover"),
        (0.90, 1.0, "attack again"),
        (0.10, 1.0, "long recovery 1"),
        (0.10, 1.0, "long recovery 2"),
        (0.10, 1.0, "long recovery 3"),
    ]

    print(f"{'severity':>10}  {'event':<28}  {'trust':>7}  zone  action")
    print("─" * 78)
    for s, dt, label in events:
        state = engine.update_full(s, dt)
        print(
            f"{s:>10.2f}  {label:<28}  "
            f"{state.trust:>7.4f}  {state.zone.value:>4}  {state.action}"
        )
