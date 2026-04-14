"""
pipeline/trust/__init__.py
==========================
Layer 5: Trust Engine Layer

Maintains trust state using exponential decay + linear recovery.
Pure math, zero ML dependencies.
"""

from pipeline.trust.engine import TrustLayer

__all__ = ["TrustLayer"]
