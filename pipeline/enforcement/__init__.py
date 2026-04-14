"""
pipeline/enforcement/__init__.py
================================
Layer 6: Enforcement Layer

Maps trust levels to enforcement actions and policies.
"""

from pipeline.enforcement.policy import EnforcementLayer

__all__ = ["EnforcementLayer"]
