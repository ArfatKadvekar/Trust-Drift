"""
pipeline/severity/__init__.py
=============================
Layer 3: Severity Sensor Layer

Hybrid AE + Isolation Forest anomaly detection.
Computes severity score ∈ [0, 1] from network flow features.
"""

from pipeline.severity.scorer import SeverityLayer

__all__ = ["SeverityLayer"]
