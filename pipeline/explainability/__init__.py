"""
pipeline/explainability/__init__.py
===================================
Layer 4: Explainability Layer

Converts severity scores and anomalous features into human-readable explanations.
"""

from pipeline.explainability.explainer import ExplainabilityLayer

__all__ = ["ExplainabilityLayer"]
