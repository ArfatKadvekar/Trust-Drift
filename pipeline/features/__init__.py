"""
pipeline/features/__init__.py
=============================
Layer 2: Feature Processing Layer

Scale features using fitted scaler.
"""

from pipeline.features.processor import FeatureProcessor

__all__ = ["FeatureProcessor"]
