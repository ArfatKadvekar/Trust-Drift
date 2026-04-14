"""
pipeline/api/__init__.py
========================
Layer 8: API / REST Integration Layer

FastAPI server exposing pipeline functionality.
"""

from pipeline.api.server import create_app

__all__ = ["create_app"]
