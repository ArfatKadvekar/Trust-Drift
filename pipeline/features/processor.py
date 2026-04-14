"""
pipeline/features/processor.py
==============================
Feature Processing Layer: Scale features using fitted scaler.

Accepts raw features and applies MinMaxScaler transformation.
Returns normalized features suitable for ML models.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from typing import Optional

from pipeline.utils.models import FeatureLayerOutput, get_timestamp


class FeatureProcessor:
    """
    Feature scaling and preprocessing.
    
    Loads a fitted MinMaxScaler and applies it to feature vectors.
    """
    
    def __init__(self, scaler_path: str):
        """
        Initialize with path to fitted scaler.
        
        Parameters
        ----------
        scaler_path : str
            Path to .pkl file containing fitted MinMaxScaler
        """
        self.scaler_path = scaler_path
        self.scaler = self._load_scaler()
        self.feature_names: Optional[list[str]] = None
    
    def _load_scaler(self):
        """Load fitted scaler from disk."""
        scaler_path = Path(self.scaler_path)
        
        if not scaler_path.exists():
            raise FileNotFoundError(f"Scaler not found: {self.scaler_path}")
        
        print(f"[FeatureProcessor] Loading scaler from {self.scaler_path}...")
        scaler = joblib.load(scaler_path)
        print(f"[FeatureProcessor] Scaler loaded: {type(scaler).__name__}")
        return scaler
    
    def process(
        self,
        X: pd.DataFrame | np.ndarray,
        feature_names: Optional[list[str]] = None
    ) -> FeatureLayerOutput:
        """
        Scale features using fitted scaler.
        
        Parameters
        ----------
        X : pd.DataFrame or np.ndarray
            Raw feature matrix
        feature_names : list[str], optional
            Feature column names (required if X is ndarray)
        
        Returns
        -------
        FeatureLayerOutput
            Scaled features + metadata
        """
        # Convert to numpy if needed
        if isinstance(X, pd.DataFrame):
            if feature_names is None:
                feature_names = list(X.columns)
            X_raw = X.values
        else:
            X_raw = np.asarray(X)
            if feature_names is None:
                raise ValueError("feature_names required when X is ndarray")
        
        self.feature_names = feature_names
        
        print(f"[FeatureProcessor] Scaling {len(X_raw):,} samples × {len(feature_names)} features...")
        
        # Validate shape
        expected_n_features = self.scaler.n_features_in_
        if X_raw.shape[1] != expected_n_features:
            raise ValueError(
                f"Feature count mismatch: got {X_raw.shape[1]}, "
                f"expected {expected_n_features}"
            )
        
        # Scale
        X_scaled = self.scaler.transform(X_raw).astype(np.float32)
        
        metadata = {
            "scaled_at": get_timestamp(),
            "scaler_type": type(self.scaler).__name__,
            "n_features_expected": expected_n_features,
            "n_features_got": X_raw.shape[1],
            "shape": list(X_scaled.shape),
            "dtype": str(X_scaled.dtype),
            "value_range": {
                "min": float(np.min(X_scaled)),
                "max": float(np.max(X_scaled)),
                "mean": float(np.mean(X_scaled))
            }
        }
        
        print(f"[FeatureProcessor] Scaling complete. Output shape: {X_scaled.shape}")
        
        return FeatureLayerOutput(
            X_scaled=X_scaled,
            feature_names=feature_names,
            n_features=len(feature_names),
            metadata=metadata
        )
