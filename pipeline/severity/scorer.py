"""
pipeline/severity/scorer.py
============================
Severity Sensor Layer: Wraps the existing SeverityScorer module.

This layer does NOT rewrite the original severity_scorer.py logic.
It imports and wraps it for integration into the pipeline architecture.

Now with SAFE LOADING and FALLBACK MODE:
  - Checks if model files exist before loading
  - Falls back to deterministic simulation if missing
  - Fully crash-proof for PoC demonstrations
"""

from __future__ import annotations

import sys
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from typing import Optional

# Import the existing SeverityScorer module
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from severity_scorer import SeverityScorer

from pipeline.utils.models import SeverityOutput, get_timestamp
from pipeline.severity.model_loader import create_safe_loader, FallbackSeveritySimulator


class SeverityLayer:
    """
    Wrapper around SeverityScorer for pipeline integration.
    
    Accepts scaled features and returns severity scores with diagnostics.
    Uses hybrid AE + IF approach with percentile normalization and dynamic weighting.
    
    SAFE LOADING:
      - If models exist: uses trained models
      - If missing: switches to deterministic fallback simulator
      - Never crashes due to missing artifacts
    """
    
    def __init__(
        self,
        autoencoder_path: str,
        encoder_path: str,
        iso_forest_path: str,
        scaler_path: str,
        feature_cols_path: str,
        top_n: int = 5,
        ema_alpha: float = 0.3,
        allow_fallback: bool = True,
    ):
        """
        Initialize Severity Layer with safe loading.
        
        Parameters
        ----------
        autoencoder_path : str
            Path to trained autoencoder model (.keras)
        encoder_path : str
            Path to encoder sub-model (.keras)
        iso_forest_path : str
            Path to Isolation Forest model (.pkl)
        scaler_path : str
            Path to MinMaxScaler (.pkl)
        feature_cols_path : str
            Path to feature column names (.pkl)
        top_n : int
            Number of top anomalous features to extract
        ema_alpha : float
            EMA smoothing factor (0 = no smoothing, 1 = no memory)
        allow_fallback : bool
            If True, use simulation when models missing; if False, raise error
        """
        print("[SeverityLayer] Initializing with SAFE LOADING...")
        
        config = {
            "autoencoder_path": autoencoder_path,
            "encoder_path": encoder_path,
            "iso_forest_path": iso_forest_path,
            "scaler_path": scaler_path,
            "feature_cols_path": feature_cols_path,
        }
        
        # Safe load with fallback
        self.model_loader = create_safe_loader(
            config=config,
            allow_fallback=allow_fallback,
            logger=print,
        )
        
        self.top_n = top_n
        self.ema_alpha = ema_alpha
        self._calibrated = False
        self.scorer = None  # Only initialized if models available
        
        # Initialize based on mode
        if not self.model_loader.is_fallback:
            # REAL MODEL MODE
            self.scorer = SeverityScorer(
                autoencoder=self.model_loader.get_autoencoder(),
                encoder_model=self.model_loader.get_encoder(),
                iso_forest=self.model_loader.get_iso_forest(),
                scaler=self.model_loader.get_scaler(),
                feature_names=self.model_loader.get_feature_cols(),
                top_n=top_n,
                ema_alpha=ema_alpha,
            )
            print(f"[SeverityLayer] Mode: REAL MODELS")
        else:
            # FALLBACK SIMULATION MODE
            print(f"[SeverityLayer] Mode: SIMULATION (deterministic fallback)")
        
        print("[SeverityLayer] Initialized.")
    
    def calibrate(self, X_train_scaled: np.ndarray) -> None:
        """
        Calibrate on benign-only training data.
        
        Must be called once before scoring.
        
        Parameters
        ----------
        X_train_scaled : np.ndarray
            Benign-only scaled feature matrix
        """
        print("[SeverityLayer] Calibrating...")
        
        if self.scorer:
            # REAL MODEL MODE
            self.scorer.calibrate(X_train_scaled)
        else:
            # FALLBACK MODE - simulator doesn't need calibration
            # but we can extract info for diagnostics
            self.model_loader.get_simulator().calibrate(X_train_scaled)
        
        self._calibrated = True
    
    def score(self, x_scaled: np.ndarray) -> SeverityOutput:
        """
        Score a single scaled feature vector.
        
        Parameters
        ----------
        x_scaled : np.ndarray
            Single scaled feature vector, shape (n_features,)
        
        Returns
        -------
        SeverityOutput
            Structured severity output with diagnostics
        """
        if not self._calibrated:
            raise RuntimeError("Must call calibrate() before scoring")
        
        if self.scorer:
            # REAL MODEL MODE
            severity, diagnostics = self.scorer.score_row(x_scaled)
            
            return SeverityOutput(
                severity_score=diagnostics["severity_score"],
                ae_score=diagnostics["ae_score"],
                if_score=diagnostics["if_score"],
                weight_ae=diagnostics["weights"]["ae"],
                weight_if=diagnostics["weights"]["if"],
                top_features=diagnostics["top_features"],
                feature_errors=diagnostics["feature_errors"],
                explain_driver="AE" if diagnostics["ae_score"] >= diagnostics["if_score"] else "IF",
                metadata={
                    "scored_at": get_timestamp(),
                    "top_n": len(diagnostics["top_features"]),
                }
            )
        else:
            # FALLBACK MODE - deterministic simulation
            simulator = self.model_loader.get_simulator()
            severity = simulator.score_single(x_scaled, scenario="normal")
            
            # Generate fake top features for compatibility
            fake_top_features = [
                f"feature_{i}" for i in range(min(self.top_n, len(x_scaled)))
            ]
            
            return SeverityOutput(
                severity_score=severity,
                ae_score=severity * 0.6,  # Simulate AE contribution
                if_score=severity * 0.4,  # Simulate IF contribution
                weight_ae=0.6,
                weight_if=0.4,
                top_features=fake_top_features,
                feature_errors=[0.0] * len(x_scaled),
                explain_driver="SIM",  # Simulation driver
                metadata={
                    "scored_at": get_timestamp(),
                    "mode": "simulation",
                    "top_n": len(fake_top_features),
                }
            )
    
    def score_batch(self, X_scaled: np.ndarray) -> list[SeverityOutput]:
        """
        Score multiple scaled feature vectors.
        
        Parameters
        ----------
        X_scaled : np.ndarray
            Scaled feature matrix, shape (n, n_features)
        
        Returns
        -------
        list[SeverityOutput]
            Severity output for each row
        """
        if not self._calibrated:
            raise RuntimeError("Must call calibrate() before scoring")
        
        if self.scorer:
            # REAL MODEL MODE
            df = self.scorer.score_batch(X_scaled)
            
            results = []
            for _, row in df.iterrows():
                top_features = [
                    row[f"top_feature_{i+1}"]
                    for i in range(self.top_n)
                    if f"top_feature_{i+1}" in row and pd.notna(row[f"top_feature_{i+1}"])
                ]
                
                output = SeverityOutput(
                    severity_score=float(row["combined_severity"]),
                    ae_score=float(row["ae_severity"]),
                    if_score=float(row["if_severity"]),
                    weight_ae=float(row["weight_ae"]),
                    weight_if=float(row["weight_if"]),
                    top_features=top_features,
                    feature_errors=[
                        float(row[f"feat_err_{j}"])
                        for j in range(len(self.scorer.feat_names))
                    ],
                    explain_driver=str(row["explain_driver"]),
                )
                results.append(output)
            
            return results
        else:
            # FALLBACK MODE - deterministic simulation
            simulator = self.model_loader.get_simulator()
            severities = simulator.score_batch(X_scaled, scenario="normal")
            
            results = []
            for severity in severities:
                fake_top_features = [
                    f"feature_{i}" for i in range(min(self.top_n, X_scaled.shape[1]))
                ]
                
                output = SeverityOutput(
                    severity_score=float(severity),
                    ae_score=float(severity * 0.6),
                    if_score=float(severity * 0.4),
                    weight_ae=0.6,
                    weight_if=0.4,
                    top_features=fake_top_features,
                    feature_errors=[0.0] * X_scaled.shape[1],
                    explain_driver="SIM",
                    metadata={
                        "mode": "simulation",
                        "scored_at": get_timestamp(),
                    }
                )
                results.append(output)
            
            return results

