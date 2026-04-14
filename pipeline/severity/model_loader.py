"""
pipeline/severity/model_loader.py
==================================
Safe model loading with fallback to simulation mode.

Features:
  - Safe file existence checking
  - Graceful fallback to simulation mode
  - Optional auto-training
  - Configuration-driven behavior
  - Comprehensive logging
"""

import sys
import joblib
import numpy as np
from pathlib import Path
from typing import Tuple, Optional, Any

import warnings
warnings.filterwarnings('ignore')


class FallbackSeveritySimulator:
    """
    Simulates severity scoring when models are unavailable.
    
    Provides deterministic, repeatable severity scores based on synthetic input patterns.
    Not intended for production but enables PoC demonstrations.
    """
    
    def __init__(self, seed: int = 42):
        """Initialize simulator with optional seed for reproducibility."""
        self.np_random = np.random.RandomState(seed)
        self._simulation_state = {}
        
    def calibrate(self, X_train: np.ndarray) -> None:
        """
        Calibrate on benign data (no-op for simulator).
        
        Parameters
        ----------
        X_train : np.ndarray
            Training data (unused but keeps interface compatible)
        """
        pass
    
    def score_single(self, x: np.ndarray, scenario: str = "normal") -> float:
        """
        Generate deterministic severity based on input pattern and scenario.
        
        Parameters
        ----------
        x : np.ndarray
            Feature vector
        scenario : str
            "normal" (low severity), "attack" (high severity), "gradual" (varies)
        
        Returns
        -------
        float
            Severity score [0, 1]
        """
        # Use feature statistics as basis for deterministic behavior
        feature_mean = float(np.mean(x)) if len(x) > 0 else 0.5
        feature_var = float(np.var(x)) if len(x) > 0 else 0.01
        feature_max = float(np.max(x)) if len(x) > 0 else 1.0
        
        # Scenario-based severity
        if scenario == "normal":
            # Normal traffic: low severity with small noise
            base = 0.15
            noise = self.np_random.normal(0, 0.05)
            severity = np.clip(base + noise, 0, 1)
            
        elif scenario == "attack":
            # Attack: high severity with variation
            base = 0.85
            noise = self.np_random.normal(0, 0.1)
            severity = np.clip(base + noise, 0, 1)
            
        elif scenario == "gradual":
            # Gradual degradation: based on feature properties
            # High variance or extreme values → higher severity
            base = min(0.5, feature_var * 10 + feature_max * 0.2)
            noise = self.np_random.normal(0, 0.05)
            severity = np.clip(base + noise, 0, 1)
            
        else:  # default: auto-detect from feature statistics
            # High variance/max → likely anomaly
            anomaly_score = min(1.0, feature_var * 5 + (feature_max - 0.5) * 0.5)
            noise = self.np_random.normal(0, 0.03)
            severity = np.clip(anomaly_score + noise, 0, 1)
        
        return float(np.clip(severity, 0, 1))
    
    def score_batch(self, X: np.ndarray, scenario: str = "normal") -> np.ndarray:
        """Score multiple samples deterministically."""
        return np.array([self.score_single(x, scenario) for x in X])


class SafeModelLoader:
    """
    Safe model loading with fallback to simulation mode.
    
    Behavior:
      - If models exist: load them
      - If missing: log warning and switch to fallback simulator
      - Provides unified interface for both modes
    """
    
    def __init__(
        self,
        autoencoder_path: str,
        encoder_path: str,
        iso_forest_path: str,
        scaler_path: str,
        feature_cols_path: str,
        allow_fallback: bool = True,
        fallback_seed: int = 42,
        logger=None,
    ):
        """
        Initialize safe loader.
        
        Parameters
        ----------
        autoencoder_path : str
            Path to autoencoder model (.keras)
        encoder_path : str
            Path to encoder model (.keras)
        iso_forest_path : str
            Path to isolation forest (.pkl)
        scaler_path : str
            Path to scaler (.pkl)
        feature_cols_path : str
            Path to feature columns (.pkl)
        allow_fallback : bool
            If True, use simulator when models missing; if False, raise error
        fallback_seed : int
            Random seed for simulator reproducibility
        logger : optional
            Logger for output (default: print)
        """
        self.autoencoder_path = autoencoder_path
        self.encoder_path = encoder_path
        self.iso_forest_path = iso_forest_path
        self.scaler_path = scaler_path
        self.feature_cols_path = feature_cols_path
        self.allow_fallback = allow_fallback
        self.fallback_seed = fallback_seed
        self.logger = logger or print
        
        self.mode = None  # "real" or "simulation"
        self.autoencoder = None
        self.encoder = None
        self.iso_forest = None
        self.scaler = None
        self.feature_cols = None
        self.simulator = None
        
        self._load()
    
    def _log(self, msg: str, level: str = "INFO") -> None:
        """Internal logging."""
        prefix = f"[{level}]" if level != "INFO" else "[MODEL]"
        self.logger(f"{prefix} {msg}")
    
    def _file_exists(self, path: str) -> bool:
        """Check if a file exists."""
        return Path(path).exists()
    
    def _check_all_files(self) -> Tuple[bool, list]:
        """
        Check if all required files exist.
        
        Returns
        -------
        Tuple[bool, list]
            (all_exist, missing_files)
        """
        files_to_check = {
            "autoencoder": self.autoencoder_path,
            "encoder": self.encoder_path,
            "iso_forest": self.iso_forest_path,
            "scaler": self.scaler_path,
            "feature_cols": self.feature_cols_path,
        }
        
        missing = []
        for name, path in files_to_check.items():
            if not self._file_exists(path):
                missing.append(f"{name} ({path})")
        
        return len(missing) == 0, missing
    
    def _load(self) -> None:
        """Load models or fallback to simulation."""
        all_exist, missing = self._check_all_files()
        
        if all_exist:
            self._load_real_models()
        else:
            if self.allow_fallback:
                self._load_fallback_mode(missing)
            else:
                raise ValueError(
                    f"Models missing and fallback disabled:\n"
                    + "\n".join(missing)
                )
    
    def _load_real_models(self) -> None:
        """Load actual trained models."""
        try:
            self._log("Loading trained models...", "INFO")
            
            # Import here to avoid TF init if not needed
            from tensorflow.keras.models import load_model
            
            self.autoencoder = load_model(self.autoencoder_path)
            self._log(f"  [OK] Autoencoder loaded", "INFO")
            
            self.encoder = load_model(self.encoder_path)
            self._log(f"  [OK] Encoder loaded", "INFO")
            
            self.iso_forest = joblib.load(self.iso_forest_path)
            self._log(f"  [OK] Isolation Forest loaded", "INFO")
            
            self.scaler = joblib.load(self.scaler_path)
            self._log(f"  [OK] Scaler loaded", "INFO")
            
            self.feature_cols = joblib.load(self.feature_cols_path)
            self._log(f"  [OK] Feature columns loaded ({len(self.feature_cols)} cols)", "INFO")
            
            self.mode = "real"
            self._log(f"Mode: REAL MODELS", "INFO")
            
        except Exception as e:
            if self.allow_fallback:
                self._log(f"Failed to load models: {str(e)}", "WARNING")
                self._log(f"Falling back to simulation mode", "WARNING")
                self._load_fallback_mode([str(e)])
            else:
                raise
    
    def _load_fallback_mode(self, reason: list) -> None:
        """Load fallback simulator."""
        self._log("=" * 70, "WARNING")
        self._log("FALLBACK MODE: Using simulated severity scores", "WARNING")
        self._log("Reason(s):", "WARNING")
        for r in reason:
            self._log(f"  - {r}", "WARNING")
        self._log("Note: Models will work but use deterministic simulation", "WARNING")
        self._log("      For production, train and save models to:", "WARNING")
        self._log(f"      {self.autoencoder_path}", "WARNING")
        self._log("=" * 70, "WARNING")
        
        self.simulator = FallbackSeveritySimulator(seed=self.fallback_seed)
        self.mode = "simulation"
        self._log(f"Mode: SIMULATION", "INFO")
    
    @property
    def is_fallback(self) -> bool:
        """True if using fallback simulator."""
        return self.mode == "simulation"
    
    def get_autoencoder(self) -> Any:
        """Get autoencoder (or None in fallback mode)."""
        return self.autoencoder
    
    def get_encoder(self) -> Any:
        """Get encoder (or None in fallback mode)."""
        return self.encoder
    
    def get_iso_forest(self) -> Any:
        """Get isolation forest (or None in fallback mode)."""
        return self.iso_forest
    
    def get_scaler(self) -> Any:
        """Get scaler (or None in fallback mode)."""
        return self.scaler
    
    def get_feature_cols(self) -> Optional[list]:
        """Get feature column names (or None in fallback mode)."""
        return self.feature_cols
    
    def get_simulator(self) -> Optional[FallbackSeveritySimulator]:
        """Get simulator (or None in real mode)."""
        return self.simulator


def create_safe_loader(
    config: dict,
    allow_fallback: bool = True,
    logger=None,
) -> SafeModelLoader:
    """
    Factory function to create safe loader from config.
    
    Parameters
    ----------
    config : dict
        Configuration dict with model paths
    allow_fallback : bool
        Enable fallback to simulation mode
    logger : optional
        Logger callback
    
    Returns
    -------
    SafeModelLoader
    """
    return SafeModelLoader(
        autoencoder_path=config.get("autoencoder_path", 
            "./pipeline/severity/models/autoencoder.keras"),
        encoder_path=config.get("encoder_path", 
            "./pipeline/severity/models/encoder.keras"),
        iso_forest_path=config.get("iso_forest_path", 
            "./pipeline/severity/models/iso_forest.pkl"),
        scaler_path=config.get("scaler_path", 
            "./pipeline/severity/models/scaler.pkl"),
        feature_cols_path=config.get("feature_cols_path", 
            "./pipeline/severity/models/feature_cols.pkl"),
        allow_fallback=allow_fallback,
        fallback_seed=config.get("fallback_seed", 42),
        logger=logger,
    )
