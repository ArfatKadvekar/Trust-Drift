"""
pipeline/input/loader.py
========================
Input Layer: Load and validate network flow data.

Accepts CSV files in ISCX format and validates structure.
Returns parsed DataFrame with metadata.
"""

from __future__ import annotations

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Optional

from pipeline.utils.models import InputLayerOutput, get_timestamp


class InputLayer:
    """Load and validate network flow input data."""
    
    # Expected columns in ISCX format
    ISCX_REQUIRED_COLUMNS = [
        'Flow ID', 'Source IP', 'Destination IP',
        'Source Port', 'Destination Port', 'Protocol'
    ]
    
    # Metadata columns to preserve
    METADATA_COLUMNS = ['Flow ID', 'Source IP', 'Destination IP', 'Label']
    
    def __init__(self, format: str = "ISCX"):
        self.format = format
        self.df: Optional[pd.DataFrame] = None
    
    def load(self, filepath: str) -> InputLayerOutput:
        """
        Load CSV file and validate structure.
        
        Parameters
        ----------
        filepath : str
            Path to CSV file
        
        Returns
        -------
        InputLayerOutput
            Contains DataFrame, column names, row count, metadata
        """
        file_path = Path(filepath)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        print(f"[InputLayer] Loading {filepath} ...")
        
        # Load CSV
        self.df = pd.read_csv(file_path)
        
        # Basic validation
        if len(self.df) == 0:
            raise ValueError("CSV file is empty")
        
        print(f"[InputLayer] Loaded {len(self.df):,} rows, {len(self.df.columns)} columns")
        
        # Extract metadata
        metadata = {
            "file": file_path.name,
            "filepath": str(file_path),
            "loaded_at": get_timestamp(),
            "format": self.format,
            "dtypes": self.df.dtypes.astype(str).to_dict(),
            "shape": [len(self.df), len(self.df.columns)],
            "null_counts": self.df.isnull().sum().to_dict(),
        }
        
        return InputLayerOutput(
            rows=len(self.df),
            columns=list(self.df.columns),
            metadata=metadata
        )
    
    def get_feature_columns(self) -> list[str]:
        """
        Get list of feature columns (excluding metadata columns).
        
        Feature columns are those NOT in METADATA_COLUMNS.
        """
        if self.df is None:
            raise RuntimeError("No data loaded. Call load() first.")
        
        return [col for col in self.df.columns if col not in self.METADATA_COLUMNS]
    
    def get_data(self) -> pd.DataFrame:
        """Get loaded DataFrame."""
        if self.df is None:
            raise RuntimeError("No data loaded. Call load() first.")
        return self.df.copy()
    
    def get_metadata_columns(self, df: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        """Extract metadata columns from DataFrame."""
        if df is None:
            if self.df is None:
                raise RuntimeError("No data loaded. Call load() first.")
            df = self.df
        
        cols = [col for col in self.METADATA_COLUMNS if col in df.columns]
        return df[cols].copy() if cols else pd.DataFrame()
    
    def get_features(self, df: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        """Extract feature columns from DataFrame."""
        if df is None:
            if self.df is None:
                raise RuntimeError("No data loaded. Call load() first.")
            df = self.df
        
        feature_cols = self.get_feature_columns()
        return df[feature_cols].copy()
