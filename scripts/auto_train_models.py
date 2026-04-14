#!/usr/bin/env python
"""
scripts/auto_train_models.py
============================
Optional auto-training script to generate model artifacts.

Usage:
    python scripts/auto_train_models.py

This script:
  1. Creates synthetic training data
  2. Trains a simple autoencoder
  3. Trains an Isolation Forest
  4. Saves all artifacts to pipeline/severity/models/

Note: This is for PoC demonstrations. For production use case-specific data.
"""

import os
import sys
import numpy as np
import joblib
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def create_synthetic_data(n_samples: int = 5000, n_features: int = 41) -> tuple:
    """
    Generate synthetic benign network flow data.
    
    Parameters
    ----------
    n_samples : int
        Number of synthetic samples
    n_features : int
        Number of features (matches ISCX dataset)
    
    Returns
    -------
    tuple
        (X_benign, X_attack) both shape (n, n_features)
    """
    print(f"[TRAIN] Generating {n_samples} synthetic samples ({n_features} features)...")
    
    # Benign traffic: normal distribution, centered around 0.3-0.5
    X_benign = np.random.normal(loc=0.4, scale=0.15, size=(n_samples, n_features))
    X_benign = np.clip(X_benign, 0, 1)
    
    # Attack traffic: higher mean, more variance
    X_attack = np.random.normal(loc=0.7, scale=0.2, size=(n_samples // 2, n_features))
    X_attack = np.clip(X_attack, 0, 1)
    
    print(f"  ✓ Benign samples: {X_benign.shape}")
    print(f"  ✓ Attack samples: {X_attack.shape}")
    
    return X_benign, X_attack


def train_and_save(output_dir: str = "./pipeline/severity/models") -> bool:
    """
    Train simple models and save to disk.
    
    Parameters
    ----------
    output_dir : str
        Directory to save model artifacts
    
    Returns
    -------
    bool
        True if successful
    """
    print("\n" + "=" * 70)
    print("AUTO-TRAINING MODELS FOR POC")
    print("=" * 70)
    
    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    print(f"\n[TRAIN] Output directory: {output_dir}")
    
    # Generate synthetic data
    X_benign, X_attack = create_synthetic_data(n_samples=5000, n_features=41)
    
    # ─────────────────────────────────────────────────────────────
    # 1. TRAIN & SAVE SCALER
    # ─────────────────────────────────────────────────────────────
    print("\n[TRAIN] Training MinMaxScaler...")
    from sklearn.preprocessing import MinMaxScaler
    
    scaler = MinMaxScaler(feature_range=(0, 1))
    X_benign_scaled = scaler.fit_transform(X_benign)
    X_attack_scaled = scaler.transform(X_attack)
    
    scaler_path = os.path.join(output_dir, "scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"  ✓ Scaler saved: {scaler_path}")
    
    # ─────────────────────────────────────────────────────────────
    # 2. TRAIN & SAVE AUTOENCODER
    # ─────────────────────────────────────────────────────────────
    print("\n[TRAIN] Training Autoencoder...")
    try:
        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers
        
        # Simple autoencoder architecture
        input_dim = X_benign_scaled.shape[1]
        encoding_dim = 20
        
        # Encoder
        encoder_input = keras.Input(shape=(input_dim,))
        encoded = layers.Dense(encoding_dim, activation='relu')(encoder_input)
        encoder = keras.Model(encoder_input, encoded)
        
        # Full autoencoder
        autoencoder_input = keras.Input(shape=(input_dim,))
        encoded = layers.Dense(encoding_dim, activation='relu')(autoencoder_input)
        decoded = layers.Dense(input_dim, activation='sigmoid')(encoded)
        autoencoder = keras.Model(autoencoder_input, decoded)
        
        autoencoder.compile(optimizer='adam', loss='mse')
        
        # Train on benign data only
        print(f"  → Training on {len(X_benign_scaled)} benign samples...")
        autoencoder.fit(
            X_benign_scaled,
            X_benign_scaled,
            epochs=20,
            batch_size=128,
            validation_split=0.2,
            verbose=0,
        )
        print("  ✓ Autoencoder trained")
        
        # Save models
        ae_path = os.path.join(output_dir, "autoencoder.keras")
        autoencoder.save(ae_path)
        print(f"  ✓ Autoencoder saved: {ae_path}")
        
        enc_path = os.path.join(output_dir, "encoder.keras")
        encoder.save(enc_path)
        print(f"  ✓ Encoder saved: {enc_path}")
        
    except ImportError:
        print("  ✗ TensorFlow not installed, skipping autoencoder")
        return False
    
    # ─────────────────────────────────────────────────────────────
    # 3. TRAIN & SAVE ISOLATION FOREST
    # ─────────────────────────────────────────────────────────────
    print("\n[TRAIN] Training Isolation Forest...")
    from sklearn.ensemble import IsolationForest
    
    iso_forest = IsolationForest(
        contamination=0.1,
        random_state=42,
        n_estimators=100,
    )
    iso_forest.fit(X_benign_scaled)
    
    iso_path = os.path.join(output_dir, "iso_forest.pkl")
    joblib.dump(iso_forest, iso_path)
    print(f"  ✓ Isolation Forest saved: {iso_path}")
    
    # ─────────────────────────────────────────────────────────────
    # 4. SAVE FEATURE COLUMN NAMES
    # ─────────────────────────────────────────────────────────────
    print("\n[TRAIN] Saving feature column names...")
    
    # Standard ISCX feature names (41 columns)
    feature_names = [
        'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts',
        'totlen_fwd_pkts', 'totlen_bwd_pkts', 'fwd_pkt_len_max',
        'bwd_pkt_len_max', 'fwd_pkt_len_min', 'bwd_pkt_len_min',
        'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'fwd_pkt_len_std',
        'bwd_pkt_len_std', 'flow_byts_s', 'flow_pkts_s',
        'fwd_blk_rate_avg', 'bwd_blk_rate_avg', 'fwd_ulen_total',
        'bwd_ulen_total', 'fwd_header_len_total', 'bwd_header_len_total',
        'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags',
        'bwd_urg_flags', 'fwd_rst_flags', 'bwd_rst_flags',
        'fwd_syn_flags', 'bwd_syn_flags', 'fwd_fin_flags',
        'bwd_fin_flags', 'fwd_cwr_flags', 'bwd_cwr_flags',
        'fwd_ece_flags', 'bwd_ece_flags', 'fwd_ack_flags',
        'bwd_ack_flags', 'fwd_urg_flags_count', 'bwd_urg_flags_count',
        'subflow_fwd_pkts', 'subflow_fwd_byts', 'subflow_bwd_pkts',
        'subflow_bwd_byts',
    ]
    
    if len(feature_names) != X_benign_scaled.shape[1]:
        print(f"  ! Feature count mismatch: {len(feature_names)} vs {X_benign_scaled.shape[1]}")
        feature_names = [f"feature_{i}" for i in range(X_benign_scaled.shape[1])]
    
    cols_path = os.path.join(output_dir, "feature_cols.pkl")
    joblib.dump(feature_names, cols_path)
    print(f"  ✓ Feature columns saved: {cols_path} ({len(feature_names)} cols)")
    
    # ─────────────────────────────────────────────────────────────
    # SUMMARY
    # ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("AUTO-TRAINING COMPLETE")
    print("=" * 70)
    print(f"\nModel artifacts saved to: {output_dir}")
    print("\nFiles created:")
    print(f"  ✓ autoencoder.keras")
    print(f"  ✓ encoder.keras")
    print(f"  ✓ iso_forest.pkl")
    print(f"  ✓ scaler.pkl")
    print(f"  ✓ feature_cols.pkl")
    print("\nYou can now run:")
    print("  python main.py --demo normal_traffic")
    print("  python main.py --demo sudden_attack")
    print("  python main.py --demo low_and_slow")
    print()
    
    return True


if __name__ == "__main__":
    success = train_and_save()
    sys.exit(0 if success else 1)
