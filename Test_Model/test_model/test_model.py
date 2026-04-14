# test_model.py

from severity_scorer import SeverityScorer
from explain import generate_explanation, generate_mitre_playbook
from keras.models import load_model
import joblib
import numpy as np
import sys

# Force UTF-8 output for high-fidelity ASCII characters
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# ================================
# 1. LOAD MODELS
# ================================

BASE_PATH = "../models/"

ae = load_model(BASE_PATH + "autoencoder.keras")
enc = load_model(BASE_PATH + "encoder.keras")
iso = joblib.load(BASE_PATH + "iso_forest.pkl")
scaler = joblib.load(BASE_PATH + "scaler.pkl")

# load feature names (IMPORTANT FIX)
feature_cols = joblib.load(BASE_PATH + "feature_cols.pkl")

# ================================
# 2. LOAD SOME DATA
# ================================

#  Replace this with your actual data loading
# Example: using random data just to test pipeline

# NOTE: shape must match training features
dummy_data = np.random.rand(10, len(feature_cols))
dummy_labels = ["Normal", "DoS Slowloris", "PortScan", "DDoS", "Bot"] * 2
# scale data (VERY IMPORTANT)
X_scaled = scaler.transform(dummy_data)

# ================================
# 3. INITIALIZE SCORER
# ================================

scorer = SeverityScorer(
    autoencoder=ae,
    encoder_model=enc,
    iso_forest=iso,
    scaler=scaler,
    feature_names=feature_cols
)

# ================================
# 4. CALIBRATE (MANDATORY)
# ================================

#  Ideally use real benign training data
# For now using dummy data (replace later)

scorer.calibrate(X_scaled)

# ================================
# 5. TEST LOOP WITH PLAYBOOK
# ================================

current_trust = 0.95  # Initial Trust

print("\n" + "="*50)
print("TRUST-DRIFT MITRE PLAYBOOK")
print("="*50 + "\n")

for i in range(len(X_scaled)):
    severity, diag = scorer.score_row(X_scaled[i])

    # Simulate Trust Decay if severity is high
    if severity > 0.3:
        # T_new = T_old * e^(-lambda * s)
        current_trust *= np.exp(-1.5 * severity)
    else:
        # T_new = min(1.0, T_old + mu * dt)
        current_trust = min(1.0, current_trust + 0.05)

    # Generate Playbook
    playbook = generate_mitre_playbook(current_trust, diag)
    
    print(f"Row {i+1} [Label: {dummy_labels[i]}]:")
    print(playbook)
    print("\n")