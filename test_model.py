<<<<<<< HEAD
# test_model.py

from severity_scorer import SeverityScorer
from keras.models import load_model
import joblib
import numpy as np

# ================================
# 1. LOAD MODELS
# ================================

BASE_PATH = "trust_drift/models/"

ae = load_model(BASE_PATH + "autoencoder.keras")
enc = load_model(BASE_PATH + "encoder.keras")
iso = joblib.load(BASE_PATH + "iso_forest.pkl")
scaler = joblib.load(BASE_PATH + "scaler.pkl")

# load feature names (IMPORTANT FIX)
feature_cols = joblib.load(BASE_PATH + "feature_cols.pkl")

# ================================
# 2. LOAD SOME DATA
# ================================

# ⚠️ Replace this with your actual data loading
# Example: using random data just to test pipeline

# NOTE: shape must match training features
dummy_data = np.random.rand(10, len(feature_cols))

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

# ⚠️ Ideally use real benign training data
# For now using dummy data (replace later)

scorer.calibrate(X_scaled)

# ================================
# 5. TEST SINGLE ROW
# ================================

severity, diag = scorer.score_row(X_scaled[0])

print("\n=== SINGLE FLOW TEST ===")
print("Severity:", round(severity, 4))
print("Diagnostics:")
print(diag)

# ================================
# 6. TEST MULTIPLE FLOWS
# ================================

print("\n=== MULTIPLE FLOW TEST ===")

for i in range(5):
    severity, diag = scorer.score_row(X_scaled[i])

    print(f"\n--- FLOW {i} ---")
    print("Severity:", round(severity, 4))
=======
# test_model.py

from severity_scorer import SeverityScorer
from keras.models import load_model
import joblib
import numpy as np

# ================================
# 1. LOAD MODELS
# ================================

BASE_PATH = "trust_drift/models/"

ae = load_model(BASE_PATH + "autoencoder.keras")
enc = load_model(BASE_PATH + "encoder.keras")
iso = joblib.load(BASE_PATH + "iso_forest.pkl")
scaler = joblib.load(BASE_PATH + "scaler.pkl")

# load feature names (IMPORTANT FIX)
feature_cols = joblib.load(BASE_PATH + "feature_cols.pkl")

# ================================
# 2. LOAD SOME DATA
# ================================

# ⚠️ Replace this with your actual data loading
# Example: using random data just to test pipeline

# NOTE: shape must match training features
dummy_data = np.random.rand(10, len(feature_cols))

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

# ⚠️ Ideally use real benign training data
# For now using dummy data (replace later)

scorer.calibrate(X_scaled)

# ================================
# 5. TEST SINGLE ROW
# ================================

severity, diag = scorer.score_row(X_scaled[0])

print("\n=== SINGLE FLOW TEST ===")
print("Severity:", round(severity, 4))
print("Diagnostics:")
print(diag)

# ================================
# 6. TEST MULTIPLE FLOWS
# ================================

print("\n=== MULTIPLE FLOW TEST ===")

for i in range(5):
    severity, diag = scorer.score_row(X_scaled[i])

    print(f"\n--- FLOW {i} ---")
    print("Severity:", round(severity, 4))
>>>>>>> 5200c5e (Initial commit: Trust-Drift pipeline with explainability and firewall simulation)
    print("Top Features:", diag["top_features"])