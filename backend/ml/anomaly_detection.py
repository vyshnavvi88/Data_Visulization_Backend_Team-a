"""
anomaly_detection.py
--------------------
Trains an Isolation Forest model on ml_features.csv and generates
prediction results stored in prediction_results.csv.

Run from the PROJECT ROOT:
    python backend/ml/anomaly_detection.py
"""

import os
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from datetime import datetime

# --------------------------------------------------
# Base paths (resolved relative to this file's location)
# --------------------------------------------------

_ML_DIR       = os.path.dirname(os.path.abspath(__file__))        # backend/ml/
_BACKEND_DIR  = os.path.dirname(_ML_DIR)                          # backend/
_DATA_DIR     = os.path.join(_BACKEND_DIR, "data", "processed")   # backend/data/processed/
_MODELS_DIR   = os.path.join(_BACKEND_DIR, "models")              # backend/models/

ML_FEATURES_CSV      = os.path.join(_DATA_DIR, "ml_features.csv")
# Use Security_db.processed_events.csv as the canonical source for event_id / metadata
ORIGINAL_DATASET_CSV = os.path.join(_DATA_DIR, "Security_db.processed_events.csv")
PREDICTIONS_CSV      = os.path.join(_DATA_DIR, "prediction_results.csv")
MODEL_PKL            = os.path.join(_MODELS_DIR, "isolation_forest.pkl")


# ---------------------------------------
# 1. Load ML-ready features
# ---------------------------------------

df = pd.read_csv(ML_FEATURES_CSV)
print("ML feature dataset shape:", df.shape)


# ---------------------------------------
# 2. Load original dataset (for event_id and metadata)
# ---------------------------------------

original_df = pd.read_csv(ORIGINAL_DATASET_CSV)
print("Original dataset shape:", original_df.shape)

# Align lengths (safety check)
min_len = min(len(df), len(original_df))
df          = df.iloc[:min_len]
original_df = original_df.iloc[:min_len]


# ---------------------------------------
# 3. Create Isolation Forest model
# ---------------------------------------

model = IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42
)


# ---------------------------------------
# 4. Train the model
# ---------------------------------------

model.fit(df)
print("Isolation Forest model trained successfully.")


# ---------------------------------------
# 5. Save trained model
# ---------------------------------------

os.makedirs(_MODELS_DIR, exist_ok=True)
joblib.dump(model, MODEL_PKL)
print(f"Model saved to: {MODEL_PKL}")


# ---------------------------------------
# 6. Generate predictions
# ---------------------------------------

predictions   = model.predict(df)          # 1 = Normal, -1 = Suspicious
anomaly_scores = model.decision_function(df)


# ---------------------------------------
# 7. Convert predictions to readable labels
# ---------------------------------------

prediction_labels = [
    "Suspicious" if p == -1 else "Normal"
    for p in predictions
]


# ---------------------------------------
# Threat Classification
# ---------------------------------------

def classify_threat(row, prediction):
    # Normal ML prediction → Low threat
    if prediction == 1:
        return "Low"

    # Critical indicators
    if (
        row.get("malware_detected") == "Yes"
        and float(row.get("cvss_score", 0)) >= 9
    ):
        return "Critical"

    # High threat indicators
    if (
        float(row.get("failed_login_attempts", 0)) > 10
        or float(row.get("cvss_score", 0)) >= 7
        or row.get("malware_detected") == "Yes"
        or row.get("severity") in ("High", "Critical")
    ):
        return "High"

    return "Medium"


threat_levels = [
    classify_threat(row, pred)
    for (_, row), pred in zip(original_df.iterrows(), predictions)
]


# ---------------------------------------
# Confidence Score
# ---------------------------------------

def calculate_confidence(row, prediction):
    score = 0

    if prediction == -1:
        score += 30

    failed = float(row.get("failed_login_attempts", 0))
    if failed > 10:
        score += 20
    elif failed > 5:
        score += 10

    cvss = float(row.get("cvss_score", 0))
    if cvss >= 9:
        score += 25
    elif cvss >= 7:
        score += 15
    elif cvss >= 4:
        score += 5

    if row.get("malware_detected") == "Yes":
        score += 25

    return min(score, 100)


confidence_scores = [
    calculate_confidence(row, pred)
    for (_, row), pred in zip(original_df.iterrows(), predictions)
]


# ---------------------------------------
# 9. Create prediction results DataFrame
# ---------------------------------------

results = pd.DataFrame({
    "event_id":            original_df["event_id"],
    "prediction":          prediction_labels,
    "threat_type":         original_df["event_type"],
    "confidence_score":    confidence_scores,
    "anomaly_score":       anomaly_scores,
    "severity":            threat_levels,
    "model_version":       "IF_v1",
    "prediction_timestamp": datetime.now().isoformat()
})


# ---------------------------------------
# 10. Save prediction results CSV
# ---------------------------------------

results.to_csv(PREDICTIONS_CSV, index=False)
print(f"\nPrediction results saved to: {PREDICTIONS_CSV}")


# ---------------------------------------
# 11. Display summary
# ---------------------------------------

print("\nPredictions (first 10):")
print(predictions[:10])

print("\nAnomaly scores (first 10):")
print(anomaly_scores[:10])

print("\nPrediction summary:")
print(f"  Total    : {len(results)}")
print(f"  Normal   : {sum(1 for p in prediction_labels if p == 'Normal')}")
print(f"  Suspicious: {sum(1 for p in prediction_labels if p == 'Suspicious')}")
print(f"\nModel file : {MODEL_PKL}")
print(f"Results CSV: {PREDICTIONS_CSV}")
