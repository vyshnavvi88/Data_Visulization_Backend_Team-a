"""
model_evaluation.py
-------------------
Evaluates the Isolation Forest model using prediction_results.csv.
Reports unsupervised model statistics (no invented accuracy/F1).

Run from ANY directory:
    python backend/ml/model_evaluation.py
"""

import os
import pandas as pd

# --------------------------------------------------
# Paths (resolved relative to this file's location)
# --------------------------------------------------

_ML_DIR      = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR    = os.path.join(os.path.dirname(_ML_DIR), "data", "processed")

PREDICTIONS_CSV = os.path.join(_DATA_DIR, "prediction_results.csv")

# --------------------------------------------------
# Load prediction results
# --------------------------------------------------

df = pd.read_csv(PREDICTIONS_CSV)
print(f"Loaded prediction results from: {PREDICTIONS_CSV}")
print(f"Total events: {len(df)}")

# --------------------------------------------------
# Prediction counts
# --------------------------------------------------

prediction_counts = df["prediction"].value_counts()
print("\nPrediction counts:")
print(prediction_counts.to_string())

normal_count     = prediction_counts.get("Normal", 0)
suspicious_count = prediction_counts.get("Suspicious", 0)

normal_pct     = (normal_count     / len(df)) * 100
suspicious_pct = (suspicious_count / len(df)) * 100

print(f"\nNormal     : {normal_count}  ({round(normal_pct, 2)}%)")
print(f"Suspicious : {suspicious_count}  ({round(suspicious_pct, 2)}%)")

# --------------------------------------------------
# Anomaly score statistics
# --------------------------------------------------

print("\nAnomaly score statistics:")
print(df["anomaly_score"].describe().round(6).to_string())

# --------------------------------------------------
# Severity breakdown
# --------------------------------------------------

if "severity" in df.columns:
    print("\nSeverity breakdown:")
    print(df["severity"].value_counts().to_string())

# --------------------------------------------------
# Threat type breakdown
# --------------------------------------------------

if "threat_type" in df.columns:
    print("\nThreat type breakdown (top 10):")
    print(df["threat_type"].value_counts().head(10).to_string())

# --------------------------------------------------
# Model version
# --------------------------------------------------

if "model_version" in df.columns:
    print("\nModel version:", df["model_version"].iloc[0])

print("\nNote: Isolation Forest is unsupervised.")
print("Accuracy / Precision / Recall / F1 are NOT applicable without ground-truth labels.")
print("\nModel evaluation completed.")