"""
test.py
-------
Quick diagnostic: prints columns and first few rows of the main datasets.
Run from ANY directory:
    python backend/ml/test.py
"""

import os
import pandas as pd

_ML_DIR    = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR  = os.path.join(os.path.dirname(_ML_DIR), "data", "processed")

# Primary processed events dataset (Security_db source)
EVENTS_CSV      = os.path.join(_DATA_DIR, "Security_db.processed_events.csv")
FEATURES_CSV    = os.path.join(_DATA_DIR, "ml_features.csv")
PREDICTIONS_CSV = os.path.join(_DATA_DIR, "prediction_results.csv")

print("=" * 60)
print("Security_db.processed_events.csv")
print("=" * 60)
df = pd.read_csv(EVENTS_CSV)
print("Shape:", df.shape)
print("Columns:", df.columns.tolist())
print(df.head(3).to_string())

print("\n" + "=" * 60)
print("ml_features.csv")
print("=" * 60)
df_feat = pd.read_csv(FEATURES_CSV)
print("Shape:", df_feat.shape)
print("Columns:", df_feat.columns.tolist())

print("\n" + "=" * 60)
print("prediction_results.csv")
print("=" * 60)
df_pred = pd.read_csv(PREDICTIONS_CSV)
print("Shape:", df_pred.shape)
print(df_pred.head(3).to_string())