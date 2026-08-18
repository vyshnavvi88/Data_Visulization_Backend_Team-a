"""
retrain_pipeline.py
-------------------
Full retraining pipeline for the Isolation Forest model.

Steps performed:
  1. Load  Security_db.processed_events.csv
  2. Preprocess (fill NaN, one-hot encode, scale numerics)
  3. Save    ml_features.csv
  4. Train   Isolation Forest
  5. Save    isolation_forest.pkl
  6. Generate predictions + save prediction_results.csv
  7. Store fresh predictions in Security_db.prediction_results (MongoDB)

Run from the PROJECT ROOT or ANY directory:
    python backend/ml/retrain_pipeline.py
"""

import os
import json
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# ==================================================
# Paths (always resolved from this file's location)
# ==================================================

_ML_DIR      = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_ML_DIR)
_DATA_DIR    = os.path.join(_BACKEND_DIR, "data", "processed")
_MODELS_DIR  = os.path.join(_BACKEND_DIR, "models")

EVENTS_CSV      = os.path.join(_DATA_DIR, "Security_db.processed_events.csv")
ML_FEATURES_CSV = os.path.join(_DATA_DIR, "ml_features.csv")
PREDICTIONS_CSV = os.path.join(_DATA_DIR, "prediction_results.csv")
MODEL_PKL       = os.path.join(_MODELS_DIR, "isolation_forest.pkl")
FEATURES_JSON   = os.path.join(_MODELS_DIR, "feature_columns.json")   # saved feature list

os.makedirs(_MODELS_DIR, exist_ok=True)


# ==================================================
# STEP 1 – Load Security_db.processed_events.csv
# ==================================================

print("=" * 60)
print("STEP 1: Loading Security_db.processed_events.csv")
print("=" * 60)

df = pd.read_csv(EVENTS_CSV)
print(f"  Shape: {df.shape}")
print(f"  Columns: {df.columns.tolist()}")

# Keep a copy for metadata (event_id, event_type, severity, etc.)
original_df = df.copy()


# ==================================================
# STEP 2 – Preprocessing
# ==================================================

print("\n" + "=" * 60)
print("STEP 2: Preprocessing")
print("=" * 60)

# ---- 2a. Fill missing values in sparse categorical columns ----
fill_unknown = ["vulnerability_id", "mitre_id", "technique_name", "tactic"]
for col in fill_unknown:
    if col in df.columns:
        df[col] = df[col].fillna("Unknown")

# Normalise threat_feed_match to title-case so one-hot names are clean
# Values in CSV: lowercase "true" / "false"
if "threat_feed_match" in df.columns:
    df["threat_feed_match"] = df["threat_feed_match"].astype(str).str.strip().str.lower()

print(f"  Missing values after fill:\n{df.isnull().sum()[df.isnull().sum() > 0]}")

# ---- 2b. One-hot encode categorical features ----
# NOTE: new CSV uses 'status' (not 'event_status') and
#       'threat_feed_match' (not 'threat_match')
categorical_columns = [
    "event_type",
    "protocol",
    "source_country",
    "destination_country",
    "os",
    "status",            # Security_db.processed_events uses 'status'
    "severity",
    "malware_detected",
    "department",
    "vulnerability_id",
    "threat_feed_match", # Security_db.processed_events uses 'threat_feed_match'
    "technique_name",
    "tactic",
]

# Only encode columns that actually exist in the dataset
existing_cat = [c for c in categorical_columns if c in df.columns]
df_encoded = pd.get_dummies(df, columns=existing_cat, dtype=int)

print(f"  Shape after one-hot encoding: {df_encoded.shape}")

# ---- 2c. Scale numerical features ----
numerical_features = ["failed_login_attempts", "cvss_score", "severity_score"]
existing_num = [f for f in numerical_features if f in df_encoded.columns]

scaler = StandardScaler()
df_encoded[existing_num] = scaler.fit_transform(df_encoded[existing_num])

print(f"  Numerical features scaled: {existing_num}")

# ---- 2d. Feature selection ----
# These are the features we want in the ML matrix.
# The list reflects the ACTUAL column names in Security_db.processed_events.csv.
DESIRED_FEATURES = [
    "failed_login_attempts",
    "cvss_score",
    "severity_score",

    # event_type
    "event_type_Brute Force",
    "event_type_Failed Login",
    "event_type_File Access",
    "event_type_Login Success",
    "event_type_Malware Detection",
    "event_type_Phishing Email",
    "event_type_Port Scan",
    "event_type_Privilege Escalation",
    "event_type_SQL Injection Attempt",
    "event_type_USB Device Connected",

    # protocol
    "protocol_HTTP",
    "protocol_HTTPS",
    "protocol_SMB",
    "protocol_SSH",
    "protocol_TCP",

    # country
    "source_country_India",
    "destination_country_India",

    # os
    "os_Linux",
    "os_Windows 10",
    "os_Windows 11",

    # status  (renamed from event_status)
    "status_Blocked",
    "status_Detected",
    "status_Failed",
    "status_Success",

    # severity
    "severity_Critical",
    "severity_High",
    "severity_Low",
    "severity_Medium",

    # malware
    "malware_detected_No",
    "malware_detected_Yes",

    # department
    "department_Finance",
    "department_HR",
    "department_IT",
    "department_Sales",

    # vulnerability
    "vulnerability_id_CVE-2023-1234",
    "vulnerability_id_CVE-2024-1045",
    "vulnerability_id_CVE-2024-2201",
    "vulnerability_id_Unknown",

    # threat_feed_match  (renamed from threat_match; values are lowercase in CSV)
    "threat_feed_match_false",

    # technique
    "technique_name_Brute Force",
    "technique_name_Unknown",

    # tactic
    "tactic_Credential Access",
    "tactic_Unknown",
]

# Only keep features that actually exist after encoding
ml_features = [f for f in DESIRED_FEATURES if f in df_encoded.columns]
missing_features = [f for f in DESIRED_FEATURES if f not in df_encoded.columns]

if missing_features:
    print(f"\n  [WARNING] These desired features were NOT found after encoding (adding as zeros):")
    for mf in missing_features:
        print(f"    - {mf}")
        df_encoded[mf] = 0
    ml_features = DESIRED_FEATURES   # now all exist

X = df_encoded[ml_features]
print(f"\n  Final ML feature matrix shape: {X.shape}")
print(f"  Features ({len(ml_features)}): {ml_features}")


# ==================================================
# STEP 3 – Save ml_features.csv
# ==================================================

print("\n" + "=" * 60)
print("STEP 3: Saving ml_features.csv")
print("=" * 60)

X.to_csv(ML_FEATURES_CSV, index=False)
print(f"  Saved: {ML_FEATURES_CSV}")

# Save feature list to JSON so inference code can load it
with open(FEATURES_JSON, "w") as f:
    json.dump(ml_features, f, indent=2)
print(f"  Feature list saved: {FEATURES_JSON}")


# ==================================================
# STEP 4 – Train Isolation Forest
# ==================================================

print("\n" + "=" * 60)
print("STEP 4: Training Isolation Forest")
print("=" * 60)

model = IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42
)
model.fit(X)
print("  Model trained successfully.")


# ==================================================
# STEP 5 – Save model
# ==================================================

print("\n" + "=" * 60)
print("STEP 5: Saving model")
print("=" * 60)

joblib.dump(model, MODEL_PKL)
print(f"  Model saved: {MODEL_PKL}")


# ==================================================
# STEP 6 – Generate predictions
# ==================================================

print("\n" + "=" * 60)
print("STEP 6: Generating predictions")
print("=" * 60)

raw_predictions  = model.predict(X)          # 1 = Normal, -1 = Suspicious
anomaly_scores   = model.decision_function(X)

prediction_labels = [
    "Suspicious" if p == -1 else "Normal"
    for p in raw_predictions
]

# ---- Threat classification ----
def classify_threat(row, prediction):
    if prediction == 1:
        return "Low"
    if (str(row.get("malware_detected", "No")) == "Yes"
            and float(row.get("cvss_score", 0)) >= 9):
        return "Critical"
    if (float(row.get("failed_login_attempts", 0)) > 10
            or float(row.get("cvss_score", 0)) >= 7
            or str(row.get("malware_detected", "No")) == "Yes"
            or str(row.get("severity", "")) in ("High", "Critical")):
        return "High"
    return "Medium"

# ---- Confidence score ----
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
    if str(row.get("malware_detected", "No")) == "Yes":
        score += 25
    return min(score, 100)

threat_levels = [
    classify_threat(row, pred)
    for (_, row), pred in zip(original_df.iterrows(), raw_predictions)
]
confidence_scores = [
    calculate_confidence(row, pred)
    for (_, row), pred in zip(original_df.iterrows(), raw_predictions)
]

ts = datetime.now().isoformat()

results = pd.DataFrame({
    "event_id":             original_df["event_id"],
    "prediction":           prediction_labels,
    "threat_type":          original_df["event_type"],
    "confidence_score":     confidence_scores,
    "anomaly_score":        anomaly_scores,
    "severity":             threat_levels,
    "model_version":        "IF_v2",
    "prediction_timestamp": ts
})

total      = len(results)
normal_n   = sum(1 for p in prediction_labels if p == "Normal")
suspicious_n = total - normal_n

print(f"  Total        : {total}")
print(f"  Normal       : {normal_n}  ({round(normal_n/total*100, 1)}%)")
print(f"  Suspicious   : {suspicious_n}  ({round(suspicious_n/total*100, 1)}%)")


# ==================================================
# STEP 7 – Save prediction_results.csv
# ==================================================

print("\n" + "=" * 60)
print("STEP 7: Saving prediction_results.csv")
print("=" * 60)

results.to_csv(PREDICTIONS_CSV, index=False)
print(f"  Saved: {PREDICTIONS_CSV}")


# ==================================================
# STEP 8 – Store fresh predictions in MongoDB
# ==================================================

print("\n" + "=" * 60)
print("STEP 8: Storing predictions in Security_db.prediction_results")
print("=" * 60)

from pymongo.errors import ConfigurationError as MongoConfigError

def _make_client():
    """Try Atlas first; fall back to local Compass on any connection error."""
    uri = os.getenv("MONGO_URI")
    if uri:
        try:
            print("  Trying MongoDB Atlas …")
            c = MongoClient(uri, serverSelectionTimeoutMS=8000)
            c.admin.command("ping")   # fast connectivity check
            print("  Atlas connected successfully.")
            return c
        except Exception as atlas_err:
            print(f"  Atlas unavailable ({type(atlas_err).__name__}). Falling back to local Compass …")

    # Local Compass fallback
    print("  Using Local MongoDB Compass (mongodb://localhost:27017/)")
    c = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    c.admin.command("ping")
    print("  Local MongoDB connected successfully.")
    return c

try:
    client = _make_client()

    db         = client["Security_db"]
    collection = db["prediction_results"]

    # Drop existing predictions and insert fresh ones
    old_count = collection.count_documents({})
    print(f"  Existing records (will be replaced): {old_count}")
    collection.delete_many({})

    records = results.where(pd.notnull(results), None).to_dict("records")
    collection.insert_many(records)

    new_count = collection.count_documents({})
    print(f"  New records inserted: {new_count}")
    client.close()

except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
    print(f"  [WARNING] Could not connect to MongoDB: {exc}")
    print("  Predictions saved to CSV only. Run Store_predictions.py separately to load into MongoDB.")


# ==================================================
# FINAL SUMMARY
# ==================================================

print("\n" + "=" * 60)
print("RETRAIN PIPELINE COMPLETE")
print("=" * 60)
print(f"  Database         : Security_db")
print(f"  Collection       : prediction_results")
print(f"  Model file       : {MODEL_PKL}")
print(f"  Feature columns  : {FEATURES_JSON}")
print(f"  ML features CSV  : {ML_FEATURES_CSV}")
print(f"  Predictions CSV  : {PREDICTIONS_CSV}")
print(f"  Total predictions: {total}")
print(f"  Normal           : {normal_n}")
print(f"  Suspicious       : {suspicious_n}")
print(f"  Model version    : IF_v2")
