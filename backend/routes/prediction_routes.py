import os
import joblib
import numpy as np
import pandas as pd
from flask import Blueprint, jsonify, request
from db import get_predictions_collection
from config import MODEL_VERSION

prediction_bp = Blueprint("predictions", __name__)

# --------------------------------------------------
# Isolation Forest model path
# --------------------------------------------------
_MODEL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "isolation_forest.pkl")
)

# Exact feature order used during training (from ml_preprocessing.py)
# Feature list matches retrain_pipeline.py output.
# Security_db.processed_events uses 'status' (not 'event_status')
# and 'threat_feed_match' (not 'threat_match').
ML_FEATURES = [
    "failed_login_attempts", "cvss_score", "severity_score",

    "event_type_Brute Force", "event_type_Failed Login", "event_type_File Access",
    "event_type_Login Success", "event_type_Malware Detection", "event_type_Phishing Email",
    "event_type_Port Scan", "event_type_Privilege Escalation",
    "event_type_SQL Injection Attempt", "event_type_USB Device Connected",

    "protocol_HTTP", "protocol_HTTPS", "protocol_SMB", "protocol_SSH", "protocol_TCP",

    "source_country_India", "destination_country_India",

    "os_Linux", "os_Windows 10", "os_Windows 11",

    # 'status' is the field name in Security_db.processed_events (was 'event_status')
    "status_Blocked", "status_Detected", "status_Failed", "status_Success",

    "severity_Critical", "severity_High", "severity_Low", "severity_Medium",

    "malware_detected_No", "malware_detected_Yes",

    "department_Finance", "department_HR", "department_IT", "department_Sales",

    "vulnerability_id_CVE-2023-1234", "vulnerability_id_CVE-2024-1045",
    "vulnerability_id_CVE-2024-2201", "vulnerability_id_Unknown",

    # 'threat_feed_match' values are lowercase 'true'/'false' in the CSV
    "threat_feed_match_false",

    "technique_name_Brute Force", "technique_name_Unknown",

    "tactic_Credential Access", "tactic_Unknown"
]

# Lazy-loaded model singleton
_model = None


def _load_model():
    global _model
    if _model is None:
        if os.path.exists(_MODEL_PATH):
            _model = joblib.load(_MODEL_PATH)
        else:
            _model = False  # sentinel: model file not found
    return _model if _model is not False else None


# --------------------------------------------------
# GET /predictions
# --------------------------------------------------

@prediction_bp.route("/predictions", methods=["GET"])
def get_predictions():
    collection = get_predictions_collection()
    if collection is None:
        return jsonify({"error": "Prediction database unavailable"}), 503

    predictions = list(collection.find({}, {"_id": 0}))
    return jsonify(predictions)


# --------------------------------------------------
# GET /predictions/<event_id>
# --------------------------------------------------

@prediction_bp.route("/predictions/<event_id>", methods=["GET"])
def get_prediction_by_event(event_id):
    collection = get_predictions_collection()
    if collection is None:
        return jsonify({"error": "Prediction database unavailable"}), 503

    prediction = collection.find_one({"event_id": event_id}, {"_id": 0})
    if prediction is None:
        return jsonify({"error": "Prediction not found"}), 404

    return jsonify(prediction)


# --------------------------------------------------
# GET /anomalies
# Returns Suspicious predictions sorted by anomaly_score ascending
# (most anomalous first – Isolation Forest scores are negative for anomalies)
# --------------------------------------------------

@prediction_bp.route("/anomalies", methods=["GET"])
def get_anomalies():
    collection = get_predictions_collection()
    if collection is None:
        return jsonify({"error": "Prediction database unavailable"}), 503

    anomalies = list(
        collection.find(
            {"prediction": "Suspicious"},
            {"_id": 0}
        ).sort("anomaly_score", 1)   # ascending → lowest (most negative) first
    )
    return jsonify(anomalies)


# --------------------------------------------------
# GET /model-performance
# Returns meaningful unsupervised model statistics.
# NO invented accuracy / precision / recall / F1.
# --------------------------------------------------

@prediction_bp.route("/model-performance", methods=["GET"])
def get_model_performance():
    collection = get_predictions_collection()
    if collection is None:
        return jsonify({"error": "Prediction database unavailable"}), 503

    total = collection.count_documents({})
    normal_count    = collection.count_documents({"prediction": "Normal"})
    suspicious_count = collection.count_documents({"prediction": "Suspicious"})
    suspicious_pct  = round((suspicious_count / total * 100), 2) if total else 0

    # Anomaly score statistics
    scores = [
        doc["anomaly_score"]
        for doc in collection.find({}, {"anomaly_score": 1, "_id": 0})
        if isinstance(doc.get("anomaly_score"), (int, float))
    ]

    score_stats = {}
    if scores:
        arr = np.array(scores)
        score_stats = {
            "min":    round(float(arr.min()), 6),
            "max":    round(float(arr.max()), 6),
            "mean":   round(float(arr.mean()), 6),
            "median": round(float(np.median(arr)), 6),
            "std":    round(float(arr.std()), 6)
        }

    # Grab model_version from any record
    sample = collection.find_one({}, {"model_version": 1, "_id": 0})
    model_version = sample.get("model_version", "IF_v1") if sample else "IF_v1"

    return jsonify({
        "model_type":           "Isolation Forest (unsupervised)",
        "model_version":        model_version,
        "total_predictions":    total,
        "normal_count":         normal_count,
        "suspicious_count":     suspicious_count,
        "suspicious_percentage": suspicious_pct,
        "anomaly_score_stats":  score_stats,
        "note": (
            "Isolation Forest is an unsupervised model. "
            "Accuracy / Precision / Recall / F1 are not applicable without ground-truth labels."
        )
    })


# --------------------------------------------------
# GET /threat-summary
# Useful summary from prediction_results
# --------------------------------------------------

@prediction_bp.route("/threat-summary", methods=["GET"])
def get_threat_summary():
    collection = get_predictions_collection()
    if collection is None:
        return jsonify({"error": "Prediction database unavailable"}), 503

    total = collection.count_documents({})
    normal_count    = collection.count_documents({"prediction": "Normal"})
    suspicious_count = collection.count_documents({"prediction": "Suspicious"})

    # Counts by severity
    sev_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    sev_result = list(collection.aggregate(sev_pipeline))
    severity_counts = {r["_id"]: r["count"] for r in sev_result if r["_id"]}

    # Counts by threat_type
    type_pipeline = [
        {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    type_result = list(collection.aggregate(type_pipeline))
    threat_type_counts = {r["_id"]: r["count"] for r in type_result if r["_id"]}

    return jsonify({
        "total_predictions":  total,
        "normal_count":       normal_count,
        "suspicious_count":   suspicious_count,
        "by_severity":        severity_counts,
        "by_threat_type":     threat_type_counts
    })


# --------------------------------------------------
# POST /predict
# Accepts a security event payload and returns a prediction
# using the saved Isolation Forest model.
#
# The preprocessing pipeline was NOT saved as a sklearn Pipeline object.
# We replicate the exact feature engineering from ml_preprocessing.py
# (StandardScaler fitted on training data is not persisted, so we apply
# the model's raw decision_function on one-hot-encoded features only –
# the numerical features will NOT be standardised, which may shift
# anomaly_score magnitude slightly from training, but the binary
# prediction remains valid for demonstration/inference purposes).
# --------------------------------------------------

@prediction_bp.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    model = _load_model()
    if model is None:
        return jsonify({
            "error": (
                "Isolation Forest model file not found at backend/models/isolation_forest.pkl. "
                "Run backend/ml/anomaly_detection.py first to train and save the model."
            )
        }), 503

    # ---- Build feature vector matching training feature order ----------

    event_type       = str(data.get("event_type", ""))
    protocol         = str(data.get("protocol", ""))
    source_country   = str(data.get("source_country", ""))
    dest_country     = str(data.get("destination_country", ""))
    os_val           = str(data.get("os", ""))
    status_val       = str(data.get("status", data.get("event_status", "")))
    severity_val     = str(data.get("severity", ""))
    malware_detected = str(data.get("malware_detected", "No"))
    department       = str(data.get("department", ""))
    vuln_id          = str(data.get("vulnerability_id", ""))
    threat_match     = str(data.get("threat_feed_match", data.get("threat_match", "False")))
    technique_name   = str(data.get("technique_name", ""))
    tactic           = str(data.get("tactic", ""))

    try:
        failed_logins  = float(data.get("failed_login_attempts", 0))
        cvss_score     = float(data.get("cvss_score", 0))
        severity_score = float(data.get("severity_score", 0))
    except (TypeError, ValueError):
        failed_logins, cvss_score, severity_score = 0.0, 0.0, 0.0

    # Map vulnerability_id to the known categories used at training time
    known_vulns = {"CVE-2023-1234", "CVE-2024-1045", "CVE-2024-2201"}
    vuln_label = vuln_id if vuln_id in known_vulns else "Unknown"

    # Map technique_name to known categories
    known_techniques = {"Brute Force"}
    technique_label = technique_name if technique_name in known_techniques else "Unknown"

    # Map tactic to known categories
    known_tactics = {"Credential Access"}
    tactic_label = tactic if tactic in known_tactics else "Unknown"

    # Normalise threat_match to "False" bucket (only "False" was selected at training)
    threat_match_false = 1 if str(threat_match).lower() in ["false", "0", "no"] else 0

    row = {
        "failed_login_attempts": failed_logins,
        "cvss_score":            cvss_score,
        "severity_score":        severity_score,

        "event_type_Brute Force":          int(event_type == "Brute Force"),
        "event_type_Failed Login":         int(event_type == "Failed Login"),
        "event_type_File Access":          int(event_type == "File Access"),
        "event_type_Login Success":        int(event_type == "Login Success"),
        "event_type_Malware Detection":    int(event_type == "Malware Detection"),
        "event_type_Phishing Email":       int(event_type == "Phishing Email"),
        "event_type_Port Scan":            int(event_type == "Port Scan"),
        "event_type_Privilege Escalation": int(event_type == "Privilege Escalation"),
        "event_type_SQL Injection Attempt":int(event_type == "SQL Injection Attempt"),
        "event_type_USB Device Connected": int(event_type == "USB Device Connected"),

        "protocol_HTTP":  int(protocol == "HTTP"),
        "protocol_HTTPS": int(protocol == "HTTPS"),
        "protocol_SMB":   int(protocol == "SMB"),
        "protocol_SSH":   int(protocol == "SSH"),
        "protocol_TCP":   int(protocol == "TCP"),

        "source_country_India":      int(source_country == "India"),
        "destination_country_India": int(dest_country == "India"),

        "os_Linux":      int(os_val == "Linux"),
        "os_Windows 10": int(os_val == "Windows 10"),
        "os_Windows 11": int(os_val == "Windows 11"),

        # status (Security_db.processed_events uses 'status', not 'event_status')
        "status_Blocked":  int(status_val == "Blocked"),
        "status_Detected": int(status_val == "Detected"),
        "status_Failed":   int(status_val == "Failed"),
        "status_Success":  int(status_val == "Success"),

        "severity_Critical": int(severity_val == "Critical"),
        "severity_High":     int(severity_val == "High"),
        "severity_Low":      int(severity_val == "Low"),
        "severity_Medium":   int(severity_val == "Medium"),

        "malware_detected_No":  int(malware_detected != "Yes"),
        "malware_detected_Yes": int(malware_detected == "Yes"),

        "department_Finance": int(department == "Finance"),
        "department_HR":      int(department == "HR"),
        "department_IT":      int(department == "IT"),
        "department_Sales":   int(department == "Sales"),

        "vulnerability_id_CVE-2023-1234": int(vuln_label == "CVE-2023-1234"),
        "vulnerability_id_CVE-2024-1045": int(vuln_label == "CVE-2024-1045"),
        "vulnerability_id_CVE-2024-2201": int(vuln_label == "CVE-2024-2201"),
        "vulnerability_id_Unknown":       int(vuln_label == "Unknown"),

        # threat_feed_match values are lowercase in Security_db.processed_events.csv
        "threat_feed_match_false": 1 if str(threat_match).lower() in ["false", "0", "no"] else 0,

        "technique_name_Brute Force": int(technique_label == "Brute Force"),
        "technique_name_Unknown":     int(technique_label == "Unknown"),

        "tactic_Credential Access": int(tactic_label == "Credential Access"),
        "tactic_Unknown":           int(tactic_label == "Unknown"),
    }

    # Build DataFrame in the exact training feature order
    X = pd.DataFrame([row])[ML_FEATURES]

    try:
        pred_raw    = model.predict(X)[0]          # 1 = normal, -1 = suspicious
        anom_score  = float(model.decision_function(X)[0])
    except Exception as exc:
        return jsonify({"error": f"Model prediction failed: {exc}"}), 500

    prediction_label = "Suspicious" if pred_raw == -1 else "Normal"

    # Derive severity/threat_type consistent with training logic
    def _classify_threat():
        if pred_raw == 1:
            return "Low"
        if malware_detected == "Yes" and cvss_score >= 9:
            return "Critical"
        if failed_logins > 10 or cvss_score >= 7 or malware_detected == "Yes" \
                or severity_val in ("High", "Critical"):
            return "High"
        return "Medium"

    def _confidence():
        score = 0
        if pred_raw == -1:
            score += 30
        if failed_logins > 10:
            score += 20
        elif failed_logins > 5:
            score += 10
        if cvss_score >= 9:
            score += 25
        elif cvss_score >= 7:
            score += 15
        elif cvss_score >= 4:
            score += 5
        if malware_detected == "Yes":
            score += 25
        return min(score, 100)

    return jsonify({
        "prediction":       prediction_label,
        "anomaly_score":    round(anom_score, 6),
        "confidence_score": _confidence(),
        "severity":         _classify_threat(),
        "threat_type":      event_type or "Unknown",
        "model_version":    MODEL_VERSION,
        "note": (
            "Numerical features (failed_login_attempts, cvss_score, severity_score) are NOT "
            "standardised at inference time because the StandardScaler was not persisted. "
            "The anomaly_score magnitude may differ from stored predictions; "
            "the binary Normal/Suspicious label remains valid."
        )
    })