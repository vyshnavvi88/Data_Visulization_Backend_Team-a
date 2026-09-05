"""
risk_routes.py
--------------
M3 Risk Score APIs

GET  /api/v1/risk/summary     - Risk distribution summary
GET  /api/v1/risk/high        - High & Critical risk events
POST /api/v1/risk/calculate   - Real-time risk score calculation
"""

import os
import pandas as pd
from flask import Blueprint, jsonify, request

risk_bp = Blueprint("risk", __name__)

# --------------------------------------------------
# Data path — correlated_events.csv (final M3 output)
# --------------------------------------------------
_DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "processed", "correlated_events.csv"
)

def _load_risk_data():
    """Load the final M3 risk-enriched events CSV."""
    if os.path.exists(_DATA_PATH):
        df = pd.read_csv(_DATA_PATH)
        df = df.fillna("")
        return df
    return pd.DataFrame()


# --------------------------------------------------
# GET /api/v1/risk/summary
# --------------------------------------------------

@risk_bp.route("/risk/summary", methods=["GET"])
def risk_summary():
    """
    Returns overall risk distribution and statistics.

    Response:
    {
      "total_events": 1800,
      "risk_distribution": {"Critical":1, "High":506, ...},
      "avg_risk_score": 52.4,
      "top_threat_types": {"Brute Force": 300, ...},
      "ioc_matched_count": 45
    }
    """
    df = _load_risk_data()
    if df.empty:
        return jsonify({"error": "Risk data not available"}), 503

    risk_dist = df["risk_class"].value_counts().to_dict()

    avg_score = round(float(df["risk_score"].mean()), 2) if "risk_score" in df.columns else 0.0

    top_threats = {}
    if "event_type" in df.columns:
        top_threats = df["event_type"].value_counts().head(10).to_dict()

    ioc_count = 0
    if "ioc_match" in df.columns:
        ioc_count = int(df["ioc_match"].apply(
            lambda x: str(x).lower() in ("true", "1", "yes")
        ).sum())

    correlated_count = 0
    if "is_correlated" in df.columns:
        correlated_count = int(df["is_correlated"].apply(
            lambda x: str(x).lower() in ("true", "1")
        ).sum())

    return jsonify({
        "total_events":        len(df),
        "risk_distribution":   risk_dist,
        "avg_risk_score":      avg_score,
        "top_threat_types":    top_threats,
        "ioc_matched_count":   ioc_count,
        "correlated_events":   correlated_count
    })


# --------------------------------------------------
# GET /api/v1/risk/high
# --------------------------------------------------

@risk_bp.route("/risk/high", methods=["GET"])
def high_risk_events():
    """
    Returns High and Critical risk events, sorted by risk_score descending.

    Query params:
      ?risk_class=Critical     filter by class
      ?limit=50                max records (default 100)
      ?offset=0                pagination offset
    """
    df = _load_risk_data()
    if df.empty:
        return jsonify({"error": "Risk data not available"}), 503

    risk_class_filter = request.args.get("risk_class", None)
    limit  = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))

    if risk_class_filter:
        filtered = df[df["risk_class"].str.lower() == risk_class_filter.lower()]
    else:
        filtered = df[df["risk_class"].isin(["Critical", "High"])]

    filtered = filtered.sort_values("risk_score", ascending=False)

    cols = [
        "event_id", "event_type", "risk_score", "risk_class", "priority",
        "severity", "asset_name", "asset_id", "criticality",
        "username", "source_ip", "timestamp",
        "mitre_id", "technique_name", "tactic",
        "ioc_match", "threat_actor", "cvss_score",
        "correlation_id", "is_correlated", "correlated_event_count"
    ]
    cols = [c for c in cols if c in filtered.columns]

    page = filtered[cols].iloc[offset: offset + limit]

    return jsonify({
        "total":   len(filtered),
        "offset":  offset,
        "limit":   limit,
        "events":  page.to_dict(orient="records")
    })


# --------------------------------------------------
# POST /api/v1/risk/calculate
# --------------------------------------------------

@risk_bp.route("/risk/calculate", methods=["POST"])
def calculate_risk():
    """
    Real-time risk score calculation for a single event.

    Request body (JSON):
    {
      "event_type":       "Brute Force",
      "severity":         "Critical",
      "confidence_score": 92,
      "asset_criticality":"Critical",
      "cvss_score":       9.8,
      "ioc_match":        true
    }

    Weights:
      Threat Severity        25%
      ML Confidence          25%
      Asset Criticality      20%
      Vulnerability (CVSS)   20%
      Threat Intelligence    10%
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    # ── 1. Threat severity score ─────────────────────────────────────
    severity_map = {"critical": 100, "high": 80, "medium": 60, "low": 30}
    sev_raw = str(data.get("severity", "low")).lower()
    threat_severity = severity_map.get(sev_raw, 50)

    # ── 2. ML confidence (already 0–100) ─────────────────────────────
    ml_confidence = float(data.get("confidence_score", 50))
    ml_confidence = max(0, min(100, ml_confidence))

    # ── 3. Asset criticality score ───────────────────────────────────
    crit_map = {"critical": 100, "high": 75, "medium": 50, "low": 25}
    crit_raw = str(data.get("asset_criticality", "medium")).lower()
    asset_crit = crit_map.get(crit_raw, 50)

    # ── 4. Vulnerability exposure (CVSS 0–10 → 0–100) ────────────────
    cvss = float(data.get("cvss_score", 0))
    vuln_score = (cvss / 10.0) * 100

    # ── 5. Threat intelligence (IOC match) ───────────────────────────
    ioc_match = data.get("ioc_match", False)
    ti_score  = 100 if ioc_match else 0

    # ── Weighted risk score ───────────────────────────────────────────
    risk_score = (
        (threat_severity * 0.25) +
        (ml_confidence   * 0.25) +
        (asset_crit      * 0.20) +
        (vuln_score      * 0.20) +
        (ti_score        * 0.10)
    )
    risk_score = round(risk_score, 2)

    # ── Risk classification ───────────────────────────────────────────
    if risk_score >= 81:
        risk_class = "Critical"
        priority   = 1
    elif risk_score >= 61:
        risk_class = "High"
        priority   = 2
    elif risk_score >= 41:
        risk_class = "Moderate"
        priority   = 3
    elif risk_score >= 21:
        risk_class = "Medium"
        priority   = 4
    else:
        risk_class = "Low"
        priority   = 5

    # ── Recommendations ───────────────────────────────────────────────
    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from risk.recommendations import get_recommendations
        recs = get_recommendations(
            event_type=data.get("event_type", ""),
            risk_class=risk_class,
            ioc_match=bool(ioc_match),
            cvss_score=cvss
        )
    except Exception:
        recs = []

    return jsonify({
        "risk_score":     risk_score,
        "risk_class":     risk_class,
        "priority":       priority,
        "breakdown": {
            "threat_severity_score":  threat_severity,
            "ml_confidence_score":    ml_confidence,
            "asset_criticality_score": asset_crit,
            "vulnerability_score":    round(vuln_score, 2),
            "threat_intelligence_score": ti_score
        },
        "weights": {
            "threat_severity":     "25%",
            "ml_confidence":       "25%",
            "asset_criticality":   "20%",
            "vulnerability":       "20%",
            "threat_intelligence": "10%"
        },
        "recommendation": recs
    })
