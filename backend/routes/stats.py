from flask import Blueprint, jsonify
from db import get_events_data, load_predictions

stats_bp = Blueprint("stats", __name__)

@stats_bp.route("/stats", methods=["GET"])
def get_stats():
    events = get_events_data()
    predictions = load_predictions()
    
    total_events = len(events)
    anomalies_detected = 0
    normal_events = 0
    high_risk_events = 0
    critical_threats = 0
    
    for e in events:
        evt_id = e.get("event_id", "")
        pred_info = predictions.get(evt_id, {})
        pred = pred_info.get("prediction", "Normal")
        
        if pred == "Suspicious":
            anomalies_detected += 1
        else:
            normal_events += 1
            
        is_hr = e.get("is_high_risk")
        if is_hr in [True, 1, "true", "True"]:
            high_risk_events += 1
            
        sev = str(e.get("severity", "")).lower()
        if sev == "critical":
            critical_threats += 1
            
    return jsonify({
        "totalEvents": total_events,
        "anomaliesDetected": anomalies_detected,
        "normalEvents": normal_events,
        "highRiskEvents": high_risk_events,
        "criticalThreats": critical_threats
    })